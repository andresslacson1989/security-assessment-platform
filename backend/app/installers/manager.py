"""
Contract 03 (Section 5) & Contract 04 (Section 1.5, 2.2) Tool Installation Manager.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import asyncio
import logging
from datetime import datetime, timezone
import json
import time
import uuid
from typing import Dict, List, Optional, AsyncGenerator, Set, Tuple

from app.core.models import (
    ToolInstallationInfo,
    ToolInstallResponse,
    ToolInstallStatus,
    ToolInstallMethod,
)
from app.installers.base_installer import BaseToolInstaller
from app.installers.pip_installer import PipToolInstaller
from app.installers.github_release_installer import GithubReleaseInstaller
from app.installers.source_build_installer import SourceBuildInstaller
from app.installers.system_installer import SystemToolHelper
from app.installers.npm_installer import NpmToolInstaller
from app.installers.nmap_artifact_installer import NmapArtifactInstaller
from app.core.tool_fleet import SUPPORTED_TOOL_IDS

logger = logging.getLogger("cyberassess.installers.manager")


class ToolInstallationManager:
    """
    Central manager for tool capability detection, serialized background in-app installation jobs,
    cancellation lifecycle, and real-time Server-Sent Events (SSE) telemetry broadcast.
    """

    _instance: Optional[ToolInstallationManager] = None

    def __init__(self):
        self._installers: Dict[str, BaseToolInstaller] = {
            # Pip packages (6 tools)
            "sslyze": PipToolInstaller("sslyze"),
            "bandit": PipToolInstaller("bandit"),
            "semgrep": PipToolInstaller("semgrep"),
            "checkov": PipToolInstaller("checkov"),
            "prowler": PipToolInstaller("prowler"),
            "schemathesis": PipToolInstaller("schemathesis"),

            # Standalone GitHub release binaries (14 tools)
            "nuclei": GithubReleaseInstaller("nuclei"),
            "ffuf": GithubReleaseInstaller("ffuf"),
            "gitleaks": GithubReleaseInstaller("gitleaks"),
            "trivy": SourceBuildInstaller("trivy"),
            "subfinder": GithubReleaseInstaller("subfinder"),
            "httpx": GithubReleaseInstaller("httpx"),
            "katana": GithubReleaseInstaller("katana"),
            "syft": GithubReleaseInstaller("syft"),
            "grype": GithubReleaseInstaller("grype"),
            "osv-scanner": GithubReleaseInstaller("osv-scanner"),
            "trufflehog": GithubReleaseInstaller("trufflehog"),
            "dockle": GithubReleaseInstaller("dockle"),
            "kube-bench": GithubReleaseInstaller("kube-bench"),
            "amass": GithubReleaseInstaller("amass"),

            # Approved verified source-build, direct-artifact, and package-manager tools
            "nmap": NmapArtifactInstaller("nmap"),
            "retire": NpmToolInstaller("retire"),
            "metasploit": SystemToolHelper("metasploit"),
            "sqlmap": SystemToolHelper("sqlmap"),
            "hydra": SystemToolHelper("hydra"),
            "gtfobins": SystemToolHelper("gtfobins"),
        }
        if set(self._installers) != SUPPORTED_TOOL_IDS:
            raise RuntimeError("Installer registry does not preserve the complete 26-tool fleet")
        self._active_tasks: Dict[str, asyncio.Task] = {}
        self._tool_to_task: Dict[str, str] = {}
        self._subscribers: Set[asyncio.Queue] = set()
        self._tool_cache: Dict[str, ToolInstallationInfo] = {}
        self._pip_lock: asyncio.Lock = asyncio.Lock()

    @classmethod
    def get_instance(cls) -> ToolInstallationManager:
        if cls._instance is None:
            cls._instance = ToolInstallationManager()
        return cls._instance

    def get_installer(self, tool_name: str) -> Optional[BaseToolInstaller]:
        return self._installers.get(tool_name.lower())

    async def get_tool_info(self, tool_name: str) -> Optional[ToolInstallationInfo]:
        inst = self.get_installer(tool_name)
        if not inst:
            return None
        info = await inst.get_info()
        self._tool_cache[tool_name] = info
        return info

    async def get_all_tools_info(self) -> List[ToolInstallationInfo]:
        results = []
        for name, inst in self._installers.items():
            info = await inst.get_info()
            self._tool_cache[name] = info
            results.append(info)
        return results

    async def broadcast_event(self, event_type: str, data: dict) -> None:
        """Broadcasts SSE event payload to all active listeners."""
        payload = {
            "event": event_type,
            "data": data,
        }
        for q in list(self._subscribers):
            try:
                await q.put(payload)
            except Exception as exc:
                logger.debug("Tool-installation SSE subscriber delivery failed: error_type=%s", type(exc).__name__)

    async def subscribe_events(self, ping_interval: float = 10.0) -> AsyncGenerator[dict, None]:
        """Subscribes a client to the tool installation SSE stream with keepalive pings."""
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(q)
        try:
            while True:
                try:
                    payload = await asyncio.wait_for(q.get(), timeout=ping_interval)
                    yield payload
                except asyncio.TimeoutError:
                    yield {
                        "event": "ping",
                        "data": {"timestamp": time.time()},
                    }
        finally:
            self._subscribers.discard(q)

    def cancel_installation(self, tool_name: str) -> bool:
        """Cancels any running installation task for the given tool."""
        tool_name = tool_name.lower()
        task_id = self._tool_to_task.get(tool_name)
        if task_id and task_id in self._active_tasks:
            task = self._active_tasks[task_id]
            task.cancel()
            return True
        return False

    def install_tool(self, tool_name: str, force: bool = False) -> ToolInstallResponse:
        """
        Asynchronously triggers the in-app installation of a tool with pip serialization.
        """
        inst = self.get_installer(tool_name)
        if not inst:
            raise ValueError(f"Unknown tool '{tool_name}' for installation")

        # Cancel prior ongoing task for same tool if any
        self.cancel_installation(tool_name)

        task_id = f"tool-inst-{uuid.uuid4().hex[:8]}"
        self._tool_to_task[tool_name.lower()] = task_id

        async def _run_install():
            try:
                await self.broadcast_event(
                    "install_progress",
                    {
                        "task_id": task_id,
                        "tool_name": tool_name,
                        "percent": 5,
                        "stage": f"Queued installation for {inst.display_name}...",
                    },
                )

                async def _log_cb(msg: str):
                    await self.broadcast_event(
                        "install_log",
                        {
                            "task_id": task_id,
                            "tool_name": tool_name,
                            "message": msg,
                        },
                    )

                async def _prog_cb(pct: int, stg: str):
                    await self.broadcast_event(
                        "install_progress",
                        {
                            "task_id": task_id,
                            "tool_name": tool_name,
                            "percent": pct,
                            "stage": stg,
                        },
                    )

                # Serialize Pip installations to prevent concurrent site-packages write locking
                if isinstance(inst, PipToolInstaller):
                    await _log_cb(f"Acquiring global Pip execution lock for {inst.display_name}...")
                    async with self._pip_lock:
                        success = await inst.install(_log_cb, _prog_cb, force=force)
                else:
                    success = await inst.install(_log_cb, _prog_cb, force=force)

                info = await inst.get_info()

                if success:
                    await self.broadcast_event(
                        "install_completed",
                        {
                            "task_id": task_id,
                            "tool_name": tool_name,
                            "path": info.path,
                            "version": info.version,
                            "message": f"{inst.display_name} installed successfully and verified.",
                        },
                    )
                else:
                    await self.broadcast_event(
                        "install_failed",
                        {
                            "task_id": task_id,
                            "tool_name": tool_name,
                            "error": f"Installation script completed with failure state.",
                        },
                    )
            except asyncio.CancelledError:
                await self.broadcast_event(
                    "install_failed",
                    {
                        "task_id": task_id,
                        "tool_name": tool_name,
                        "error": "Installation was aborted by user request.",
                    },
                )
            except Exception as exc:
                await self.broadcast_event(
                    "install_failed",
                    {
                        "task_id": task_id,
                        "tool_name": tool_name,
                        "error": str(exc),
                    },
                )
            finally:
                self._active_tasks.pop(task_id, None)
                if self._tool_to_task.get(tool_name.lower()) == task_id:
                    self._tool_to_task.pop(tool_name.lower(), None)

        task = asyncio.create_task(_run_install())
        self._active_tasks[task_id] = task

        return ToolInstallResponse(
            task_id=task_id,
            tool_name=tool_name,
            status=ToolInstallStatus.INSTALLING,
            message=f"Queued automated installation for {inst.display_name}",
        )

    async def install_all(self, force: bool = False) -> List[ToolInstallResponse]:
        """
        Batch installs all missing managed user-space tools.

        Manual and native-engine entries remain in the 26-tool capability
        registry, but are intentionally excluded from automated installation;
        their manifest trust modes make that boundary explicit.
        """
        from app.installers.tool_manifest import PINNED_TOOL_MANIFEST

        responses = []
        user_space_tools = [
            name for name in self._installers
            if PINNED_TOOL_MANIFEST.get(name, {}).get("trust_mode")
            not in {"MANUAL_MODE", "NATIVE_ENGINE_MODE"}
        ]

        for name in user_space_tools:
            info = await self.get_tool_info(name)
            if force or not info or info.status != ToolInstallStatus.INSTALLED:
                resp = self.install_tool(name, force=force)
                responses.append(resp)

        return responses
