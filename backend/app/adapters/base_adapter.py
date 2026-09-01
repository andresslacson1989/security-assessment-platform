"""
Contract 03 (Section 4) & Contract 08 (Section 8) Base Hybrid Tool Adapter.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
from abc import ABC, abstractmethod
import asyncio
import os
import shutil
import sys
from typing import Optional, List, Callable, Awaitable, Tuple

from app.core.models import Target, Finding, ScanConfig, LogLevel
from app.core.binary_resolver import resolve_tool_binary, safe_execute_subprocess


class BaseToolAdapter(ABC):
    """
    Authoritative abstract contract for external CLI security tool adapters.
    """

    safe_execute_subprocess = staticmethod(safe_execute_subprocess)

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name of executable: 'nmap', 'nuclei', 'semgrep', 'trivy'."""
        pass

    def resolve_binary_path(self, custom_path: Optional[str] = None) -> Optional[str]:
        """
        Deterministic 5-Tier Binary Resolution Order:
        Tier 1: Explicit custom configured path (if file exists and is executable or on PATH)
        Tier 2: In-App Managed Binaries directory ('backend/bin/<tool_name>[.exe|.bat|.cmd|.pl]')
        Tier 3: Active Python environment Scripts / bin directory (for pip-installed tools)
        Tier 4: System PATH discovery via shutil.which(tool_name)
        Tier 5: Platform-Specific Auto-Discovery (Windows Registry, multi-drive Program Files, package managers, Unix paths)
        """
        local_bin_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "bin"))
        return resolve_tool_binary(
            tool_name=self.tool_name,
            custom_path=custom_path,
            local_bin_dir=local_bin_dir,
        )

    async def is_available(self, custom_path: Optional[str] = None) -> bool:
        """
        Checks if tool executable is present and accessible on host.
        """
        path = self.resolve_binary_path(custom_path)
        if not path:
            return False
        return os.path.isfile(path) or os.path.exists(path)

    @abstractmethod
    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        """
        Retrieves CLI tool version string (e.g. 'Nmap 7.94', 'nuclei v3.2.0').
        """
        pass

    @abstractmethod
    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
        **kwargs,
    ) -> List[Finding]:
        """
        Executes CLI command asynchronously, parses stdout/JSON/XML, and normalizes findings.
        """
        pass

    async def execute_command(
        self,
        cmd: List[str],
        timeout: float = 60.0,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
        emit_log: Optional[Callable[[LogLevel, str], Awaitable[None]]] = None,
        pre_launch_check: Optional[Callable[[], bool]] = None,
    ) -> Tuple[int, str, str]:
        """
        Safe subprocess execution helper with bounded timeout (default 60s), non-blocking
        async communicate, graceful termination on cancellation / timeout, and zero
        unhandled exception leakage.

        Returns: (returncode, stdout_str, stderr_str)
        """
        if not cmd:
            return -1, "", "Empty command provided"

        code, stdout, stderr = await self.safe_execute_subprocess(
            cmd=cmd,
            timeout=timeout,
            cwd=cwd,
            env=env,
            pre_launch_check=pre_launch_check,
        )

        if code != 0 and emit_log:
            if "timed out" in stderr.lower():
                await emit_log(
                    LogLevel.WARNING,
                    f"Tool adapter '{self.tool_name}' timed out after {timeout}s.",
                )
            elif "not found" in stderr.lower():
                await emit_log(
                    LogLevel.WARNING,
                    f"Executable not found for '{self.tool_name}': {stderr}",
                )
            elif "denied" in stderr.lower():
                await emit_log(
                    LogLevel.ERROR,
                    f"Permission denied executing '{self.tool_name}': {stderr}",
                )

        return code, stdout, stderr
