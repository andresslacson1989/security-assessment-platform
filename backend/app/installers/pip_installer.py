"""
Contract 03 & 08 Pure Python Package Pip Installer (sslyze, bandit, semgrep, checkov).
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import asyncio
import os
import sys
from typing import Optional, Dict

from app.core.models import ToolInstallMethod
from app.installers.base_installer import (
    BaseToolInstaller,
    LogCallback,
    ProgressCallback,
)
from app.core.process_supervisor import process_supervisor


PIP_TOOL_CONFIGS: Dict[str, dict] = {
    "sslyze": {
        "display_name": "SSLyze Deep TLS/SSL Configuration Auditor",
        "category": "Network & TLS",
        "package_name": "sslyze",
        "binary_name": "sslyze",
        "command_hint": "pip install --upgrade sslyze",
        "pinned_version": "5.2.0",
    },
    "bandit": {
        "display_name": "Bandit Python AST Security Linter",
        "category": "Code SAST",
        "package_name": "bandit",
        "binary_name": "bandit",
        "command_hint": "pip install --upgrade bandit",
        "pinned_version": "1.7.8",
    },
    "semgrep": {
        "display_name": "Semgrep Semantic SAST Engine",
        "category": "Code SAST",
        "package_name": "semgrep",
        "binary_name": "semgrep",
        "command_hint": "pip install --upgrade semgrep",
        "pinned_version": "1.65.0",
    },
    "checkov": {
        "display_name": "Checkov Infrastructure-as-Code Policy Auditor",
        "category": "Infra IaC",
        "package_name": "checkov",
        "binary_name": "checkov",
        "command_hint": "pip install --upgrade checkov",
        "pinned_version": "3.2.0",
    },
    "prowler": {
        "display_name": "Prowler Multi-Cloud CIS Benchmark & Posture Auditor",
        "category": "Cloud Posture",
        "package_name": "prowler",
        "binary_name": "prowler",
        "command_hint": "pip install --upgrade prowler",
        "pinned_version": "4.1.0",
    },
    "schemathesis": {
        "display_name": "Schemathesis Property-Based API Contract Fuzzer",
        "category": "API Security",
        "package_name": "schemathesis",
        "binary_name": "schemathesis",
        "command_hint": "pip install --upgrade schemathesis",
        "pinned_version": "3.20.0",
    },
}


class PipToolInstaller(BaseToolInstaller):
    """
    Installer for pure Python tools available on PyPI.
    Installs safely into the active Python environment with cross-platform threaded I/O streaming.
    """

    def __init__(self, tool_name: str):
        if tool_name not in PIP_TOOL_CONFIGS:
            raise ValueError(f"Unknown PipToolInstaller target: {tool_name}")
        self._tool_name = tool_name
        self._cfg = PIP_TOOL_CONFIGS[tool_name]

    @property
    def tool_name(self) -> str:
        return self._tool_name

    @property
    def display_name(self) -> str:
        return self._cfg["display_name"]

    @property
    def category(self) -> str:
        return self._cfg["category"]

    @property
    def install_method(self) -> ToolInstallMethod:
        return ToolInstallMethod.PIP

    @property
    def install_command_hint(self) -> str:
        return f"python -m pip install {self._cfg['package_name']}=={self._cfg['pinned_version']}"

    @property
    def download_url(self) -> Optional[str]:
        pkg = self._cfg["package_name"]
        return f"https://pypi.org/project/{pkg}/"

    async def get_version(self) -> Optional[str]:
        pkg = self._cfg["package_name"]
        try:
            from importlib.metadata import version
            ver = version(pkg)
            if ver:
                return f"{pkg} {ver}"
        except Exception:
            pass

        # Fallback: check binary directly via thread
        path = self.resolve_binary_path()
        if not path:
            return None

        try:
            return_code, stdout, stderr = await process_supervisor.execute(
                [path, "--version"],
                timeout=5.0,
                max_output_bytes=1024 * 1024,
            )
            if return_code != 0:
                return None
            output = (stdout or stderr or "").strip()
            return output.splitlines()[0] if output else None
        except Exception:
            return None

    async def install(
        self,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        force: bool = False,
    ) -> bool:
        pkg = self._cfg["package_name"]
        await emit_log(f"Starting pip installation for package '{pkg}'...")
        await emit_progress(10, f"Initializing pip install for {pkg}...")

        cmd = [sys.executable, "-m", "pip", "install", "--upgrade"]
        if force:
            cmd.append("--force-reinstall")
        cmd.append(f"{pkg}=={self._cfg['pinned_version']}")

        await emit_progress(30, f"Running: {' '.join(cmd)}")

        try:
            ret, stdout, stderr = await process_supervisor.execute(
                cmd,
                timeout=120.0,
                max_output_bytes=10 * 1024 * 1024,
            )
            output = stdout + (f"\n{stderr}" if stderr else "")
            for line in output.splitlines():
                if line.strip():
                    await emit_log(line.rstrip())

            if ret == 0:
                ver = await self.get_version()
                expected = f"{pkg} {self._cfg['pinned_version']}"
                if ver != expected:
                    await emit_progress(100, f"Pinned version verification failed for {pkg}: expected {expected}, found {ver or 'unavailable'}")
                    await emit_log(f"Package '{pkg}' installation rejected because the exact pinned version was not verified.")
                    return False
                await emit_progress(100, f"Successfully installed {expected}")
                await emit_log(f"Package '{pkg}' installed successfully at the pinned version.")
                return True

            await emit_progress(100, f"Pip installation failed with exit code {ret}")
            await emit_log(f"Pip installation failed with exit code {ret}.")
            return False
        except asyncio.CancelledError:
            await emit_log(f"Installation of {pkg} was cancelled by user.")
            raise
        except Exception as ex:
            await emit_log(f"Exception during pip execution: {type(ex).__name__}: {str(ex)}")
            await emit_progress(100, f"Installation error: {type(ex).__name__}: {str(ex)}")
            return False
