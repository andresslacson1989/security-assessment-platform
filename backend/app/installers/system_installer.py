"""
Contract 03 & 08 System / Driver-Level Tool Helper (nmap, nikto).
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import asyncio
import os
import platform
import shutil
import sys
from typing import Optional, Dict

from app.core.models import ToolInstallMethod
from app.installers.base_installer import (
    BaseToolInstaller,
    LogCallback,
    ProgressCallback,
)


SYSTEM_TOOL_CONFIGS: Dict[str, dict] = {
    "nmap": {
        "display_name": "Nmap Network & Port Scanner (NSE)",
        "category": "Network Perimeter",
        "command_hint": {
            "windows": "winget install Insecure.Nmap (or install from https://nmap.org/dist/nmap-setup.exe with Npcap)",
            "linux": "sudo apt-get update && sudo apt-get install -y nmap",
            "darwin": "brew install nmap",
        },
        "download_url": "https://nmap.org/download.html",
        "version_cmd": ["--version"],
    },
    "nikto": {
        "display_name": "Nikto Web Server Misconfiguration Scanner",
        "category": "Web DAST",
        "command_hint": {
            "windows": "scoop install nikto (or 'choco install nikto' / clone https://github.com/sullo/nikto with Strawberry Perl)",
            "linux": "sudo apt-get update && sudo apt-get install -y nikto",
            "darwin": "brew install nikto",
        },
        "download_url": "https://github.com/sullo/nikto",
        "version_cmd": ["-Version"],
    },
    "retire": {
        "display_name": "Retire.js Client-Side JavaScript CVE Auditor",
        "category": "Code SAST",
        "command_hint": {
            "windows": "npm install -g retire (or clone https://github.com/RetireJS/retire.js)",
            "linux": "npm install -g retire",
            "darwin": "npm install -g retire",
        },
        "download_url": "https://github.com/RetireJS/retire.js",
        "version_cmd": ["--version"],
    },
}


class SystemToolHelper(BaseToolInstaller):
    """
    Helper for driver/system level tools that require elevated or package-manager installation.
    Provides verified terminal command snippets and platform launch instructions.
    """

    def __init__(self, tool_name: str):
        if tool_name not in SYSTEM_TOOL_CONFIGS:
            raise ValueError(f"Unknown SystemToolHelper target: {tool_name}")
        self._tool_name = tool_name
        self._cfg = SYSTEM_TOOL_CONFIGS[tool_name]

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
        return ToolInstallMethod.SYSTEM_PACKAGE_MANAGER

    @property
    def is_elevated_required(self) -> bool:
        return True

    @property
    def install_command_hint(self) -> str:
        hints = self._cfg["command_hint"]
        if sys.platform == "win32" or "windows" in platform.system().lower():
            return hints["windows"]
        elif "darwin" in platform.system().lower():
            return hints["darwin"]
        else:
            return hints["linux"]

    @property
    def download_url(self) -> Optional[str]:
        return self._cfg["download_url"]

    async def get_version(self) -> Optional[str]:
        path = self.resolve_binary_path()
        if not path:
            return None
        cmd = [path] + self._cfg["version_cmd"]
        try:
            import subprocess
            def _run():
                return subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=5.0,
                    encoding="utf-8",
                    errors="replace",
                )
            res = await asyncio.to_thread(_run)
            if res.returncode != 0:
                return None
            text = (res.stdout or "").strip()
            if not text:
                return None
            first_line = text.splitlines()[0].strip()
            if any(err in first_line.lower() for err in ["error:", "not found", "can't locate", "failed"]):
                return None
            return first_line
        except Exception:
            return None

    async def install(
        self,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        force: bool = False,
    ) -> bool:
        await emit_log(f"System-level tool '{self.tool_name}' requires elevated privileges or OS package manager.")
        await emit_progress(20, f"Evaluating OS package manager for {self.display_name}...")

        # If winget / brew / apt is available, try running or provide hint
        cmd_hint = self.install_command_hint
        await emit_log(f"Recommended installation command: {cmd_hint}")
        await emit_log(f"Official download website: {self.download_url}")

        # Check if already installed
        ver = await self.get_version()
        if ver:
            await emit_progress(100, f"{self.display_name} is already available: {ver}")
            await emit_log(f"Detected existing installation: {ver}")
            return True

        await emit_progress(100, f"Please run in terminal: {cmd_hint}")
        return False
