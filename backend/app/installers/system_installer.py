"""
Contract 03 & 08 System / Driver-Level Tool Helper and manually provisioned tools.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import asyncio
import os
import platform
import re
import shutil
import sys
from typing import Optional, Dict

from app.core.models import ToolInstallMethod
from app.installers.base_installer import (
    BaseToolInstaller,
    LogCallback,
    ProgressCallback,
)
from app.core.process_supervisor import process_supervisor
from app.core.execution_context import issue_non_scan_execution_context


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
        "approved_version": "7.95",
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
        "approved_version": "4.4.3",
    },
    "metasploit": {
        "display_name": "Metasploit Auxiliary Verification Framework",
        "category": "Exploit Verification",
        "command_hint": {"windows": "Install from the official Metasploit package: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html", "linux": "Install from the official Metasploit package: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html", "darwin": "Install from the official Metasploit package: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"},
        "download_url": "https://github.com/rapid7/metasploit-framework",
        "version_cmd": ["-v"],
        "binary_name": "msfconsole",
    },
    "sqlmap": {
        "display_name": "sqlmap Bounded SQL Injection Verifier",
        "category": "Web DAST",
        "command_hint": {"windows": "Install the pinned sqlmap release through the approved isolated tool environment.", "linux": "Install the pinned sqlmap release through the approved isolated tool environment.", "darwin": "Install the pinned sqlmap release through the approved isolated tool environment."},
        "download_url": "https://github.com/sqlmapproject/sqlmap",
        "version_cmd": ["--version"],
        "binary_name": "sqlmap",
    },
    "amass": {
        "display_name": "OWASP Amass Passive Attack Surface Enumerator",
        "category": "Network Perimeter",
        "command_hint": {"windows": "Install from the official OWASP Amass release: https://github.com/owasp-amass/amass/releases", "linux": "Install from the official OWASP Amass release: https://github.com/owasp-amass/amass/releases", "darwin": "Install from the official OWASP Amass release: https://github.com/owasp-amass/amass/releases"},
        "download_url": "https://github.com/owasp-amass/amass",
        "version_cmd": ["-version"],
        "binary_name": "amass",
    },
    "hydra": {
        "display_name": "THC-Hydra Bounded Authentication Auditor",
        "category": "Authentication Resilience",
        "command_hint": {"windows": "Install from the approved isolated tool environment; use only for explicitly authorized credential audits.", "linux": "Install from the official THC-Hydra package: https://github.com/vanhauser-thc/thc-hydra", "darwin": "Install from the official THC-Hydra package: https://github.com/vanhauser-thc/thc-hydra"},
        "download_url": "https://github.com/vanhauser-thc/thc-hydra",
        "version_cmd": ["-h"],
        "binary_name": "hydra",
    },
    "gtfobins": {
        "display_name": "GTFOBins / LOLBAS Native Privilege Rule Engine",
        "category": "Host Privilege Escalation",
        "command_hint": {"windows": "Native rule engine; no external installation required.", "linux": "Native rule engine; no external installation required.", "darwin": "Native rule engine; no external installation required."},
        "download_url": "https://gtfobins.github.io/",
        "version_cmd": [],
        "binary_name": None,
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
            returncode, stdout, stderr = await process_supervisor.execute(
                cmd,
                timeout=5.0,
                max_output_bytes=1024 * 1024,
                non_scan_context=issue_non_scan_execution_context(f"installer:{self.tool_name}:version"),
            )
            if returncode != 0:
                return None
            text = (stdout or "").strip()
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
            approved_version = self._cfg.get("approved_version")
            if not approved_version:
                await emit_log(
                    f"System-level tool '{self.tool_name}' is diagnostic-only: no exact contract-approved version is configured."
                )
                await emit_progress(100, f"Assured installation unavailable for {self.tool_name}")
                return False
            version_match = re.search(r"(?<![0-9])v?([0-9]+(?:\.[0-9]+)+)(?![0-9])", ver)
            if not version_match or version_match.group(1) != approved_version:
                await emit_log(
                    f"System-level tool '{self.tool_name}' rejected: expected exact version {approved_version}, found {ver}."
                )
                await emit_progress(100, f"Version verification failed for {self.tool_name}")
                return False
            await emit_progress(100, f"{self.display_name} is already available: {ver}")
            await emit_log(f"Detected existing installation: {ver}")
            return True

        await emit_progress(100, f"Please run in terminal: {cmd_hint}")
        return False
