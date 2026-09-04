"""
Core Binary Resolver and Deterministic Multi-Tier Executable Discovery Utility.
Authoritative Contract: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md

Deterministic 5-Tier Binary Resolution Order:
Tier 1: Explicit custom configured path (if file exists or resolves via PATH)
Tier 2: In-App Managed Binaries directory ('backend/bin/<tool_name>[.exe|.bat|.cmd|.pl]')
Tier 3: Active Python environment Scripts / bin directory (for pip-installed CLI tools)
Tier 4: System PATH discovery via shutil.which(tool_name)
Tier 5: Platform-Specific Auto-Discovery:
        - Windows Registry (HKLM & HKCU Uninstall keys for MSI/winget/standard installers)
        - Windows Multi-Drive Program Files scan (C:, D:, E:, etc. for standard installs)
        - Windows Package Managers (Chocolatey, Scoop shims/apps, LocalAppData Programs)
        - Unix / Linux / macOS standard paths (/usr/local/bin, /opt/homebrew/bin, /usr/bin, /snap/bin, ~/.local/bin)
"""

from __future__ import annotations
import logging
import asyncio
import os
import shutil
import string
import subprocess
import sys
from typing import Callable, Optional, List

from app.core.process_supervisor import (
    CredentialEnvironmentHandoff,
    CredentialExecutionContext,
    ProcessExecutionResult,
    VerifiedEgressProxy,
)

logger = logging.getLogger("cyberassess.binary_resolver")


def get_default_bin_dir() -> str:
    """Returns the default in-app managed binaries directory: backend/bin/."""
    bin_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "bin")
    )
    os.makedirs(bin_dir, exist_ok=True)
    return bin_dir


def _find_in_windows_registry(tool_name: str) -> Optional[str]:
    """Scans Windows Registry uninstall keys to discover installer-registered executables."""
    if sys.platform != "win32":
        return None
    try:
        import winreg
        roots = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        for hkey, subkey in roots:
            try:
                with winreg.OpenKey(hkey, subkey) as key:
                    num_subkeys, _, _ = winreg.QueryInfoKey(key)
                    for i in range(num_subkeys):
                        try:
                            child_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, child_name) as child_key:
                                dname = ""
                                loc = ""
                                icon = ""
                                try:
                                    dname, _ = winreg.QueryValueEx(child_key, "DisplayName")
                                except Exception as exc:
                                    logger.debug("Windows registry DisplayName lookup failed: error_type=%s", type(exc).__name__)
                                try:
                                    loc, _ = winreg.QueryValueEx(child_key, "InstallLocation")
                                except Exception as exc:
                                    logger.debug("Windows registry InstallLocation lookup failed: error_type=%s", type(exc).__name__)
                                try:
                                    icon, _ = winreg.QueryValueEx(child_key, "DisplayIcon")
                                except Exception as exc:
                                    logger.debug("Windows registry DisplayIcon lookup failed: error_type=%s", type(exc).__name__)
                                
                                if (
                                    tool_name.lower() in str(dname).lower()
                                    or tool_name.lower() in str(loc).lower()
                                    or tool_name.lower() in str(icon).lower()
                                ):
                                    candidate_dirs = [str(loc), os.path.dirname(str(icon).strip('"'))]
                                    for cdir in candidate_dirs:
                                        if cdir and os.path.isdir(cdir):
                                            for ext in [".exe", ".bat", ".cmd", ""]:
                                                exe_path = os.path.join(cdir, f"{tool_name}{ext}")
                                                if os.path.isfile(exe_path):
                                                    return os.path.abspath(exe_path)
                        except Exception as exc:
                            logger.debug("Windows registry entry inspection failed: error_type=%s", type(exc).__name__)
            except Exception as exc:
                logger.debug("Windows registry root inspection failed: error_type=%s", type(exc).__name__)
    except Exception as exc:
        logger.debug("Windows registry discovery unavailable: error_type=%s", type(exc).__name__)
    return None


def _find_in_windows_standard_paths(tool_name: str) -> Optional[str]:
    """Scans all active Windows drive letters, Program Files, Scoop, and Chocolatey directories."""
    if sys.platform != "win32":
        return None

    # Check all active drive letters for Program Files installs (e.g. D:\Program Files (x86)\Nmap)
    drives = [f"{d}:" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
    for drive in drives:
        for pf in ["Program Files", "Program Files (x86)", "tools", "ProgramData"]:
            for folder in [tool_name, tool_name.capitalize(), tool_name.upper()]:
                for ext in [".exe", ".bat", ".cmd", ""]:
                    cand = os.path.join(drive, "\\", pf, folder, f"{tool_name}{ext}")
                    if os.path.isfile(cand):
                        return os.path.abspath(cand)

    # Package managers and user directories
    user_home = os.path.expanduser("~")
    pkg_candidates = [
        os.path.join(user_home, "scoop", "shims", f"{tool_name}.exe"),
        os.path.join(user_home, "scoop", "shims", f"{tool_name}.cmd"),
        os.path.join(user_home, "scoop", "apps", tool_name, "current", f"{tool_name}.exe"),
        os.path.join(os.environ.get("ChocolateyInstall", r"C:\ProgramData\chocolatey"), "bin", f"{tool_name}.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", tool_name, f"{tool_name}.exe"),
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), tool_name.capitalize(), f"{tool_name}.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), tool_name.capitalize(), f"{tool_name}.exe"),
    ]
    for cand in pkg_candidates:
        if cand and os.path.isfile(cand):
            return os.path.abspath(cand)

    return None


def _find_in_unix_standard_paths(tool_name: str) -> Optional[str]:
    """Scans standard Unix/Linux/macOS directories."""
    unix_dirs = [
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/opt",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        "/snap/bin",
        os.path.expanduser("~/.local/bin"),
        os.path.expanduser("~/bin"),
    ]
    for udir in unix_dirs:
        cand = os.path.join(udir, tool_name)
        if os.path.isfile(cand):
            return os.path.abspath(cand)
    return None


def resolve_tool_binary(
    tool_name: str,
    custom_path: Optional[str] = None,
    local_bin_dir: Optional[str] = None,
) -> Optional[str]:
    """
    Deterministic 5-Tier Binary Resolution Order:
    Tier 1: Explicit custom configured path (if file exists or resolves on PATH)
    Tier 2: In-App Managed Binaries directory ('backend/bin/<tool_name>[.exe|.bat|.cmd|.pl]')
    Tier 3: Active Python environment Scripts / bin directory (for pip-installed tools)
    Tier 4: System PATH discovery via shutil.which(tool_name)
    Tier 5: Platform-Specific Auto-Discovery (Windows Registry, drive scan, package managers, Unix dirs)
    """
    if not isinstance(tool_name, str) or not tool_name.strip():
        return None

    # Tier 1: Explicit custom configured path
    if custom_path:
        if os.path.isfile(custom_path):
            return os.path.abspath(custom_path)
        resolved = shutil.which(custom_path)
        if resolved:
            return resolved

    # Tier 2: In-App Managed Binaries directory ('backend/bin/<tool_name>[.exe|.bat|.cmd|.pl]')
    bin_dir = local_bin_dir or get_default_bin_dir()
    exts = [".exe", ".bat", ".cmd", ".pl", ""] if sys.platform == "win32" else ["", ".sh", ".pl"]
    for ext in exts:
        candidate = os.path.join(bin_dir, f"{tool_name}{ext}")
        if os.path.isfile(candidate):
            if sys.platform != "win32" and not os.access(candidate, os.X_OK):
                continue
            return os.path.abspath(candidate)

    # Tier 3: Python environment Scripts / bin directory (for pip-installed tools)
    tool_venv_root = os.environ.get("CYBERASSESS_TOOL_VENV_DIR")
    if tool_venv_root:
        venv_dir = os.path.join(os.path.abspath(tool_venv_root), tool_name)
        venv_bin_dir = os.path.join(venv_dir, "Scripts") if sys.platform == "win32" else os.path.join(venv_dir, "bin")
        for candidate in (os.path.join(venv_bin_dir, f"{tool_name}.exe"), os.path.join(venv_bin_dir, tool_name)):
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)

    py_dir = os.path.dirname(sys.executable)
    py_candidates = [
        os.path.join(py_dir, "Scripts", f"{tool_name}.exe"),
        os.path.join(py_dir, "Scripts", tool_name),
        os.path.join(py_dir, f"{tool_name}.exe"),
        os.path.join(py_dir, tool_name),
        os.path.join(sys.prefix, "bin", tool_name),
        os.path.join(sys.prefix, "Scripts", f"{tool_name}.exe"),
    ]
    for candidate in py_candidates:
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)

    # Tier 4: System PATH discovery via shutil.which(tool_name)
    resolved_path = shutil.which(tool_name)
    if resolved_path:
        return resolved_path

    # Tier 5: Platform-Specific Auto-Discovery
    if sys.platform == "win32":
        # 5a: Windows Registry Uninstall discovery
        reg_match = _find_in_windows_registry(tool_name)
        if reg_match:
            return reg_match

        # 5b: Windows Drive Scan & Standard Folders
        std_match = _find_in_windows_standard_paths(tool_name)
        if std_match:
            return std_match
    else:
        unix_match = _find_in_unix_standard_paths(tool_name)
        if unix_match:
            return unix_match

    return None


# Canonical alias
resolve_binary = resolve_tool_binary


async def safe_execute_subprocess(
    cmd: List[str],
    timeout: float = 60.0,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    max_output_bytes: int = 10 * 1024 * 1024,
    pre_launch_check: Optional[Callable[[], bool]] = None,
    execution_id: Optional[str] = None,
    scanner_egress_proxy: Optional[VerifiedEgressProxy] = None,
    credential_handoff: Optional[CredentialEnvironmentHandoff] = None,
    credential_context: Optional[CredentialExecutionContext] = None,
) -> ProcessExecutionResult:
    """
    Loop-agnostic safe subprocess execution helper.
    Delegates to central ProcessSupervisor to track subprocesses and guarantee
    clean process tree termination on timeout or cancellation.
    """
    if not cmd:
        return -1, "", "Empty command provided"

    from app.core.process_supervisor import process_supervisor
    result = await process_supervisor.execute(
        cmd=cmd,
        timeout=timeout,
        cwd=cwd,
        env=env,
        max_output_bytes=max_output_bytes,
        pre_launch_check=pre_launch_check,
        execution_id=execution_id,
        scanner_egress_proxy=scanner_egress_proxy,
        credential_handoff=credential_handoff,
        credential_context=credential_context,
    )
    code, stdout, stderr = result
    if "<3>WSL" in stderr:
        cleaned_lines = [line for line in stderr.splitlines() if not line.startswith("<3>WSL")]
        stderr = "\n".join(cleaned_lines)
        return ProcessExecutionResult(code, stdout, stderr)
    return result
