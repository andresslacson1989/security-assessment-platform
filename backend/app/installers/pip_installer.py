"""
Contract 03 & 08 Pure Python Package Pip Installer (sslyze, bandit, semgrep, checkov).
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import asyncio
import os
import sys
from pathlib import Path
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
        return f"python -m pip install --require-hashes -r tool-requirements/{self._tool_name}.lock"

    @property
    def download_url(self) -> Optional[str]:
        pkg = self._cfg["package_name"]
        return f"https://pypi.org/project/{pkg}/"

    def resolve_binary_path(self) -> Optional[str]:
        """Resolve only the managed per-tool venv before diagnostic fallbacks."""
        venv_root = Path(os.environ.get(
            "CYBERASSESS_TOOL_VENV_DIR",
            str(Path(__file__).resolve().parents[2] / ".tool-venvs"),
        )).resolve()
        venv_bin = venv_root / self._tool_name / ("Scripts" if os.name == "nt" else "bin")
        for candidate in (venv_bin / f"{self._cfg['binary_name']}.exe", venv_bin / self._cfg["binary_name"]):
            if candidate.is_file():
                return str(candidate)
        return super().resolve_binary_path()

    async def get_version(self) -> Optional[str]:
        pkg = self._cfg["package_name"]
        path = self.resolve_binary_path()
        if path:
            try:
                return_code, stdout, stderr = await process_supervisor.execute(
                    [path, "--version"], timeout=5.0, max_output_bytes=1024 * 1024,
                )
                if return_code == 0:
                    output = (stdout or stderr or "").strip()
                    if output:
                        return output.splitlines()[0]
            except Exception:
                pass

        # Metadata fallback is useful for diagnostics when the executable is
        # not present, but it is never preferred over the managed executable.
        try:
            from importlib.metadata import version
            ver = version(pkg)
            if ver:
                return f"{pkg} {ver}"
        except Exception:
            pass

        return None

    async def install(
        self,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        force: bool = False,
    ) -> bool:
        pkg = self._cfg["package_name"]
        lock_path = Path(__file__).resolve().parents[2] / "tool-requirements" / f"{self._tool_name}.lock"
        if not lock_path.is_file():
            await emit_log(f"Package '{pkg}' installation rejected: its hash-locked requirements file is missing.")
            await emit_progress(100, f"Missing locked requirements for {pkg}")
            return False

        venv_root = Path(os.environ.get(
            "CYBERASSESS_TOOL_VENV_DIR",
            str(Path(__file__).resolve().parents[2] / ".tool-venvs"),
        )).resolve()
        venv_dir = venv_root / self._tool_name
        venv_python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        await emit_log(f"Starting pip installation for package '{pkg}'...")
        await emit_progress(10, f"Initializing pip install for {pkg}...")

        if not venv_python.is_file() or force:
            await emit_progress(20, f"Creating isolated environment for {pkg}...")
            create_ret, _, create_err = await process_supervisor.execute(
                [sys.executable, "-m", "venv", str(venv_dir)],
                timeout=120.0,
                max_output_bytes=10 * 1024 * 1024,
            )
            if create_ret != 0:
                await emit_log(f"Virtual environment creation failed with exit code {create_ret}: {create_err}")
                await emit_progress(100, f"Environment creation failed for {pkg}")
                return False

        cmd = [str(venv_python), "-m", "pip", "install", "--require-hashes", "-r", str(lock_path)]
        if force:
            cmd.insert(5, "--force-reinstall")

        await emit_progress(30, f"Running: {' '.join(cmd)}")

        try:
            ret, stdout, stderr = await process_supervisor.execute(
                cmd,
                timeout=600.0,
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
