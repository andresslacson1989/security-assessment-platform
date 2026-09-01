"""
Contract 03 (Section 4) & Contract 08 (Section 8) Base Hybrid Tool Adapter.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
from abc import ABC, abstractmethod
import asyncio
import hashlib
import json
import os
import platform
import re
import shutil
import sys
from typing import Optional, List, Callable, Awaitable, Tuple

from app.core.models import Target, Finding, ScanConfig, LogLevel, NormalizedExecutionState
from app.core.binary_resolver import resolve_tool_binary, safe_execute_subprocess


class BaseToolAdapter(ABC):
    """
    Authoritative abstract contract for external CLI security tool adapters.
    """

    safe_execute_subprocess = staticmethod(safe_execute_subprocess)
    last_execution_state = NormalizedExecutionState.COMPLETED_NO_FINDINGS

    def _record_execution(self, returncode: int, stdout: str, stderr: str, findings_count: int = 0, parser_error: bool = False) -> None:
        """Map upstream process results to the platform execution-state contract."""
        if parser_error:
            self.last_execution_state = NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING if stdout.strip() else NormalizedExecutionState.TOOL_EXECUTION_FAILED
        elif "timed out" in (stderr or "").lower():
            self.last_execution_state = NormalizedExecutionState.EXECUTION_TIMED_OUT
        elif returncode == 126 and "security check" in (stderr or "").lower():
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
        elif returncode != 0 and not stdout.strip():
            self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
        elif findings_count:
            self.last_execution_state = NormalizedExecutionState.COMPLETED_WITH_FINDINGS
        elif returncode in (0, 1):
            self.last_execution_state = NormalizedExecutionState.COMPLETED_NO_FINDINGS
        else:
            self.last_execution_state = NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING if stdout.strip() else NormalizedExecutionState.TOOL_EXECUTION_FAILED

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

    async def ensure_approved_version(
        self,
        custom_path: Optional[str] = None,
        emit_log: Optional[Callable[[LogLevel, str], Awaitable[None]]] = None,
        pre_launch_check: Optional[Callable[[], bool]] = None,
    ) -> bool:
        """Fail closed unless the resolved executable reports its exact approved version."""
        expected = getattr(self, "approved_version", None)
        if not expected:
            return True
        version_output = await self.get_version(custom_path, pre_launch_check=pre_launch_check)
        match = re.search(r"(?<![0-9A-Za-z.-])v?(\d+\.\d+\.\d+)(?![0-9A-Za-z.-])", version_output or "")
        actual = match.group(1) if match else None
        expected_clean = str(expected).lstrip("v")
        if actual != expected_clean:
            if hasattr(self, "last_execution_state"):
                from app.core.models import NormalizedExecutionState
                self.last_execution_state = NormalizedExecutionState.INVALID_VERSION
            if emit_log:
                await emit_log(
                    LogLevel.ERROR,
                    f"{self.tool_name} execution blocked: approved version {expected_clean}, found {actual or 'unavailable'}.",
                )
            return False
        return True

    def verify_managed_binary(self, binary: str) -> bool:
        """Verify the installer-created identity record for direct managed binaries."""
        managed_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "bin"))
        path = os.path.abspath(binary)
        package_name = getattr(self, "package_name", None)
        if package_name:
            python_roots = {
                os.path.abspath(os.path.dirname(sys.executable)),
                os.path.abspath(sys.prefix),
            }
            try:
                if not any(os.path.commonpath([path, root]) == root for root in python_roots):
                    return False
                from importlib.metadata import version
                return version(package_name) == str(getattr(self, "approved_version", "")).lstrip("v")
            except Exception:
                return False
        if self.tool_name == "schemathesis":
            # Schemathesis is governed as a package-manager tool. Accept only
            # the active interpreter's executable and exact installed metadata.
            python_roots = {
                os.path.abspath(os.path.dirname(sys.executable)),
                os.path.abspath(sys.prefix),
            }
            in_python_root = False
            for root in python_roots:
                try:
                    if os.path.commonpath([path, root]) == root:
                        in_python_root = True
                        break
                except ValueError:
                    continue
            if not in_python_root:
                return False
            try:
                from importlib.metadata import version
                return version("schemathesis") == str(getattr(self, "approved_version", ""))
            except Exception:
                return False
        if os.path.realpath(path) != path or os.path.dirname(path) != managed_dir:
            return False
        if os.path.basename(path).lower() not in {self.tool_name.lower(), f"{self.tool_name.lower()}.exe"}:
            return False
        try:
            with open(f"{path}.trust.json", "r", encoding="utf-8") as record_file:
                record = json.load(record_file)
            expected = str(getattr(self, "approved_version", "")).lstrip("v")
            if record.get("tool_id") != f"TOOL-{self.tool_name.upper()}":
                return False
            if record.get("trust_status") != "VALID" or str(record.get("tool_version", "")).lstrip("v") != expected:
                return False
            if record.get("executable_relative_path") != os.path.basename(path):
                return False
            if "ARCHIVE_INTEGRITY_VERIFIED" not in record.get("claims", []) or "EXECUTABLE_INTEGRITY_VERIFIED" not in record.get("claims", []):
                return False
            with open(path, "rb") as binary_file:
                digest = hashlib.sha256(binary_file.read()).hexdigest()
            return digest == record.get("executable_sha256")
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return False

    @abstractmethod
    async def get_version(
        self,
        custom_path: Optional[str] = None,
        pre_launch_check: Optional[Callable[[], bool]] = None,
    ) -> Optional[str]:
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
