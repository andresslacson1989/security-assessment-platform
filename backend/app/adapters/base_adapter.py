"""
Contract 03 (Section 4) & Contract 08 (Section 8) Base Hybrid Tool Adapter.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
from abc import ABC, abstractmethod
import asyncio
import os
import shutil
from typing import Optional, List, Callable, Awaitable, Tuple

from app.core.models import Target, Finding, ScanConfig, LogLevel


class BaseToolAdapter(ABC):
    """
    Authoritative abstract contract for external CLI security tool adapters (Nmap, Nuclei, Semgrep, Trivy).
    """

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name of executable: 'nmap', 'nuclei', 'semgrep', 'trivy'."""
        pass

    def resolve_binary_path(self, custom_path: Optional[str] = None) -> Optional[str]:
        """
        Resolves executable path using custom_path first, then falls back to system PATH via shutil.which().
        """
        if custom_path:
            # If custom_path is a direct file path that exists
            if os.path.isfile(custom_path):
                return os.path.abspath(custom_path)
            # If custom_path is a binary name on PATH
            resolved = shutil.which(custom_path)
            if resolved:
                return resolved

        # Fall back to resolving tool_name in system PATH
        return shutil.which(self.tool_name)

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
    ) -> Tuple[int, str, str]:
        """
        Safe subprocess execution helper with bounded timeout (default 60s), non-blocking
        async communicate, graceful termination on cancellation / timeout, and zero
        unhandled exception leakage.

        Returns: (returncode, stdout_str, stderr_str)
        """
        if not cmd:
            return -1, "", "Empty command provided"

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
            stdout_str = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
            stderr_str = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
            return proc.returncode if proc.returncode is not None else 0, stdout_str, stderr_str

        except asyncio.TimeoutError:
            if emit_log:
                await emit_log(
                    LogLevel.WARNING,
                    f"Tool adapter '{self.tool_name}' timed out after {timeout}s. Terminating child process...",
                )
            if proc:
                try:
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=1.0)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            return -1, "", f"Execution timed out after {timeout} seconds"

        except asyncio.CancelledError:
            if emit_log:
                await emit_log(
                    LogLevel.WARNING,
                    f"Tool adapter '{self.tool_name}' cancelled. Terminating child process...",
                )
            if proc:
                try:
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=0.5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            raise

        except FileNotFoundError as e:
            if emit_log:
                await emit_log(
                    LogLevel.WARNING,
                    f"Executable not found for '{self.tool_name}': {e}",
                )
            return 127, "", f"Executable not found: {e}"

        except PermissionError as e:
            if emit_log:
                await emit_log(
                    LogLevel.ERROR,
                    f"Permission denied executing '{self.tool_name}': {e}",
                )
            return 126, "", f"Permission denied: {e}"

        except Exception as e:
            if emit_log:
                await emit_log(
                    LogLevel.ERROR,
                    f"Unhandled error executing tool adapter '{self.tool_name}': {e}",
                )
            return -1, "", str(e)
