"""
Contract 03 §3: Central Process Supervisor & Execution Governance.
Tracks, bounds, and recursively terminates subprocess trees on cancellation or timeout.
"""

from __future__ import annotations
import asyncio
import ctypes
from ctypes import wintypes
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from enum import Enum
from typing import Callable, NamedTuple, Optional, Set

logger = logging.getLogger("cyberassess.process_supervisor")


class ProcessExecutionStatus(str, Enum):
    """Typed outcome for a supervised subprocess invocation."""

    COMPLETED = "COMPLETED"
    SECURITY_REJECTED = "SECURITY_REJECTED"
    TIMED_OUT = "TIMED_OUT"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    NOT_FOUND = "NOT_FOUND"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    FAILED = "FAILED"


class ProcessExecutionResult(NamedTuple):
    """Three-value-compatible process result with a typed execution status."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def execution_status(self) -> ProcessExecutionStatus:
        if self.stderr.startswith("PROCESS_LAUNCH_REJECTED_SECURITY"):
            return ProcessExecutionStatus.SECURITY_REJECTED
        if self.stderr.startswith("Output exceeded maximum"):
            return ProcessExecutionStatus.OUTPUT_LIMIT_EXCEEDED
        if self.stderr.startswith("Execution timed out"):
            return ProcessExecutionStatus.TIMED_OUT
        if self.returncode == 127 and self.stderr.startswith("Executable not found"):
            return ProcessExecutionStatus.NOT_FOUND
        if self.returncode == 126 and self.stderr.startswith("Permission denied"):
            return ProcessExecutionStatus.PERMISSION_DENIED
        if self.returncode == 0:
            return ProcessExecutionStatus.COMPLETED
        return ProcessExecutionStatus.FAILED


class ProcessSupervisor:
    """
    Central process supervisor tracking running external tool subprocesses,
    enforcing bounded execution timeouts, memory output quotas, and guaranteeing
    clean process tree termination on cancellation or timeout.
    """

    _instance: Optional[ProcessSupervisor] = None

    def __init__(self):
        self._active_pids: Set[int] = set()
        self._execution_pids: dict[str, int] = {}
        self._lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> ProcessSupervisor:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _register_execution(self, pid: int, execution_id: Optional[str] = None) -> None:
        with self._lock:
            self._active_pids.add(pid)
            if execution_id:
                self._execution_pids[execution_id] = pid

    def _unregister_execution(self, pid: int, execution_id: Optional[str] = None) -> None:
        with self._lock:
            self._active_pids.discard(pid)
            if execution_id and self._execution_pids.get(execution_id) == pid:
                self._execution_pids.pop(execution_id, None)

    def _register_pid(self, pid: int) -> None:
        self._register_execution(pid)

    def _unregister_pid(self, pid: int) -> None:
        self._unregister_execution(pid)

    def cancel_execution(self, execution_id: str) -> bool:
        """
        Safely cancels a specific execution by execution_id without affecting sibling executions.
        Returns True if the execution was actively tracked and terminated, False otherwise.
        """
        if not execution_id or not isinstance(execution_id, str):
            return False
        with self._lock:
            pid = self._execution_pids.pop(execution_id, None)
            if pid:
                self._active_pids.discard(pid)
        if pid:
            self.kill_process_tree(pid)
            return True
        return False

    def cancel_pid(self, pid: int) -> bool:
        """
        Safely cancels a specific process by PID if it is tracked by this supervisor.
        """
        if not pid or pid <= 0:
            return False
        with self._lock:
            if pid not in self._active_pids:
                return False
            self._active_pids.discard(pid)
            to_remove = [k for k, v in self._execution_pids.items() if v == pid]
            for k in to_remove:
                self._execution_pids.pop(k, None)
        self.kill_process_tree(pid)
        return True

    @staticmethod
    def _windows_descendant_pids(root_pid: int) -> list[int]:
        """Return a snapshot of descendants using the Windows process table."""
        if sys.platform != "win32":
            return []

        current_pid = os.getpid()
        parent_pid = os.getppid() if hasattr(os, "getppid") else None

        class _ProcessEntry32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        invalid_handle = ctypes.c_void_p(-1).value
        if snapshot == invalid_handle:
            return []
        try:
            entry = _ProcessEntry32()
            entry.dwSize = ctypes.sizeof(_ProcessEntry32)
            first = ctypes.windll.kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            if not first:
                return []
            parent_map: dict[int, list[int]] = {}
            while first:
                parent_map.setdefault(int(entry.th32ParentProcessID), []).append(int(entry.th32ProcessID))
                first = ctypes.windll.kernel32.Process32NextW(snapshot, ctypes.byref(entry))
            descendants: list[int] = []
            pending = list(parent_map.get(root_pid, []))
            while pending:
                child = pending.pop()
                if child > 1 and child != current_pid and (parent_pid is None or child != parent_pid):
                    descendants.append(child)
                    pending.extend(parent_map.get(child, []))
            return descendants
        finally:
            ctypes.windll.kernel32.CloseHandle(snapshot)

    @staticmethod
    def _windows_terminate_pid(pid: int) -> None:
        """Terminate one Windows process by PID when taskkill misses a race."""
        current_pid = os.getpid()
        parent_pid = os.getppid() if hasattr(os, "getppid") else None
        if pid <= 1 or pid == current_pid or (parent_pid is not None and pid == parent_pid):
            logger.warning("Refusing to terminate current or parent process PID=%s", pid)
            return

        process = ctypes.windll.kernel32.OpenProcess(0x0001 | 0x1000, False, pid)
        if process:
            try:
                ctypes.windll.kernel32.TerminateProcess(process, 1)
            finally:
                ctypes.windll.kernel32.CloseHandle(process)

    @staticmethod
    def kill_process_tree(pid: int) -> None:
        """
        Recursively terminates a process and all its child/grandchild descendants.
        Guarantees isolation: never signals the host, server process, or sibling processes.
        """
        if not pid or pid <= 0:
            return

        current_pid = os.getpid()
        parent_pid = os.getppid() if hasattr(os, "getppid") else None
        if pid == current_pid or (parent_pid is not None and pid == parent_pid) or pid <= 1:
            logger.error("Security invariant: Refusing to terminate current/parent PID=%s", pid)
            return

        if sys.platform == "win32":
            try:
                # Capture descendants before terminating the root.
                descendants = ProcessSupervisor._windows_descendant_pids(pid)
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                for descendant in reversed(descendants):
                    ProcessSupervisor._windows_terminate_pid(descendant)
                ProcessSupervisor._windows_terminate_pid(pid)
            except Exception as e:
                logger.debug(f"Failed to taskkill PID +{pid}: {e}")
                try:
                    os.kill(pid, signal.SIGTERM)
                except Exception as exc:
                    logger.debug("Fallback termination failed for PID=%s: error_type=%s", pid, type(exc).__name__)
        else:
            try:
                # POSIX process isolation:
                # Only signal a process group if the process is its own group leader (pgid == pid),
                # which was spawned with start_new_session=True, AND pgid != current process group!
                current_pgrp = os.getpgrp()
                pgid = os.getpgid(pid)
                if pgid > 1 and pgid == pid and pgid != current_pgrp:
                    os.killpg(pgid, signal.SIGKILL)
                else:
                    os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception as exc:
                logger.debug("Process-group termination failed for PID=%s: error_type=%s", pid, type(exc).__name__)
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception as fallback_exc:
                    logger.debug("Fallback process termination failed for PID=%s: error_type=%s", pid, type(fallback_exc).__name__)

    _SAFE_ENVIRONMENT_KEYS = frozenset({
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "COMMONPROGRAMFILES",
        "COMMONPROGRAMFILES(X86)",
        "ALLUSERSPROFILE",
        "PUBLIC",
        "OS",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_ARCHITEW6432",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "TMP",
        "TEMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PYTHONIOENCODING",
        "PYTHONUNBUFFERED",
        "PYTHONPATH",
        "COMSPEC",
    })

    @classmethod
    def sanitize_environment(cls, custom_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Builds a strictly curated environment for subprocess execution:
        - Never leaks application secrets (JWT_SECRET, DATABASE_URL, etc.).
        - Only inherits safe system keys from host.
        - Applies SCANNER_EGRESS_PROXY if configured; otherwise strips ambient proxy variables.
        """
        source = custom_env if custom_env is not None else os.environ
        clean: Dict[str, str] = {}
        for k, v in source.items():
            k_upper = str(k).upper()
            if k_upper in cls._SAFE_ENVIRONMENT_KEYS:
                if any(sec in k_upper for sec in ["SECRET", "PASSWORD", "DATABASE", "REDIS", "KEY", "TOKEN", "CREDENTIAL"]):
                    continue
                clean[str(k)] = str(v)

        if custom_env is not None:
            for k, v in custom_env.items():
                k_upper = str(k).upper()
                if not any(sec in k_upper for sec in ["SECRET", "PASSWORD", "DATABASE", "REDIS"]):
                    clean[str(k)] = str(v)

        scanner_proxy = os.environ.get("SCANNER_EGRESS_PROXY", "").strip()
        if scanner_proxy:
            clean["HTTP_PROXY"] = scanner_proxy
            clean["HTTPS_PROXY"] = scanner_proxy
            clean["ALL_PROXY"] = scanner_proxy
            clean["http_proxy"] = scanner_proxy
            clean["https_proxy"] = scanner_proxy
            clean["all_proxy"] = scanner_proxy
        else:
            for p in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy"]:
                clean.pop(p, None)

        return clean

    async def execute(
        self,
        cmd: List[str],
        timeout: float = 60.0,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        max_output_bytes: int = 10 * 1024 * 1024,
        pre_launch_check: Optional[Callable[[], bool]] = None,
        execution_id: Optional[str] = None,
    ) -> ProcessExecutionResult:
        """
        Executes a subprocess with execution tracking, timeout enforcement,
        and guaranteed process tree cleanup on cancellation or timeout.
        """
        if not cmd:
            return ProcessExecutionResult(-1, "", "Empty command provided")
        if max_output_bytes <= 0:
            return ProcessExecutionResult(-1, "", "Invalid maximum output size")

        # R2.3 / Option B: Enterprise external-tool execution must fail closed unless
        # the required egress enforcement facility is configured and verifiably available.
        operating_mode = (os.environ.get("OPERATING_MODE") or os.environ.get("ENVIRONMENT") or "").strip().upper()
        egress_required = operating_mode == "ENTERPRISE" or os.environ.get("ENTERPRISE_EGRESS_ENFORCEMENT_REQUIRED", "").lower() in {"1", "true", "yes"}
        if egress_required:
            verified_facility = os.environ.get("CYBERASSESS_VERIFIED_EGRESS_FACILITY", "").strip()
            if not verified_facility:
                return ProcessExecutionResult(
                    -1,
                    "",
                    "PROCESS_LAUNCH_REJECTED_SECURITY: Enterprise egress network enforcement facility is not configured or verifiably available.",
                )

        creationflags = 0
        start_new_session = False
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            start_new_session = True

        def _bounded_communicate(proc: subprocess.Popen) -> Tuple[str, str, bool]:
            """Drain both pipes concurrently while enforcing a combined byte cap."""
            output_lock = threading.Lock()
            captured = {"stdout": bytearray(), "stderr": bytearray()}
            total_bytes = 0
            limit_reached = threading.Event()

            def _reader(name: str, stream) -> None:
                nonlocal total_bytes
                try:
                    while True:
                        chunk = stream.read(8192)
                        if not chunk:
                            return
                        with output_lock:
                            remaining = max_output_bytes - total_bytes
                            if remaining > 0:
                                kept = chunk[:remaining]
                                captured[name].extend(kept)
                                total_bytes += len(kept)
                            if len(chunk) > max(remaining, 0):
                                limit_reached.set()
                except Exception:
                    limit_reached.set()

            readers = [
                threading.Thread(target=_reader, args=("stdout", proc.stdout), daemon=True),
                threading.Thread(target=_reader, args=("stderr", proc.stderr), daemon=True),
            ]
            for reader in readers:
                reader.start()

            deadline = time.monotonic() + max(timeout, 0.0)
            timed_out = False
            while proc.poll() is None:
                if limit_reached.is_set():
                    self.kill_process_tree(proc.pid)
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    self.kill_process_tree(proc.pid)
                    break
                time.sleep(0.01)

            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            for reader in readers:
                reader.join(timeout=2)

            stdout = bytes(captured["stdout"]).decode("utf-8", errors="replace")
            stderr = bytes(captured["stderr"]).decode("utf-8", errors="replace")
            if limit_reached.is_set():
                stderr = f"Output exceeded maximum of {max_output_bytes} bytes" + (f"\n{stderr}" if stderr else "")
            if timed_out:
                stderr = f"Execution timed out after {timeout} seconds" + (f"\n{stderr}" if stderr else "")
            return stdout, stderr, limit_reached.is_set() or timed_out

        proc_ref: list[Optional[subprocess.Popen]] = [None]

        def _run_sync() -> ProcessExecutionResult:
            nonlocal proc_ref
            proc = None
            try:
                if pre_launch_check is not None and not pre_launch_check():
                    return ProcessExecutionResult(
                        126,
                        "",
                        "PROCESS_LAUNCH_REJECTED_SECURITY: pre-launch security verification failed",
                    )
                clean_env = self.sanitize_environment(env)
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=cwd,
                    env=clean_env,
                    creationflags=creationflags,
                    start_new_session=start_new_session,
                )
                proc_ref[0] = proc
                self._register_execution(proc.pid, execution_id=execution_id)

                stdout, stderr, bounded_failure = _bounded_communicate(proc)
                if "Output exceeded maximum" in stderr:
                    return ProcessExecutionResult(-1, stdout, stderr)
                if bounded_failure and "Execution timed out" in stderr:
                    return ProcessExecutionResult(-1, stdout, stderr)
                return ProcessExecutionResult(proc.returncode, stdout, stderr)
            except FileNotFoundError as e:
                return ProcessExecutionResult(127, "", f"Executable not found: {e}")
            except PermissionError as e:
                return ProcessExecutionResult(126, "", f"Permission denied: {e}")
            except Exception as e:
                if proc and proc.pid:
                    self.kill_process_tree(proc.pid)
                return ProcessExecutionResult(-1, "", str(e))
            finally:
                if proc and proc.pid:
                    self._unregister_execution(proc.pid, execution_id=execution_id)

        try:
            return await asyncio.to_thread(_run_sync)
        except asyncio.CancelledError:
            if proc_ref[0] and proc_ref[0].pid:
                self.kill_process_tree(proc_ref[0].pid)
            raise


process_supervisor = ProcessSupervisor.get_instance()
