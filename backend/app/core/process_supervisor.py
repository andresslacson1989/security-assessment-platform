"""
Contract 03 §3: Central Process Supervisor & Execution Governance.
Tracks, bounds, and recursively terminates subprocess trees on cancellation or timeout.
"""

from __future__ import annotations
import asyncio
import contextvars
import ctypes
from contextlib import contextmanager
from ctypes import wintypes
import logging
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from enum import Enum
from typing import Callable, Dict, Iterator, List, NamedTuple, Optional, Set, Tuple

logger = logging.getLogger("cyberassess.process_supervisor")

# Propagates through asyncio task creation and asyncio.to_thread. Queue-owned
# scans set this to scan_id so every external child launched by that scan shares
# one lifecycle boundary without sharing it with another scan/tenant.
_CURRENT_EXECUTION_CONTEXT: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "cyberassess_process_execution_context",
    default=None,
)


@contextmanager
def process_execution_context(context_id: str) -> Iterator[None]:
    """Bind supervised subprocesses created in this context to one owner."""
    normalized = str(context_id or "").strip()
    if not normalized:
        raise ValueError("Process execution context ID must be non-empty.")
    token = _CURRENT_EXECUTION_CONTEXT.set(normalized)
    try:
        yield
    finally:
        _CURRENT_EXECUTION_CONTEXT.reset(token)


def current_execution_context_id() -> Optional[str]:
    return _CURRENT_EXECUTION_CONTEXT.get()


class ProcessExecutionStatus(str, Enum):
    COMPLETED = "COMPLETED"
    SECURITY_REJECTED = "SECURITY_REJECTED"
    TIMED_OUT = "TIMED_OUT"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    NOT_FOUND = "NOT_FOUND"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    FAILED = "FAILED"


class ProcessExecutionResult(NamedTuple):
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
    """Central, owner-scoped external process supervisor."""

    _instance: Optional["ProcessSupervisor"] = None

    def __init__(self):
        self._active_pids_by_context: Dict[str, Set[int]] = {}
        self._pid_context: Dict[int, str] = {}
        self._registry_lock = threading.RLock()

    @classmethod
    def get_instance(cls) -> "ProcessSupervisor":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def active_pids(self) -> Set[int]:
        """Return a snapshot for diagnostics/tests; callers cannot mutate state."""
        with self._registry_lock:
            return set(self._pid_context)

    def active_pids_for_context(self, context_id: str) -> Set[int]:
        with self._registry_lock:
            return set(self._active_pids_by_context.get(context_id, set()))

    def _register_pid(self, pid: int, context_id: str) -> None:
        with self._registry_lock:
            self._pid_context[pid] = context_id
            self._active_pids_by_context.setdefault(context_id, set()).add(pid)

    def _unregister_pid(self, pid: int) -> None:
        with self._registry_lock:
            context_id = self._pid_context.pop(pid, None)
            if context_id is None:
                return
            pids = self._active_pids_by_context.get(context_id)
            if pids is not None:
                pids.discard(pid)
                if not pids:
                    self._active_pids_by_context.pop(context_id, None)

    def kill_context(self, context_id: str) -> None:
        """Terminate only process trees owned by one execution context."""
        with self._registry_lock:
            pids = list(self._active_pids_by_context.get(context_id, set()))
        for pid in pids:
            self.kill_process_tree(pid)

    def kill_all_processes(self) -> None:
        """Explicit service-shutdown primitive; never used for single-scan cancel."""
        with self._registry_lock:
            pids = list(self._pid_context)
        for pid in pids:
            self.kill_process_tree(pid)

    @staticmethod
    def _windows_descendant_pids(root_pid: int) -> list[int]:
        if sys.platform != "win32":
            return []

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
                descendants.append(child)
                pending.extend(parent_map.get(child, []))
            return descendants
        finally:
            ctypes.windll.kernel32.CloseHandle(snapshot)

    @staticmethod
    def _windows_terminate_pid(pid: int) -> None:
        process = ctypes.windll.kernel32.OpenProcess(0x0001 | 0x1000, False, pid)
        if process:
            try:
                ctypes.windll.kernel32.TerminateProcess(process, 1)
            finally:
                ctypes.windll.kernel32.CloseHandle(process)

    @staticmethod
    def kill_process_tree(pid: int) -> None:
        if not pid or pid <= 0:
            return
        if sys.platform == "win32":
            try:
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
            except Exception as exc:
                logger.debug("Windows process-tree termination failed for PID=%s: error_type=%s", pid, type(exc).__name__)
                try:
                    os.kill(pid, signal.SIGTERM)
                except Exception as fallback_exc:
                    logger.debug("Fallback termination failed for PID=%s: error_type=%s", pid, type(fallback_exc).__name__)
        else:
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGKILL)
            except Exception as exc:
                logger.debug("Process-group termination failed for PID=%s: error_type=%s", pid, type(exc).__name__)
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception as fallback_exc:
                    logger.debug("Fallback process termination failed for PID=%s: error_type=%s", pid, type(fallback_exc).__name__)

    async def execute(
        self,
        cmd: List[str],
        timeout: float = 60.0,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        max_output_bytes: int = 10 * 1024 * 1024,
        pre_launch_check: Optional[Callable[[], bool]] = None,
    ) -> ProcessExecutionResult:
        if not cmd:
            return ProcessExecutionResult(-1, "", "Empty command provided")
        if max_output_bytes <= 0:
            return ProcessExecutionResult(-1, "", "Invalid maximum output size")

        # Unscoped direct adapter use receives a unique invocation context, so
        # cancellation of one call can never terminate another unrelated call.
        context_id = current_execution_context_id() or f"invocation-{uuid.uuid4().hex}"
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        start_new_session = sys.platform != "win32"

        def _bounded_communicate(proc: subprocess.Popen) -> Tuple[str, str, bool]:
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

        def _run_sync() -> ProcessExecutionResult:
            proc = None
            try:
                if pre_launch_check is not None and not pre_launch_check():
                    return ProcessExecutionResult(126, "", "PROCESS_LAUNCH_REJECTED_SECURITY: pre-launch security verification failed")
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=cwd,
                    env=env,
                    creationflags=creationflags,
                    start_new_session=start_new_session,
                )
                self._register_pid(proc.pid, context_id)
                stdout, stderr, bounded_failure = _bounded_communicate(proc)
                if "Output exceeded maximum" in stderr:
                    return ProcessExecutionResult(-1, stdout, stderr)
                if bounded_failure and "Execution timed out" in stderr:
                    return ProcessExecutionResult(-1, stdout, stderr)
                return ProcessExecutionResult(proc.returncode, stdout, stderr)
            except FileNotFoundError as exc:
                return ProcessExecutionResult(127, "", f"Executable not found: {exc}")
            except PermissionError as exc:
                return ProcessExecutionResult(126, "", f"Permission denied: {exc}")
            except Exception as exc:
                if proc and proc.pid:
                    self.kill_process_tree(proc.pid)
                return ProcessExecutionResult(-1, "", str(exc))
            finally:
                if proc and proc.pid:
                    self._unregister_pid(proc.pid)

        try:
            return await asyncio.to_thread(_run_sync)
        except asyncio.CancelledError:
            # Critical isolation invariant: never terminate another scan's PIDs.
            self.kill_context(context_id)
            raise


process_supervisor = ProcessSupervisor.get_instance()
