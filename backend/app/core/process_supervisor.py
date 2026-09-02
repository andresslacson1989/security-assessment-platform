"""
Contract 03 §3: Central Process Supervisor & Execution Governance.
Tracks, bounds, and recursively terminates subprocess trees on cancellation or timeout.
"""

from __future__ import annotations
import asyncio
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

    @classmethod
    def get_instance(cls) -> ProcessSupervisor:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _register_pid(self, pid: int) -> None:
        self._active_pids.add(pid)

    def _unregister_pid(self, pid: int) -> None:
        self._active_pids.discard(pid)

    @staticmethod
    def kill_process_tree(pid: int) -> None:
        """
        Recursively terminates a process and all its child/grandchild descendants.
        """
        if not pid or pid <= 0:
            return

        if sys.platform == "win32":
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except Exception as e:
                logger.debug(f"Failed to taskkill PID +{pid}: {e}")
                try:
                    os.kill(pid, signal.SIGTERM)
                except Exception as exc:
                    logger.debug("Fallback termination failed for PID=%s: error_type=%s", pid, type(exc).__name__)
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
        """
        Executes a subprocess with execution tracking, timeout enforcement,
        and guaranteed process tree cleanup on cancellation or timeout.
        """
        if not cmd:
            return -1, "", "Empty command provided"
        if max_output_bytes <= 0:
            return -1, "", "Invalid maximum output size"

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

        def _run_sync() -> ProcessExecutionResult:
            proc = None
            try:
                if pre_launch_check is not None and not pre_launch_check():
                    return ProcessExecutionResult(
                        126,
                        "",
                        "PROCESS_LAUNCH_REJECTED_SECURITY: pre-launch security verification failed",
                    )
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=cwd,
                    env=env,
                    creationflags=creationflags,
                    start_new_session=start_new_session,
                )
                self._register_pid(proc.pid)

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
                    self._unregister_pid(proc.pid)

        try:
            return await asyncio.to_thread(_run_sync)
        except asyncio.CancelledError:
            for active_pid in list(self._active_pids):
                self.kill_process_tree(active_pid)
            raise


process_supervisor = ProcessSupervisor.get_instance()
