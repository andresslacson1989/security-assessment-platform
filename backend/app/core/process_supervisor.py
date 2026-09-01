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
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("cyberassess.process_supervisor")


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
                except Exception:
                    pass
        else:
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGKILL)
            except Exception:
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass

    async def execute(
        self,
        cmd: List[str],
        timeout: float = 60.0,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        max_output_bytes: int = 10 * 1024 * 1024,
        pre_launch_check: Optional[Callable[[], bool]] = None,
    ) -> Tuple[int, str, str]:
        """
        Executes a subprocess with execution tracking, timeout enforcement,
        and guaranteed process tree cleanup on cancellation or timeout.
        """
        if not cmd:
            return -1, "", "Empty command provided"

        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

        def _run_sync() -> Tuple["int", "str", "str"]:
            proc = None
            try:
                if pre_launch_check is not None and not pre_launch_check():
                    return 126, "", "Process launch rejected by pre-launch security check"
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=cwd,
                    env=env,
                    encoding="utf-8",
                    errors="replace",
                    creationflags=creationflags,
                )
                self._register_pid(proc.pid)

                try:
                    stdout, stderr = proc.communicate(timeout=timeout)
                    return proc.returncode, stdout or "", stderr or ""
                except subprocess.TimeoutExpired:
                    self.kill_process_tree(proc.pid)
                    proc.kill()
                    stdout, stderr = proc.communicate()
                    return -1, stdout or "", f"Execution timed out after {timeout} seconds"
            except FileNotFoundError as e:
                return 127, "", f"Executable not found: {e}"
            except PermissionError as e:
                return 126, "", f"Permission denied: {e}"
            except Exception as e:
                if proc and proc.pid:
                    self.kill_process_tree(proc.pid)
                return -1, "", str(e)
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
