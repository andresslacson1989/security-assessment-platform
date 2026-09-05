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
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Callable, Dict, Mapping, NamedTuple, Optional, Set, Tuple
from app.core.tool_operation_policy import is_canonical_operation_policy_revision
from app.core.execution_decision import ExecutionDecisionCapability, ExecutionDecisionError

logger = logging.getLogger("cyberassess.process_supervisor")


class ProcessExecutionStatus(str, Enum):
    """Typed outcome for a supervised subprocess invocation."""

    COMPLETED = "COMPLETED"
    SECURITY_REJECTED = "SECURITY_REJECTED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    NOT_FOUND = "NOT_FOUND"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    FAILED = "FAILED"


class ProcessCancellationStatus(str, Enum):
    """Verified result of terminating one execution's process tree."""

    KILLED = "KILLED"
    ALREADY_EXITED = "ALREADY_EXITED"
    NOT_FOUND = "NOT_FOUND"
    FAILED = "FAILED"
    INVALID_REQUEST = "INVALID_REQUEST"


@dataclass(frozen=True)
class ProcessCancellationResult:
    execution_id: str
    status: ProcessCancellationStatus
    pid: Optional[int] = None

    @property
    def confirmed(self) -> bool:
        return self.status in {
            ProcessCancellationStatus.KILLED,
            ProcessCancellationStatus.ALREADY_EXITED,
        }

    def __bool__(self) -> bool:
        return self.confirmed


@dataclass(frozen=True)
class ProcessIdentity:
    """Platform-specific identity captured at process creation."""

    pid: int
    process_group_id: Optional[int]
    start_token: str


def _read_posix_start_token(pid: int) -> Optional[str]:
    if os.name == "nt":
        return None
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as stat_file:
            stat_text = stat_file.read()
        after_comm = stat_text.rsplit(")", 1)[1].split()
        start_ticks = after_comm[19]
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as boot_id_file:
            boot_id = boot_id_file.read().strip()
        return f"posix:{boot_id}:{start_ticks}"
    except (OSError, IndexError):
        return None


def _read_windows_start_token(pid: int) -> Optional[str]:
    if os.name != "nt":
        return None
    class _FileTime(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        created, _exited, _kernel, _user = (_FileTime(), _FileTime(), _FileTime(), _FileTime())
        if not ctypes.windll.kernel32.GetProcessTimes(
            handle, ctypes.byref(created), ctypes.byref(_exited),
            ctypes.byref(_kernel), ctypes.byref(_user),
        ):
            return None
        value = (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)
        return f"windows:{value}"
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


class ProcessExecutionResult(NamedTuple):
    """Three-value-compatible process result with a typed execution status."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def execution_status(self) -> ProcessExecutionStatus:
        if self.stderr.startswith("PROCESS_LAUNCH_REJECTED_SECURITY"):
            return ProcessExecutionStatus.SECURITY_REJECTED
        if self.stderr.startswith("PROCESS_LAUNCH_CANCELLED"):
            return ProcessExecutionStatus.CANCELLED
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


@dataclass(frozen=True)
class CredentialExecutionContext:
    """Exact authorization context expected by one supervised launch."""

    organization_id: str
    asset_id: str
    provider: str
    authorization_decision_id: str
    request_id: str
    operation_policy_revision: str


@dataclass(frozen=True)
class VerifiedEgressProxy:
    """Explicit, expiring egress capability issued by an authoritative verifier."""

    proxy_url: str
    worker_identity: str
    expires_at: datetime
    verified_by: str

    def materialize(self) -> str:
        raise ValueError("authoritative egress verifier is not configured")


@dataclass(frozen=True)
class CredentialEnvironmentHandoff:
    """Typed, tenant-bound credential material for one supervised launch."""

    organization_id: str
    asset_id: str
    provider: str
    authorization_decision_id: str
    request_id: str
    operation_policy_revision: str
    expires_at: datetime
    credentials: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", self.provider.strip().lower())
        object.__setattr__(self, "credentials", MappingProxyType(dict(self.credentials)))

    def materialize(self) -> Dict[str, str]:
        """Validate metadata and return only the centrally approved child keys."""
        approved_keys = {
            "aws": frozenset({
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
            }),
        }.get(self.provider)
        if not self.organization_id or not self.asset_id or not self.provider:
            raise ValueError("credential handoff scope is incomplete")
        if not self.authorization_decision_id:
            raise ValueError("credential handoff authorization decision is missing")
        if not self.request_id or not self.operation_policy_revision:
            raise ValueError("credential handoff execution binding is incomplete")
        if self.expires_at.tzinfo is None or self.expires_at <= datetime.now(timezone.utc):
            raise ValueError("credential handoff is expired")
        if approved_keys is None:
            raise ValueError("credential provider is not approved")
        if set(self.credentials) - approved_keys:
            raise ValueError("credential handoff contains an unapproved key")
        if self.provider == "aws" and not {
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
        }.issubset(self.credentials):
            raise ValueError("credential handoff is missing required AWS credentials")
        values: Dict[str, str] = {}
        for key in approved_keys:
            if key in self.credentials:
                value = self.credentials[key]
                if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
                    raise ValueError("credential handoff contains an invalid value")
                values[key] = value
        # Structural validation is deliberately not authorization.  There is
        # currently no authoritative decision verifier that binds the exact
        # tool/operation, target policy, approval, budget, and worker identity
        # at this boundary.  Never release credentials until that capability
        # exists; fail closed rather than treating caller metadata as proof.
        raise ValueError("authoritative credential release verifier is not configured")


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
        self._execution_groups: dict[str, int] = {}
        self._execution_identities: dict[str, ProcessIdentity] = {}
        self._lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> ProcessSupervisor:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _register_execution(
        self, pid: int, execution_id: Optional[str] = None,
        process_group_id: Optional[str] = None,
        identity: Optional[ProcessIdentity] = None,
    ) -> None:
        with self._lock:
            self._active_pids.add(pid)
            if execution_id:
                self._execution_pids[execution_id] = pid
                if process_group_id and process_group_id.isdigit():
                    self._execution_groups[execution_id] = int(process_group_id)
                if identity is not None:
                    self._execution_identities[execution_id] = identity

    def _unregister_execution(self, pid: int, execution_id: Optional[str] = None) -> None:
        with self._lock:
            self._active_pids.discard(pid)
            if execution_id and self._execution_pids.get(execution_id) == pid:
                self._execution_pids.pop(execution_id, None)
                self._execution_groups.pop(execution_id, None)
                self._execution_identities.pop(execution_id, None)

    def _register_pid(self, pid: int) -> None:
        self._register_execution(pid)

    def _unregister_pid(self, pid: int) -> None:
        self._unregister_execution(pid)

    def cancel_execution(self, execution_id: str) -> ProcessCancellationResult:
        """
        Safely cancels a specific execution by execution_id without affecting sibling executions.
        Returns a typed result.  Durable callers may close an execution only
        when ``confirmed`` is true; NOT_FOUND is not proof of process exit.
        """
        if not execution_id or not isinstance(execution_id, str):
            return ProcessCancellationResult(str(execution_id or ""), ProcessCancellationStatus.INVALID_REQUEST)
        with self._lock:
            pid = self._execution_pids.get(execution_id)
            group_id = self._execution_groups.get(execution_id)
            identity = self._execution_identities.get(execution_id)
        if pid is None:
            return ProcessCancellationResult(execution_id, ProcessCancellationStatus.NOT_FOUND)
        if identity is not None and not self._identity_matches(identity):
            if self._pid_exists(pid) or self._process_group_exists(group_id):
                return ProcessCancellationResult(execution_id, ProcessCancellationStatus.FAILED, pid)
            status = ProcessCancellationStatus.ALREADY_EXITED
            terminated = True
        elif self._pid_exists(pid) or self._process_group_exists(group_id):
            terminated = self.kill_process_tree(pid, process_group_id=group_id, identity=identity)
            status = ProcessCancellationStatus.KILLED if terminated else ProcessCancellationStatus.FAILED
        else:
            status = ProcessCancellationStatus.ALREADY_EXITED
        if status in {ProcessCancellationStatus.KILLED, ProcessCancellationStatus.ALREADY_EXITED}:
            with self._lock:
                if self._execution_pids.get(execution_id) == pid:
                    self._execution_pids.pop(execution_id, None)
                    self._execution_groups.pop(execution_id, None)
                    self._execution_identities.pop(execution_id, None)
                    self._active_pids.discard(pid)
        return ProcessCancellationResult(execution_id, status, pid)

    def cancel_pid(self, pid: int) -> ProcessCancellationResult:
        """
        Cancels a tracked PID with the same verified result contract as
        ``cancel_execution``. New callers should prefer execution identity.
        """
        if not pid or pid <= 0:
            return ProcessCancellationResult(f"pid:{pid}", ProcessCancellationStatus.INVALID_REQUEST, pid)
        with self._lock:
            if pid not in self._active_pids:
                return ProcessCancellationResult(f"pid:{pid}", ProcessCancellationStatus.NOT_FOUND, pid)
            execution_id = next((key for key, value in self._execution_pids.items() if value == pid), f"pid:{pid}")
            group_id = self._execution_groups.get(execution_id)
            identity = self._execution_identities.get(execution_id)
        if identity is not None and not self._identity_matches(identity):
            return ProcessCancellationResult(execution_id, ProcessCancellationStatus.FAILED, pid)
        if self._pid_exists(pid) or self._process_group_exists(group_id):
            terminated = self.kill_process_tree(pid, process_group_id=group_id, identity=identity)
            status = ProcessCancellationStatus.KILLED if terminated else ProcessCancellationStatus.FAILED
        else:
            status = ProcessCancellationStatus.ALREADY_EXITED
        if status in {ProcessCancellationStatus.KILLED, ProcessCancellationStatus.ALREADY_EXITED}:
            with self._lock:
                self._active_pids.discard(pid)
                for key in [k for k, value in self._execution_pids.items() if value == pid]:
                    self._execution_pids.pop(key, None)
                    self._execution_groups.pop(key, None)
                    self._execution_identities.pop(key, None)
        return ProcessCancellationResult(execution_id, status, pid)

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
    def _pid_exists(pid: int) -> bool:
        if not pid or pid <= 0:
            return False
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False

    @staticmethod
    def _posix_descendant_pids(root_pid: int) -> list[int]:
        """Snapshot descendants without trusting an arbitrary caller PID."""
        if os.name == "nt":
            return []
        try:
            result = subprocess.run(
                ["ps", "-e", "-o", "pid=", "-o", "ppid="],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, timeout=1.0, check=False,
            )
            parents: dict[int, list[int]] = {}
            for line in result.stdout.splitlines():
                fields = line.split()
                if len(fields) != 2:
                    continue
                try:
                    child, parent = (int(value) for value in fields)
                except ValueError:
                    continue
                parents.setdefault(parent, []).append(child)
            descendants: list[int] = []
            pending = list(parents.get(root_pid, []))
            while pending:
                child = pending.pop(0)
                if child in descendants or child == root_pid:
                    continue
                descendants.append(child)
                pending.extend(parents.get(child, []))
            return descendants
        except (OSError, subprocess.SubprocessError):
            return []

    @staticmethod
    def _process_group_exists(pgid: Optional[int]) -> bool:
        if os.name == "nt" or not pgid or pgid <= 1:
            return False
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False

    @staticmethod
    def _capture_process_identity(pid: int, process_group_id: Optional[int]) -> Optional[ProcessIdentity]:
        start_token = _read_posix_start_token(pid)
        if start_token is None:
            if os.name == "nt":
                start_token = _read_windows_start_token(pid)
                if start_token is None:
                    return None
            else:
                return None
        return ProcessIdentity(pid, process_group_id, start_token)

    @staticmethod
    def _identity_matches(identity: ProcessIdentity) -> bool:
        if not ProcessSupervisor._pid_exists(identity.pid):
            return False
        current = ProcessSupervisor._capture_process_identity(identity.pid, identity.process_group_id)
        if current is None or current.start_token != identity.start_token:
            return False
        if identity.process_group_id is not None:
            try:
                return os.getpgid(identity.pid) == identity.process_group_id if os.name != "nt" else True
            except OSError:
                return False
        return True

    @staticmethod
    def kill_process_tree(
        pid: int,
        process_group_id: Optional[int] = None,
        identity: Optional[ProcessIdentity] = None,
    ) -> bool:
        """
        Recursively terminates a process and all its child/grandchild descendants.
        Guarantees isolation: never signals the host, server process, or sibling processes.
        """
        if not pid or pid <= 0:
            return False

        current_pid = os.getpid()
        parent_pid = os.getppid() if hasattr(os, "getppid") else None
        if pid == current_pid or (parent_pid is not None and pid == parent_pid) or pid <= 1:
            logger.error("Security invariant: Refusing to terminate current/parent PID=%s", pid)
            return False
        if identity is not None and identity.pid != pid:
            return False
        if identity is not None and ProcessSupervisor._identity_matches(identity):
            pass
        elif identity is not None and (
            ProcessSupervisor._pid_exists(pid) or ProcessSupervisor._process_group_exists(process_group_id)
        ):
            logger.error("Refusing to terminate process with mismatched launch identity PID=%s", pid)
            return False

        descendants: list[int] = []
        group_id: Optional[int] = process_group_id
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
            descendants = ProcessSupervisor._posix_descendant_pids(pid)
            try:
                # POSIX process isolation:
                # Only signal a process group if the process is its own group leader (pgid == pid),
                # which was spawned with start_new_session=True, AND pgid != current process group!
                current_pgrp = os.getpgrp()
                if group_id and group_id != current_pgrp:
                    os.killpg(group_id, signal.SIGKILL)
                else:
                    pgid = os.getpgid(pid)
                    group_id = pgid if pgid > 1 and pgid == pid and pgid != current_pgrp else None
                    if group_id:
                        os.killpg(group_id, signal.SIGKILL)
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
        tracked_pids = [pid, *descendants]
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if not any(ProcessSupervisor._pid_exists(member) for member in tracked_pids) and not ProcessSupervisor._process_group_exists(group_id):
                return True
            time.sleep(0.02)
        return (
            not any(ProcessSupervisor._pid_exists(member) for member in tracked_pids)
            and not ProcessSupervisor._process_group_exists(group_id)
        )

    # Complete reviewed baseline inherited from the worker process. Credentials,
    # proxy configuration, loader hooks, interpreter/module injection,
    # package-manager configuration, and tokens are intentionally excluded.
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
        "COMSPEC",
    })

    # Exact operation-specific names allowed from a caller. Values must still
    # be derived from server-controlled paths or policy.
    _APPROVED_OPERATION_ENVIRONMENT_KEYS = frozenset({
        "CGO_ENABLED",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_TERMINAL_PROMPT",
        "GOARCH",
        "GOCACHE",
        "GOOS",
        "GOMODCACHE",
        "GOTOOLCHAIN",
        "NMAPDIR",
        "NPM_CONFIG_AUDIT",
        "NPM_CONFIG_FUND",
        "NPM_CONFIG_IGNORE_SCRIPTS",
        "NPM_CONFIG_REGISTRY",
        "NPM_CONFIG_STRICT_SSL",
        "NPM_CONFIG_UPDATE_NOTIFIER",
        "NPM_CONFIG_USERCONFIG",
    })

    _AMBIENT_PROXY_KEYS = frozenset({
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    })

    @classmethod
    def sanitize_environment(
        cls,
        custom_env: Optional[Dict[str, str]] = None,
        *,
        scanner_egress_proxy: Optional[VerifiedEgressProxy] = None,
    ) -> Dict[str, str]:
        """
        Build the only environment that may reach a supervised child.

        The worker baseline is deny-by-default: only exact reviewed baseline
        names are inherited. Caller input can add only exact reviewed operation
        names; it is never merged wholesale. Ambient proxy variables are always
        removed. SCANNER_EGRESS_PROXY is translated only when configured by the
        server policy. Baseline keys cannot be overridden by caller input.
        """
        clean: Dict[str, str] = {}
        for key in cls._SAFE_ENVIRONMENT_KEYS:
            value = os.environ.get(key)
            if value is not None:
                clean[key] = str(value)

        if custom_env:
            for key, value in custom_env.items():
                normalized_key = str(key).upper()
                if normalized_key in cls._APPROVED_OPERATION_ENVIRONMENT_KEYS:
                    clean[normalized_key] = cls._validate_operation_environment_value(normalized_key, value)

        scanner_proxy = scanner_egress_proxy.materialize() if scanner_egress_proxy else ""
        if scanner_proxy:
            clean["HTTP_PROXY"] = scanner_proxy
            clean["HTTPS_PROXY"] = scanner_proxy
            clean["ALL_PROXY"] = scanner_proxy
            clean["http_proxy"] = scanner_proxy
            clean["https_proxy"] = scanner_proxy
            clean["all_proxy"] = scanner_proxy
        for proxy_key in cls._AMBIENT_PROXY_KEYS:
            if not scanner_proxy or proxy_key in {"NO_PROXY", "no_proxy"}:
                clean.pop(proxy_key, None)

        return clean

    @staticmethod
    def _validate_operation_environment_value(key: str, value: object) -> str:
        """Validate both the name and the value of operation-scoped env input."""
        if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
            raise ValueError(f"invalid value for approved environment key {key}")
        if key in {"NMAPDIR", "GOCACHE", "NPM_CONFIG_USERCONFIG"}:
            if not os.path.isabs(value) or ".." in os.path.normpath(value).split(os.sep):
                raise ValueError(f"non-canonical path for approved environment key {key}")
        elif key in {"GIT_CONFIG_NOSYSTEM", "GIT_TERMINAL_PROMPT"} and value not in {"0", "1"}:
            raise ValueError(f"invalid boolean value for approved environment key {key}")
        elif key == "NPM_CONFIG_IGNORE_SCRIPTS" and value.lower() not in {"true", "false"}:
            raise ValueError(f"invalid boolean value for approved environment key {key}")
        elif key == "GOTOOLCHAIN" and value not in {"auto", "local"}:
            raise ValueError(f"invalid toolchain value for approved environment key {key}")
        return value

    async def execute(
        self,
        cmd: List[str],
        timeout: float = 60.0,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        max_output_bytes: int = 10 * 1024 * 1024,
        pre_launch_check: Optional[Callable[[], bool]] = None,
        execution_id: Optional[str] = None,
        scanner_egress_proxy: Optional[VerifiedEgressProxy] = None,
        credential_handoff: Optional[CredentialEnvironmentHandoff] = None,
        credential_context: Optional[CredentialExecutionContext] = None,
        execution_capability: Optional[ExecutionDecisionCapability] = None,
        operation_family: str = "",
        operation_options: Optional[Dict[str, object]] = None,
        tool_id: str = "",
    ) -> ProcessExecutionResult:
        """
        Executes a subprocess with execution tracking, timeout enforcement,
        and guaranteed process tree cleanup on cancellation or timeout.
        """
        if not cmd:
            return ProcessExecutionResult(-1, "", "Empty command provided")
        if max_output_bytes <= 0:
            return ProcessExecutionResult(-1, "", "Invalid maximum output size")

        # R3.2: Enterprise external-tool execution fails closed unconditionally when
        # enterprise egress enforcement is required until an authoritative network verifier interface exists.
        operating_mode = (os.environ.get("OPERATING_MODE") or os.environ.get("ENVIRONMENT") or "").strip().upper()
        egress_required = operating_mode == "ENTERPRISE" or os.environ.get("ENTERPRISE_EGRESS_ENFORCEMENT_REQUIRED", "").lower() in {"1", "true", "yes"}
        if egress_required:
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

        def _bounded_communicate(
            proc: subprocess.Popen,
            renew_lease: Optional[Callable[[], bool]] = None,
            process_identity: Optional[ProcessIdentity] = None,
            process_group_id: Optional[int] = None,
        ) -> Tuple[str, str, bool, bool]:
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
            next_lease_renewal = time.monotonic() + 10.0
            lease_lost = False
            timed_out = False
            termination_confirmed = True
            while proc.poll() is None:
                if limit_reached.is_set():
                    termination_confirmed = self.kill_process_tree(proc.pid, process_group_id=process_group_id, identity=process_identity)
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    termination_confirmed = self.kill_process_tree(proc.pid, process_group_id=process_group_id, identity=process_identity)
                    break
                if renew_lease is not None and time.monotonic() >= next_lease_renewal:
                    if not renew_lease():
                        lease_lost = True
                        termination_confirmed = self.kill_process_tree(proc.pid, process_group_id=process_group_id, identity=process_identity)
                        break
                    next_lease_renewal = time.monotonic() + 10.0
                time.sleep(0.01)

            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                # Do not bypass identity-bound tree termination with proc.kill().
                # A failed confirmation must remain observable to the caller.
                termination_confirmed = self.kill_process_tree(
                    proc.pid,
                    process_group_id=process_group_id,
                    identity=process_identity,
                ) and termination_confirmed
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    termination_confirmed = False
            for reader in readers:
                reader.join(timeout=2)

            stdout = bytes(captured["stdout"]).decode("utf-8", errors="replace")
            stderr = bytes(captured["stderr"]).decode("utf-8", errors="replace")
            if limit_reached.is_set():
                stderr = f"Output exceeded maximum of {max_output_bytes} bytes" + (f"\n{stderr}" if stderr else "")
            if timed_out:
                stderr = f"Execution timed out after {timeout} seconds" + (f"\n{stderr}" if stderr else "")
            if lease_lost:
                stderr = "Execution lease renewal failed" + (f"\n{stderr}" if stderr else "")
            return stdout, stderr, limit_reached.is_set() or timed_out or lease_lost, termination_confirmed

        proc_ref: list[Optional[subprocess.Popen]] = [None]
        process_identity_ref: list[Optional[ProcessIdentity]] = [None]
        process_group_ref: list[Optional[int]] = [None]
        cancellation_requested = threading.Event()

        def _run_sync() -> ProcessExecutionResult:
            nonlocal proc_ref
            proc = None
            launch_committed = False

            def _finish_durable(terminal_state: str, reason_code: Optional[str] = None) -> Optional[ProcessExecutionResult]:
                if execution_capability is None:
                    return None
                if execution_id != execution_capability.execution_id:
                    return ProcessExecutionResult(-1, "", "PROCESS_FINALIZATION_REJECTED_SECURITY: execution identity mismatch")
                if not execution_capability.finish(
                    terminal_state=terminal_state, reason_code=reason_code,
                    process_id=proc.pid if proc else None,
                    process_group_id=str(proc.pid) if proc and start_new_session else None,
                ):
                    return ProcessExecutionResult(-1, "", "PROCESS_FINALIZATION_FAILED: durable terminal state was not committed")
                return None

            try:
                if pre_launch_check is not None and not pre_launch_check():
                    return ProcessExecutionResult(
                        126,
                        "",
                        "PROCESS_LAUNCH_REJECTED_SECURITY: pre-launch security verification failed",
                    )
                try:
                    if execution_capability is not None and type(execution_capability) is not ExecutionDecisionCapability:
                        raise TypeError("execution capability type is not approved")
                    if credential_handoff is not None and execution_capability is None:
                        raise ExecutionDecisionError("credential release requires an execution decision capability")
                    if execution_capability is not None:
                        execution_capability.revalidate_and_claim(
                            tool_id=tool_id,
                            operation_family=operation_family,
                            operation_options=operation_options or {},
                            command=cmd,
                            worker_identity=os.environ.get("CYBERASSESS_WORKER_IDENTITY", "").strip(),
                            timeout=timeout,
                            max_output_bytes=max_output_bytes,
                        )
                        if not execution_id or execution_id != execution_capability.execution_id:
                            execution_capability.abort_start(terminal_state="EXECUTION_BLOCKED", reason_code="EXECUTION_IDENTITY_MISMATCH")
                            return ProcessExecutionResult(126, "", "PROCESS_LAUNCH_REJECTED_SECURITY: execution identity mismatch")
                        if cancellation_requested.is_set():
                            execution_capability.abort_start(terminal_state="CANCELLED", reason_code="EXECUTION_CANCELLED_BEFORE_PROCESS_CREATION")
                            return ProcessExecutionResult(130, "", "PROCESS_LAUNCH_CANCELLED: cancellation was requested before process creation")
                    if scanner_egress_proxy is not None and type(scanner_egress_proxy) is not VerifiedEgressProxy:
                        raise TypeError("scanner egress capability type is not approved")
                    if credential_handoff is not None and type(credential_handoff) is not CredentialEnvironmentHandoff:
                        raise TypeError("credential handoff type is not approved")
                    if credential_context is not None and type(credential_context) is not CredentialExecutionContext:
                        raise TypeError("credential execution context type is not approved")
                    clean_env = self.sanitize_environment(
                        env,
                        scanner_egress_proxy=scanner_egress_proxy,
                    )
                    if credential_handoff is not None:
                        if credential_context is None or any(
                            getattr(credential_handoff, field) != getattr(credential_context, field)
                            for field in (
                                "organization_id",
                                "asset_id",
                                "provider",
                                "authorization_decision_id",
                                "request_id",
                                "operation_policy_revision",
                            )
                        ):
                            raise ValueError("credential handoff context mismatch")
                        if not is_canonical_operation_policy_revision(credential_context.operation_policy_revision):
                            raise ValueError("operation policy revision is not canonical")
                        clean_env.update(credential_handoff.materialize())
                except (AttributeError, TypeError, ValueError) as exc:
                    if execution_capability is not None:
                        execution_capability.abort_start(terminal_state="EXECUTION_BLOCKED", reason_code="PROCESS_LAUNCH_REJECTED_SECURITY")
                    return ProcessExecutionResult(
                        126,
                        "",
                        f"PROCESS_LAUNCH_REJECTED_SECURITY: invalid launch capability ({type(exc).__name__})",
                    )
                if cancellation_requested.is_set():
                    if execution_capability is not None:
                        execution_capability.abort_start(terminal_state="CANCELLED", reason_code="EXECUTION_CANCELLED_BEFORE_PROCESS_CREATION")
                    return ProcessExecutionResult(130, "", "PROCESS_LAUNCH_CANCELLED: cancellation was requested before process creation")
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
                process_group_id = proc.pid if start_new_session else None
                process_identity = self._capture_process_identity(proc.pid, process_group_id)
                process_identity_ref[0] = process_identity
                process_group_ref[0] = process_group_id
                if process_identity is None:
                    terminated = self.kill_process_tree(proc.pid)
                    if not terminated:
                        return ProcessExecutionResult(
                            -1, "",
                            "PROCESS_TERMINATION_UNCONFIRMED: process identity unavailable and process tree remains active",
                        )
                    if execution_capability is not None and terminated:
                        execution_capability.abort_start(
                            terminal_state="EXECUTION_BLOCKED",
                            reason_code="PROCESS_LAUNCH_REJECTED_SECURITY",
                            process_id=proc.pid,
                            process_group_id=str(process_group_id) if process_group_id else None,
                        )
                    return ProcessExecutionResult(
                        126, "", "PROCESS_LAUNCH_REJECTED_SECURITY: process identity unavailable",
                    )
                if execution_capability is not None:
                    execution_capability.mark_started(
                        process_id=proc.pid,
                        process_group_id=str(process_group_id) if process_group_id else None,
                    )
                    launch_committed = True
                self._register_execution(
                    proc.pid,
                    execution_id=execution_id,
                    process_group_id=str(process_group_id) if process_group_id else None,
                    identity=process_identity,
                )

                stdout, stderr, bounded_failure, termination_confirmed = _bounded_communicate(
                    proc,
                    renew_lease=(execution_capability.renew if execution_capability is not None else None),
                    process_identity=process_identity,
                    process_group_id=process_group_id,
                )
                if bounded_failure and not termination_confirmed:
                    return ProcessExecutionResult(
                        -1, stdout,
                        "PROCESS_TERMINATION_UNCONFIRMED: process tree remains active\n" + stderr,
                    )
                if "Output exceeded maximum" in stderr:
                    finalization = _finish_durable("PARTIAL_RESULTS_WITH_WARNING", "OUTPUT_LIMIT_EXCEEDED")
                    if finalization:
                        return finalization
                    return ProcessExecutionResult(-1, stdout, stderr)
                if bounded_failure and "Execution timed out" in stderr:
                    finalization = _finish_durable("TIMED_OUT", "EXECUTION_TIMEOUT")
                    if finalization:
                        return finalization
                    return ProcessExecutionResult(-1, stdout, stderr)
                if bounded_failure and "Execution lease renewal failed" in stderr:
                    finalization = _finish_durable("FAILED", "EXECUTION_LEASE_RENEWAL_FAILED")
                    if finalization:
                        return finalization
                    return ProcessExecutionResult(-1, stdout, stderr)
                finalization = _finish_durable(
                    "SUCCEEDED" if proc.returncode == 0 else "FAILED",
                    None if proc.returncode == 0 else "PROCESS_EXIT_NONZERO",
                )
                if finalization:
                    return finalization
                return ProcessExecutionResult(proc.returncode, stdout, stderr)
            except FileNotFoundError as e:
                if execution_capability is not None:
                    execution_capability.abort_start(terminal_state="FAILED", reason_code="EXECUTABLE_NOT_FOUND")
                return ProcessExecutionResult(127, "", f"Executable not found: {e}")
            except PermissionError as e:
                if execution_capability is not None:
                    execution_capability.abort_start(terminal_state="EXECUTION_BLOCKED", reason_code="EXECUTABLE_PERMISSION_DENIED")
                return ProcessExecutionResult(126, "", f"Permission denied: {e}")
            except Exception as e:
                termination_confirmed = True
                if proc and proc.pid:
                    termination_confirmed = self.kill_process_tree(
                        proc.pid,
                        process_group_id=process_group_ref[0],
                        identity=process_identity_ref[0],
                    )
                if execution_capability is not None:
                    if launch_committed:
                        if not termination_confirmed:
                            return ProcessExecutionResult(-1, "", "PROCESS_TERMINATION_UNCONFIRMED: process tree remains active")
                        if not execution_capability.finish(terminal_state="FAILED", reason_code="PROCESS_EXECUTION_EXCEPTION", process_id=proc.pid if proc else None, process_group_id=str(proc.pid) if proc and start_new_session else None):
                            return ProcessExecutionResult(-1, "", "PROCESS_FINALIZATION_FAILED: durable exception outcome was not committed")
                    else:
                        if not execution_capability.abort_start(terminal_state="FAILED", reason_code="PROCESS_EXECUTION_EXCEPTION"):
                            return ProcessExecutionResult(-1, "", "PROCESS_FINALIZATION_FAILED: durable launch failure was not committed")
                return ProcessExecutionResult(-1, "", str(e))
            finally:
                if proc and proc.pid:
                    self._unregister_execution(proc.pid, execution_id=execution_id)

        try:
            return await asyncio.to_thread(_run_sync)
        except asyncio.CancelledError:
            cancellation_requested.set()
            if proc_ref[0] and proc_ref[0].pid:
                termination_confirmed = self.kill_process_tree(
                    proc_ref[0].pid,
                    process_group_id=process_group_ref[0],
                    identity=process_identity_ref[0],
                )
                if not termination_confirmed:
                    raise RuntimeError("PROCESS_TERMINATION_UNCONFIRMED: process tree remains active")
                if execution_capability is not None:
                    if not execution_capability.finish(
                        terminal_state="CANCELLED", reason_code="EXECUTION_CANCELLED",
                        process_id=proc_ref[0].pid,
                        process_group_id=str(process_group_ref[0]) if process_group_ref[0] else None,
                    ):
                        raise RuntimeError("PROCESS_FINALIZATION_FAILED: durable cancellation outcome was not committed")
            elif execution_capability is not None:
                execution_capability.abort_start(terminal_state="CANCELLED", reason_code="EXECUTION_CANCELLED_BEFORE_PROCESS_CREATION")
            raise


process_supervisor = ProcessSupervisor.get_instance()
