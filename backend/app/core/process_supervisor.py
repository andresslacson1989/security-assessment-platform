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
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from types import MappingProxyType
from typing import Callable, Dict, List, Mapping, NamedTuple, Optional, Set, Tuple
from app.core.tool_operation_policy import is_canonical_operation_policy_revision
from app.core.execution_decision import ExecutionDecisionCapability, ExecutionDecisionError
from app.core.execution_context import GovernedExecutionContext, NonScanExecutionContext

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
    LAUNCH_UNCERTAIN = "LAUNCH_UNCERTAIN"
    FAILED = "FAILED"


class ProcessCancellationStatus(str, Enum):
    """Verified result of terminating one execution's process tree."""

    KILLED = "KILLED"
    ALREADY_EXITED = "ALREADY_EXITED"
    NOT_FOUND = "NOT_FOUND"
    FAILED = "FAILED"
    RECOVERY_BLOCKED = "RECOVERY_BLOCKED"
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
class ProcessMemberIdentity:
    """Kernel identity for one live member of a governed POSIX session."""

    pid: int
    process_group_id: int
    session_id: int
    start_token: str


@dataclass(frozen=True)
class ProcessIdentity:
    """Platform-specific identity captured at process creation."""

    pid: int
    process_group_id: Optional[int]
    start_token: str
    session_id: Optional[int] = None
    # A complete bounded snapshot is required for recovery after the root has
    # exited.  Empty snapshots retain compatibility with older in-memory
    # callers but cannot authorize post-root recovery.
    member_snapshot: Tuple[ProcessMemberIdentity, ...] = ()
    windows_attestation: Optional[str] = None


def _windows_identity_attestation(identity: ProcessIdentity, execution_id=None):
    from app.core.execution_context import (
        WindowsJobAttestation,
        parse_windows_attestation_json,
    )
    if type(identity) is not ProcessIdentity or not identity.windows_attestation:
        raise ValueError("Windows governed identity is missing")
    attestation = parse_windows_attestation_json(identity.windows_attestation)
    if (
        identity.pid != attestation.root_process_id
        or identity.start_token != attestation.root_process_start_token
        or identity.process_group_id is not None or identity.session_id is not None
        or identity.member_snapshot
    ):
        raise ValueError("Windows governed identity mismatch")
    if type(attestation) is WindowsJobAttestation:
        if execution_id is not None and execution_id != attestation.execution_id:
            raise ValueError("Windows governed execution identity mismatch")
    elif execution_id is not None:
        raise ValueError("non-scan Windows identity cannot satisfy a scan execution request")
    return attestation


def _read_posix_start_token(pid: int) -> Optional[str]:
    if os.name == "nt":
        return None
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as stat_file:
            stat_text = stat_file.read()
        after_comm = stat_text.rsplit(")", 1)[1].split()
        # A child can exit and remain as a zombie while the launch worker is
        # still completing its bounded identity handshake.  A zombie cannot
        # execute, and its start token must not keep it in the live-member
        # identity set or prevent the post-root-exit proof from completing.
        if not after_comm or after_comm[0] in {"Z", "X"}:
            return None
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
        if self.stderr.startswith("PROCESS_LAUNCH_UNCERTAIN"):
            return ProcessExecutionStatus.LAUNCH_UNCERTAIN
        if self.stderr.startswith("PROCESS_LAUNCH_REJECTED_SECURITY"):
            return ProcessExecutionStatus.SECURITY_REJECTED
        if self.stderr.startswith("PROCESS_TERMINATION_UNCONFIRMED"):
            return ProcessExecutionStatus.LAUNCH_UNCERTAIN
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

    # Process discovery is intentionally bounded.  This handshake window is
    # long enough for a governed tool to create its normal startup children,
    # while a process that never reaches a stable complete snapshot remains
    # launch-uncertain instead of being recorded with an incomplete identity.
    _LAUNCH_HANDSHAKE_MAX_SECONDS = 1.0
    _LAUNCH_HANDSHAKE_STABLE_SECONDS = 0.10
    _LAUNCH_HANDSHAKE_POLL_SECONDS = 0.01

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

    def cancel_execution(
        self,
        execution_id: str,
        *,
        process_identity: Optional[ProcessIdentity] = None,
    ) -> ProcessCancellationResult:
        """
        Safely cancels a specific execution by execution_id without affecting sibling executions.
        Returns a typed result.  Durable callers may close an execution only
        when ``confirmed`` is true; NOT_FOUND is not proof of process exit.

        ``process_identity`` is the restart-safe durable handoff.  When it is
        supplied, it must agree with any in-memory mapping; if the mapping was
        lost during a worker restart, the durable identity becomes the only
        permitted process target.  A raw PID is never accepted as a substitute.
        """
        if not execution_id or not isinstance(execution_id, str):
            return ProcessCancellationResult(str(execution_id or ""), ProcessCancellationStatus.INVALID_REQUEST)
        if os.name == "nt":
            with self._lock:
                mapped = self._execution_identities.get(execution_id)
                mapped_pid = self._execution_pids.get(execution_id)
            if process_identity is None and mapped is None and mapped_pid is None:
                return ProcessCancellationResult(execution_id, ProcessCancellationStatus.NOT_FOUND)
            identity = process_identity if process_identity is not None else mapped
            try:
                if mapped is not None and mapped != identity:
                    raise ValueError("Windows registry identity mismatch")
                attestation = _windows_identity_attestation(identity, execution_id)
                from app.core.windows_job import attested_job
                job = attested_job(attestation, for_recovery=True)
                had_members = bool(job.members())
                if had_members and not job.terminate():
                    raise OSError("Windows job termination unconfirmed")
                status = ProcessCancellationStatus.KILLED if had_members else ProcessCancellationStatus.ALREADY_EXITED
                if status in {ProcessCancellationStatus.KILLED, ProcessCancellationStatus.ALREADY_EXITED}:
                    with self._lock:
                        if self._execution_identities.get(execution_id) == identity:
                            self._execution_pids.pop(execution_id, None)
                            self._execution_groups.pop(execution_id, None)
                            self._execution_identities.pop(execution_id, None)
                            self._active_pids.discard(identity.pid)
                    try:
                        from app.core.windows_job import release_attestation
                        release_attestation(attestation.digest)
                    except OSError:
                        logger.warning(
                            "Windows job handle cleanup failed after confirmed cancellation: execution_id=%s",
                            execution_id,
                        )
                return ProcessCancellationResult(execution_id, status, identity.pid)
            except (OSError, ValueError, TypeError):
                return ProcessCancellationResult(execution_id, ProcessCancellationStatus.RECOVERY_BLOCKED)
        if process_identity is not None and (
            type(process_identity) is not ProcessIdentity
            or process_identity.pid <= 1
            or process_identity.process_group_id is None
            or process_identity.process_group_id <= 1
            or not isinstance(process_identity.start_token, str)
            or not process_identity.start_token.strip()
            or process_identity.session_id is None
            or process_identity.session_id < 0
        ):
            return ProcessCancellationResult(execution_id, ProcessCancellationStatus.INVALID_REQUEST)
        with self._lock:
            mapped_pid = self._execution_pids.get(execution_id)
            mapped_group_id = self._execution_groups.get(execution_id)
            mapped_identity = self._execution_identities.get(execution_id)
        if process_identity is not None:
            if mapped_pid is not None and mapped_pid != process_identity.pid:
                return ProcessCancellationResult(execution_id, ProcessCancellationStatus.RECOVERY_BLOCKED, mapped_pid)
            if mapped_group_id is not None and mapped_group_id != process_identity.process_group_id:
                return ProcessCancellationResult(execution_id, ProcessCancellationStatus.RECOVERY_BLOCKED, process_identity.pid)
            if mapped_identity is not None and mapped_identity != process_identity:
                return ProcessCancellationResult(execution_id, ProcessCancellationStatus.RECOVERY_BLOCKED, process_identity.pid)
            pid = process_identity.pid
            group_id = process_identity.process_group_id
            identity = process_identity
        else:
            pid = mapped_pid
            group_id = mapped_group_id
            identity = mapped_identity
        if pid is None:
            return ProcessCancellationResult(execution_id, ProcessCancellationStatus.NOT_FOUND)
        root_exists = self._pid_exists(pid)
        group_exists = self._process_group_exists(group_id)
        session_exists = identity is not None and self._process_session_exists(identity.session_id)
        if identity is None and (root_exists or group_exists):
            # A missing launch identity is an uncertainty condition, never
            # permission to signal a possibly reused PID or process group.
            return ProcessCancellationResult(execution_id, ProcessCancellationStatus.RECOVERY_BLOCKED, pid)
        if identity is not None and root_exists:
            refreshed_identity = self._capture_process_identity(pid, group_id)
            if (
                refreshed_identity is None
                or refreshed_identity.start_token != identity.start_token
                or refreshed_identity.process_group_id != identity.process_group_id
                or refreshed_identity.session_id != identity.session_id
            ):
                return ProcessCancellationResult(execution_id, ProcessCancellationStatus.RECOVERY_BLOCKED, pid)
            identity = refreshed_identity
        # A live root must pass its own start-token check and the complete
        # member snapshot. A dead root is recoverable only from that snapshot.
        identity_valid = identity is not None and (
            self._identity_matches(identity) and self._process_group_identity_matches(identity)
            if root_exists
            else self._process_group_identity_matches(identity) if (group_exists or session_exists) else False
        )
        if identity is not None and not identity_valid and (root_exists or group_exists or session_exists):
            return ProcessCancellationResult(execution_id, ProcessCancellationStatus.RECOVERY_BLOCKED, pid)
        if root_exists or group_exists or session_exists:
            terminated = self.kill_process_tree(pid, process_group_id=group_id, identity=identity)
            status = ProcessCancellationStatus.KILLED if terminated else ProcessCancellationStatus.RECOVERY_BLOCKED
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
        if os.name == "nt":
            with self._lock:
                execution_id = next((key for key, value in self._execution_pids.items() if value == pid), None)
                identity = self._execution_identities.get(execution_id) if execution_id else None
            if execution_id is None:
                if self._pid_exists(pid):
                    return ProcessCancellationResult(f"pid:{pid}", ProcessCancellationStatus.RECOVERY_BLOCKED, pid)
                return ProcessCancellationResult(f"pid:{pid}", ProcessCancellationStatus.NOT_FOUND, pid)
            if identity is None:
                return ProcessCancellationResult(f"pid:{pid}", ProcessCancellationStatus.RECOVERY_BLOCKED, pid)
            return self.cancel_execution(execution_id, process_identity=identity)
        with self._lock:
            if pid not in self._active_pids:
                return ProcessCancellationResult(f"pid:{pid}", ProcessCancellationStatus.NOT_FOUND, pid)
            execution_id = next((key for key, value in self._execution_pids.items() if value == pid), f"pid:{pid}")
            group_id = self._execution_groups.get(execution_id)
            identity = self._execution_identities.get(execution_id)
        root_exists = self._pid_exists(pid)
        group_exists = self._process_group_exists(group_id)
        session_exists = identity is not None and self._process_session_exists(identity.session_id)
        if identity is not None and root_exists:
            refreshed_identity = self._capture_process_identity(pid, group_id)
            if (
                refreshed_identity is None
                or refreshed_identity.start_token != identity.start_token
                or refreshed_identity.process_group_id != identity.process_group_id
                or refreshed_identity.session_id != identity.session_id
            ):
                return ProcessCancellationResult(execution_id, ProcessCancellationStatus.RECOVERY_BLOCKED, pid)
            identity = refreshed_identity
        identity_valid = identity is not None and (
            self._identity_matches(identity) and self._process_group_identity_matches(identity)
            if root_exists
            else self._process_group_identity_matches(identity) if (group_exists or session_exists) else False
        )
        if identity is not None and not identity_valid and (root_exists or group_exists or session_exists):
            return ProcessCancellationResult(execution_id, ProcessCancellationStatus.RECOVERY_BLOCKED, pid)
        if root_exists or group_exists or session_exists:
            terminated = self.kill_process_tree(pid, process_group_id=group_id, identity=identity)
            status = ProcessCancellationStatus.KILLED if terminated else ProcessCancellationStatus.RECOVERY_BLOCKED
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
    def _pid_exists(pid: int) -> bool:
        if not pid or pid <= 0:
            return False
        if os.name == "nt":
            # ``os.kill(pid, 0)`` reports some terminated Windows process
            # objects as still queryable while ``Popen`` retains its handle.
            # Query the kernel exit code instead; this is also the fact used
            # by the identity checks and avoids treating a stale PID as live.
            try:
                handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
                if not handle:
                    return False
                try:
                    exit_code = wintypes.DWORD()
                    if not ctypes.windll.kernel32.GetExitCodeProcess(
                        handle,
                        ctypes.byref(exit_code),
                    ):
                        return False
                    return exit_code.value == 259  # STILL_ACTIVE
                finally:
                    ctypes.windll.kernel32.CloseHandle(handle)
            except (AttributeError, OSError):
                return False
        if sys.platform.startswith("linux"):
            # ``os.kill(pid, 0)`` also reports a zombie as present until its
            # parent (or the init reaper) collects it. A zombie cannot execute
            # code, so treating it as live would convert a confirmed process
            # tree termination into a false termination-uncertain result.
            # Keep the conservative kill(0) fallback when procfs is not
            # readable or the process exits between the two observations.
            try:
                with open(os.path.join("/proc", str(pid), "stat"), encoding="ascii") as stat_file:
                    stat_record = stat_file.read()
                closing_paren = stat_record.rfind(")")
                fields_after_command = stat_record[closing_paren + 1 :].split()
                if fields_after_command and fields_after_command[0] in {"Z", "X"}:
                    return False
            except FileNotFoundError:
                return False
            except (OSError, UnicodeError):
                pass
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
        if sys.platform.startswith("linux"):
            # ``os.killpg(pgid, 0)`` reports a group containing only zombie
            # entries as present until those entries are reaped. Inspect the
            # procfs state so a dead, unreapable child cannot be reported as a
            # live execution process. If procfs cannot be enumerated, retain
            # the conservative kill(0) result below.
            try:
                proc_entries = os.listdir("/proc")
                procfs_complete = True
                for entry in proc_entries:
                    if not entry.isdigit():
                        continue
                    try:
                        with open(os.path.join("/proc", entry, "stat"), encoding="ascii") as stat_file:
                            stat_record = stat_file.read()
                        closing_paren = stat_record.rfind(")")
                        fields_after_command = stat_record[closing_paren + 1 :].split()
                        if len(fields_after_command) < 3:
                            continue
                        state = fields_after_command[0]
                        member_group_id = int(fields_after_command[2])
                    except FileNotFoundError:
                        continue
                    except (OSError, UnicodeError, ValueError):
                        procfs_complete = False
                        continue
                    if member_group_id == pgid and state not in {"Z", "X"}:
                        return True
                if procfs_complete:
                    return False
            except OSError:
                pass
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
    def _process_session_exists(session_id: Optional[int]) -> bool:
        """Return whether a live process remains in an owned POSIX session.

        A process group is the primary termination container, but a child can
        change its process group while remaining in the launch session.  The
        supervisor therefore checks both identities before it treats a
        governed execution as empty.  Failure to enumerate the session is
        conservative: recovery must remain open instead of being converted to
        a false terminal result.
        """
        if os.name == "nt" or not session_id or session_id <= 1:
            return False
        try:
            result = subprocess.run(
                ["ps", "-e", "-o", "pid=", "-o", "sid=", "-o", "stat="],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=1.0,
                check=False,
            )
            if result.returncode != 0:
                return True
            for line in result.stdout.splitlines():
                fields = line.split()
                if len(fields) < 3:
                    if line.strip():
                        return True
                    continue
                try:
                    member_pid, member_session_id = (int(value) for value in fields[:2])
                except ValueError:
                    return True
                if (
                    member_pid > 1
                    and member_session_id == session_id
                    and not fields[2].startswith(("Z", "X"))
                ):
                    return True
            return False
        except (OSError, subprocess.SubprocessError):
            return True

    @staticmethod
    def _posix_session_member_identities(
        session_id: Optional[int],
    ) -> Optional[list[tuple[int, str, int]]]:
        """Capture live members of an owned POSIX session with start tokens.

        The result is deliberately ``None`` when the complete membership or
        any member identity cannot be established.  Callers must treat that
        as an uncertainty condition rather than falling back to an unbound
        PID signal.
        """
        if os.name == "nt" or not session_id or session_id <= 1:
            return []
        try:
            result = subprocess.run(
                ["ps", "-e", "-o", "pid=", "-o", "pgid=", "-o", "sid=", "-o", "stat="],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=1.0,
                check=False,
            )
            if result.returncode != 0:
                return None
            members: list[tuple[int, str, int]] = []
            for line in result.stdout.splitlines():
                fields = line.split()
                if len(fields) < 4:
                    if line.strip():
                        return None
                    continue
                try:
                    member_pid, member_pgid, member_session_id = (
                        int(value) for value in fields[:3]
                    )
                except ValueError:
                    return None
                if (
                    member_pid <= 1
                    or member_pgid <= 1
                    or member_session_id != session_id
                    or fields[3].startswith(("Z", "X"))
                ):
                    continue
                start_token = _read_posix_start_token(member_pid)
                if start_token is None:
                    return None
                members.append((member_pid, start_token, member_pgid))
                if len(members) > 512:
                    # An unbounded process set cannot be safely represented or
                    # revalidated by this bounded recovery contract.
                    return None
            return members
        except (OSError, subprocess.SubprocessError):
            return None

    @staticmethod
    def _capture_process_member_identity(
        pid: int,
        process_group_id: int,
        session_id: int,
        start_token: Optional[str] = None,
    ) -> Optional[ProcessMemberIdentity]:
        """Capture one member identity without recursively enumerating a session."""
        token = start_token or _read_posix_start_token(pid)
        if (
            os.name == "nt"
            or pid <= 1
            or process_group_id <= 1
            or session_id < 0
            or not isinstance(token, str)
            or not token.strip()
        ):
            return None
        try:
            if os.getsid(pid) != session_id or os.getpgid(pid) != process_group_id:
                return None
        except OSError:
            return None
        current_token = _read_posix_start_token(pid)
        if current_token != token:
            return None
        return ProcessMemberIdentity(pid, process_group_id, session_id, token)

    @staticmethod
    def _terminate_posix_session_members(
        identity: Optional[ProcessIdentity],
        process_group_id: Optional[int],
    ) -> bool:
        """Terminate verified session members outside the owned process group.

        Process-group signalling remains the primary operation.  This narrow
        supplemental path handles a descendant that changed PGID while
        retaining the captured session.  Every supplemental signal is bound to
        a freshly revalidated PID/start-token/session/PGID tuple; a mismatch
        or incomplete enumeration fails closed.
        """
        if identity is None or identity.session_id is None or os.name == "nt":
            return True
        members = ProcessSupervisor._posix_session_member_identities(identity.session_id)
        if members is None:
            return False
        expected = {
            (member.pid, member.start_token)
            for member in identity.member_snapshot
            if member.session_id == identity.session_id
        }
        if not expected:
            return False
        current_set = {(member_pid, start_token) for member_pid, start_token, _ in members}
        # A root-exit snapshot is authoritative only when every remaining
        # member was present in the bounded snapshot. A new PID or changed
        # start token is a recovery block. PGID is mutable for an attested
        # descendant; its current value is freshly checked below.
        if not current_set.issubset(expected):
            return False
        current_pid = os.getpid()
        parent_pid = os.getppid() if hasattr(os, "getppid") else None
        for member_pid, start_token, member_pgid in members:
            if member_pid == current_pid or member_pid == parent_pid:
                logger.error(
                    "Security invariant: owned session contains supervisor PID=%s",
                    member_pid,
                )
                return False
            if member_pid == identity.pid and start_token != identity.start_token:
                logger.error(
                    "Security invariant: owned root PID was reused PID=%s",
                    member_pid,
                )
                return False
            if process_group_id is not None and member_pgid == process_group_id:
                continue
            current = ProcessSupervisor._capture_process_member_identity(
                member_pid,
                member_pgid,
                identity.session_id,
                start_token,
            )
            if current is None:
                if not ProcessSupervisor._pid_exists(member_pid):
                    continue
                return False
            try:
                os.kill(member_pid, signal.SIGKILL)
            except ProcessLookupError:
                continue
            except OSError:
                return False
        return True

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
        session_id = None
        if os.name != "nt":
            try:
                session_id = os.getsid(pid)
            except OSError:
                return None
        member_snapshot: Tuple[ProcessMemberIdentity, ...] = ()
        if os.name != "nt" and process_group_id is not None and session_id is not None:
            members = ProcessSupervisor._posix_session_member_identities(session_id)
            if members is None:
                return None
            member_snapshot = tuple(
                ProcessMemberIdentity(member_pid, member_pgid, session_id, member_start_token)
                for member_pid, member_start_token, member_pgid in members
            )
            if not any(member.pid == pid and member.start_token == start_token for member in member_snapshot):
                return None
        return ProcessIdentity(pid, process_group_id, start_token, session_id, member_snapshot)

    @staticmethod
    def _capture_posix_identity_after_root_exit(
        previous: ProcessIdentity,
    ) -> Optional[ProcessIdentity]:
        """Finalize an identity after an already-attested root exits.

        The root start token and session were captured while the root was live.
        A later snapshot may therefore retain that attested root as historical
        evidence while binding any surviving members to their own current
        start tokens and session. No PID discovered only after the root exits
        is eligible unless it was present in this complete, bounded snapshot.
        """
        if (
            os.name == "nt"
            or type(previous) is not ProcessIdentity
            or previous.pid <= 1
            or previous.process_group_id is None
            or previous.process_group_id <= 1
            or previous.session_id is None
            or previous.session_id <= 1
            or not isinstance(previous.start_token, str)
            or not previous.start_token.strip()
        ):
            return None
        previous_members = previous.member_snapshot
        if (
            type(previous_members) is not tuple
            or not previous_members
            or len(previous_members) > 512
        ):
            return None
        current_pid = os.getpid()
        parent_pid = os.getppid() if hasattr(os, "getppid") else None
        previous_pairs: set[tuple[int, str]] = set()
        previous_pids: set[int] = set()
        previous_root: Optional[ProcessMemberIdentity] = None
        for member in previous_members:
            if (
                type(member) is not ProcessMemberIdentity
                or type(member.pid) is not int
                or type(member.process_group_id) is not int
                or type(member.session_id) is not int
                or member.pid <= 1
                or member.process_group_id <= 1
                or member.session_id != previous.session_id
                or not isinstance(member.start_token, str)
                or not member.start_token.strip()
                or member.pid in {current_pid, parent_pid}
                or member.pid in previous_pids
            ):
                return None
            pair = (member.pid, member.start_token)
            if pair in previous_pairs:
                return None
            previous_pairs.add(pair)
            previous_pids.add(member.pid)
            if member.pid == previous.pid:
                if (
                    previous_root is not None
                    or member.start_token != previous.start_token
                    or member.process_group_id != previous.process_group_id
                ):
                    return None
                previous_root = member
        if previous_root is None:
            return None
        # A live or PID-reused root cannot be treated as a completed root-exit
        # transition. The second token read is the current kernel fact.
        if _read_posix_start_token(previous.pid) is not None:
            return None
        members = ProcessSupervisor._posix_session_member_identities(previous.session_id)
        if members is None:
            return None
        if not isinstance(members, list) or len(members) > 512:
            return None
        live_members: list[ProcessMemberIdentity] = []
        current_pids: set[int] = set()
        current_pairs: set[tuple[int, str]] = set()
        for raw_member in members:
            if not isinstance(raw_member, tuple) or len(raw_member) != 3:
                return None
            member_pid, member_start_token, member_pgid = raw_member
            if (
                type(member_pid) is not int
                or type(member_pgid) is not int
                or member_pid <= 1
                or member_pgid <= 1
                or not isinstance(member_start_token, str)
                or not member_start_token.strip()
                or member_pid in {current_pid, parent_pid, previous.pid}
            ):
                return None
            pair = (member_pid, member_start_token)
            # The post-root snapshot is an allowlist intersection, never a
            # new authority source. A member created after the attested
            # snapshot, or a PID reused with a new token, is a recovery block.
            if pair not in previous_pairs or member_pid in current_pids or pair in current_pairs:
                return None
            current = ProcessSupervisor._capture_process_member_identity(
                member_pid,
                member_pgid,
                previous.session_id,
                member_start_token,
            )
            if current is None:
                return None
            current_pids.add(member_pid)
            current_pairs.add(pair)
            live_members.append(current)
        root_member = previous_root
        snapshot = tuple(
            sorted(
                (root_member, *live_members),
                key=lambda member: (member.pid, member.start_token, member.process_group_id),
            )
        )
        return ProcessIdentity(
            previous.pid,
            previous.process_group_id,
            previous.start_token,
            previous.session_id,
            snapshot,
        )

    def _capture_stable_process_identity(
        self,
        pid: int,
        process_group_id: Optional[int],
    ) -> Optional[ProcessIdentity]:
        """Complete the post-Popen identity handshake after startup settles.

        ``Popen`` only proves that the root was created.  A governed tool may
        create its normal worker/helper descendants immediately afterwards.
        Capture is therefore a bounded two-phase handshake: a fresh snapshot
        is sampled repeatedly until it remains unchanged for the required
        stability interval.  If an already-attested root exits during the
        handshake, a bounded post-exit snapshot may complete the proof while
        retaining the root's original start token.  If no identity was ever
        captured or membership never settles, callers retain launch
        uncertainty and recovery rather than signalling an unbound PID/group.
        """
        if os.name == "nt":
            return self._capture_process_identity(pid, process_group_id)
        deadline = time.monotonic() + self._LAUNCH_HANDSHAKE_MAX_SECONDS
        stable_since: Optional[float] = None
        previous: Optional[ProcessIdentity] = None
        post_exit_previous: Optional[ProcessIdentity] = None
        post_exit_stable_since: Optional[float] = None
        while time.monotonic() < deadline:
            current = self._capture_process_identity(pid, process_group_id)
            if current is not None:
                post_exit_previous = None
                post_exit_stable_since = None
                if previous is None or current != previous:
                    previous = current
                    stable_since = time.monotonic()
                elif stable_since is not None and (
                    time.monotonic() - stable_since >= self._LAUNCH_HANDSHAKE_STABLE_SECONDS
                ):
                    return current
            elif previous is not None:
                post_exit = self._capture_posix_identity_after_root_exit(previous)
                if post_exit is not None:
                    stable_since = None
                    if post_exit_previous is None or post_exit != post_exit_previous:
                        post_exit_previous = post_exit
                        post_exit_stable_since = time.monotonic()
                    elif post_exit_stable_since is not None and (
                        time.monotonic() - post_exit_stable_since
                        >= self._LAUNCH_HANDSHAKE_STABLE_SECONDS
                    ):
                        return post_exit
                else:
                    post_exit_previous = None
                    post_exit_stable_since = None
                    stable_since = None
            else:
                stable_since = None
            time.sleep(self._LAUNCH_HANDSHAKE_POLL_SECONDS)
        return None

    @staticmethod
    def _process_group_identity_matches(identity: ProcessIdentity) -> bool:
        """Verify a fresh, complete identity snapshot while the root lives.

        Numeric PGID/SID values are not an ownership proof after the root has
        exited. Every currently live member is read with its PID, PGID, SID,
        and kernel start token while the root remains observable. Any
        incomplete or inconsistent snapshot fails closed; callers retain
        durable recovery instead of signalling an unbound process group.
        """
        if os.name == "nt" or identity.process_group_id is None or identity.session_id is None:
            return False
        members = ProcessSupervisor._posix_session_member_identities(identity.session_id)
        if members is None:
            return False
        if not identity.member_snapshot:
            return False
        expected = {
            (member.pid, member.start_token)
            for member in identity.member_snapshot
            if member.session_id == identity.session_id
        }
        current_set = {(member_pid, start_token) for member_pid, start_token, _ in members}
        if not expected or not current_set.issubset(expected):
            return False
        current_pid = os.getpid()
        parent_pid = os.getppid() if hasattr(os, "getppid") else None
        if any(member_pid in {current_pid, parent_pid} for member_pid, _, _ in members):
            return False
        root_members = [entry for entry in members if entry[0] == identity.pid]
        if root_members and root_members != [
            (identity.pid, identity.start_token, identity.process_group_id)
        ]:
            return False
        # If the root is gone, at least one attested member must remain for
        # group/session recovery to be meaningful. An empty container is
        # handled by the post-signal emptiness proof.
        if not root_members and not current_set:
            return False
        return all(
            ProcessSupervisor._capture_process_member_identity(pid, pgid, identity.session_id, token)
            is not None
            for pid, token, pgid in members
        )

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
    def _process_tree_empty(
        identity: Optional[ProcessIdentity],
        process_group_id: Optional[int],
        *,
        root_exited: bool = False,
    ) -> bool:
        """Require both the root and its owned container to be gone."""
        if identity is None:
            return False
        if identity.windows_attestation is not None:
            try:
                from app.core.windows_job import attested_job
                return not attested_job(_windows_identity_attestation(identity)).members()
            except (OSError, ValueError, TypeError):
                return False
        # ``os.kill(pid, 0)`` is not a reliable post-reap liveness test on
        # Windows: the PID can remain queryable after ``Popen.wait()`` has
        # reaped the process.  The supervisor has the stronger process-handle
        # fact in that case, so callers pass ``root_exited`` after observing
        # the child return.  POSIX still requires the process-group check
        # below, which covers surviving descendants.
        if not root_exited and ProcessSupervisor._pid_exists(identity.pid):
            return False
        if process_group_id and ProcessSupervisor._process_group_exists(process_group_id):
            return False
        if identity.session_id is not None and ProcessSupervisor._process_session_exists(identity.session_id):
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
        if os.name == "nt":
            try:
                if identity is None or identity.pid != pid or process_group_id is not None:
                    return False
                from app.core.windows_job import attested_job
                return attested_job(_windows_identity_attestation(identity), for_recovery=True).terminate()
            except (OSError, ValueError, TypeError):
                return False
        if identity is not None and identity.pid != pid:
            return False
        root_exists = ProcessSupervisor._pid_exists(pid)
        if identity is not None and root_exists:
            refreshed_identity = ProcessSupervisor._capture_process_identity(pid, process_group_id)
            if (
                refreshed_identity is None
                or refreshed_identity.start_token != identity.start_token
                or refreshed_identity.process_group_id != identity.process_group_id
                or refreshed_identity.session_id != identity.session_id
            ):
                return False
            identity = refreshed_identity
        session_exists = identity is not None and ProcessSupervisor._process_session_exists(identity.session_id)
        identity_matches = identity is not None and (
            ProcessSupervisor._identity_matches(identity)
            and ProcessSupervisor._process_group_identity_matches(identity)
            if root_exists
            else ProcessSupervisor._process_group_identity_matches(identity)
            if (ProcessSupervisor._process_group_exists(process_group_id) or session_exists)
            else False
        )
        if identity is not None and not identity_matches and (
            ProcessSupervisor._pid_exists(pid)
            or ProcessSupervisor._process_group_exists(process_group_id)
            or session_exists
        ):
            logger.error("Recovery blocked: process launch identity could not be proven PID=%s", pid)
            return False

        descendants: list[int] = []
        group_id: Optional[int] = process_group_id
        if os.name != "nt":
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
                # A failed group operation is indeterminate. Never fall back to
                # an unbound PID signal, which could target a reused process.
                return False
        tracked_pids = [pid, *descendants]
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if not ProcessSupervisor._terminate_posix_session_members(identity, group_id):
                return False
            if (
                not any(ProcessSupervisor._pid_exists(member) for member in tracked_pids)
                and not ProcessSupervisor._process_group_exists(group_id)
                and not ProcessSupervisor._process_session_exists(
                    identity.session_id if identity is not None else None
                )
            ):
                return True
            time.sleep(0.02)
        if not ProcessSupervisor._terminate_posix_session_members(identity, group_id):
            return False
        return (
            not any(ProcessSupervisor._pid_exists(member) for member in tracked_pids)
            and not ProcessSupervisor._process_group_exists(group_id)
            and not ProcessSupervisor._process_session_exists(
                identity.session_id if identity is not None else None
            )
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
        execution_context: Optional[GovernedExecutionContext] = None,
        non_scan_context: Optional[NonScanExecutionContext] = None,
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
        if execution_capability is None and non_scan_context is None:
            return ProcessExecutionResult(126, "", "PROCESS_LAUNCH_REJECTED_SECURITY: launch must declare governed or non-scan capability")
        if execution_capability is not None and non_scan_context is not None:
            return ProcessExecutionResult(
                126,
                "",
                "PROCESS_LAUNCH_REJECTED_SECURITY: launch cannot declare both governed and non-scan capabilities",
            )
        # R3.2: Enterprise external-tool execution fails closed unconditionally when
        # enterprise egress enforcement is required until an authoritative network verifier interface exists.
        operating_mode = (os.environ.get("OPERATING_MODE") or os.environ.get("ENVIRONMENT") or "").strip().upper()
        egress_required = operating_mode == "ENTERPRISE" or os.environ.get("ENTERPRISE_EGRESS_ENFORCEMENT_REQUIRED", "").lower() in {"1", "true", "yes"}

        creationflags = 0
        start_new_session = False
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            start_new_session = True

        def _bounded_communicate(
            proc: subprocess.Popen,
            renew_lease: Optional[Callable[[], bool]] = None,
            process_identity: Optional[ProcessIdentity] = None,
            process_group_id: Optional[int] = None,
            cancellation_requested: Optional[threading.Event] = None,
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
            cancellation_seen = False
            termination_confirmed = True
            while proc.poll() is None:
                if cancellation_requested is not None and cancellation_requested.is_set():
                    cancellation_seen = True
                    termination_confirmed = self.kill_process_tree(
                        proc.pid,
                        process_group_id=process_group_id,
                        identity=process_identity,
                    )
                    break
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
            # A native Job Object may have completed termination while its
            # first bounded membership query still observes the terminating
            # root. Once the exact process handle has reported exit, retry the
            # same identity-bound container proof once. This does not widen
            # the target: kill_process_tree still rejects an unbound Windows
            # PID and only attested job membership can make this successful.
            if not termination_confirmed and process_identity is not None:
                termination_confirmed = self.kill_process_tree(
                    proc.pid,
                    process_group_id=process_group_id,
                    identity=process_identity,
                )
                if termination_confirmed and proc.poll() is None:
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        termination_confirmed = False
            # A root can exit while an attested descendant still owns one of
            # the inherited pipes. Close the exact process container before
            # joining the readers so already-written output is retained and
            # the readers cannot remain blocked on an unbounded descendant.
            if (
                proc.poll() is not None
                and process_identity is not None
                and not self._process_tree_empty(
                    process_identity,
                    process_group_id,
                    root_exited=True,
                )
            ):
                termination_confirmed = self.kill_process_tree(
                    proc.pid,
                    process_group_id=process_group_id,
                    identity=process_identity,
                ) and termination_confirmed
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
            return stdout, stderr, limit_reached.is_set() or timed_out or lease_lost or cancellation_seen, termination_confirmed

        proc_ref: list[Optional[subprocess.Popen]] = [None]
        process_identity_ref: list[Optional[ProcessIdentity]] = [None]
        process_group_ref: list[Optional[int]] = [None]
        windows_job_ref: list[object | None] = [None]
        retain_execution_ref = [False]
        cancellation_requested = threading.Event()
        requested_execution_id = execution_id

        def _run_sync() -> ProcessExecutionResult:
            nonlocal proc_ref, execution_context, execution_id
            proc = None
            launch_committed = False
            authority_claimed = False
            windows_job = None
            windows_attestation = None

            def _settle_durable(
                terminal_state: str,
                reason_code: str,
                process_id: Optional[int] = None,
                process_group_id: Optional[str] = None,
                termination_status: Optional[str] = None,
            ) -> bool:
                if execution_capability is None:
                    return True
                if not authority_claimed or execution_id != execution_capability.execution_id:
                    return False
                from app.core.execution_service import settle_execution
                return settle_execution(
                    execution_capability,
                    terminal_state=terminal_state,
                    reason_code=reason_code,
                    process_id=process_id,
                    process_group_id=process_group_id,
                    process_start_token=(
                        process_identity_ref[0].start_token
                        if process_identity_ref[0] is not None else None
                    ),
                    session_id=(
                        process_identity_ref[0].session_id
                        if process_identity_ref[0] is not None else None
                    ),
                    termination_status=termination_status,
                )

            def _finish_durable(
                terminal_state: str,
                reason_code: Optional[str] = None,
                termination_status: Optional[str] = None,
            ) -> Optional[ProcessExecutionResult]:
                if execution_capability is None:
                    return None
                if execution_id != execution_capability.execution_id:
                    return ProcessExecutionResult(-1, "", "PROCESS_FINALIZATION_REJECTED_SECURITY: execution identity mismatch")
                if not _settle_durable(
                    terminal_state, reason_code,
                    process_id=proc.pid if proc else None,
                    process_group_id=str(proc.pid) if proc and start_new_session else None,
                    termination_status=termination_status,
                ):
                    return ProcessExecutionResult(-1, "", "PROCESS_FINALIZATION_FAILED: durable terminal state was not committed")
                return None

            def _settle_no_process(
                terminal_state: str,
                reason_code: str,
                result: ProcessExecutionResult,
            ) -> ProcessExecutionResult:
                """Return a rejection only after a claimed run is durably closed."""
                if execution_capability is not None:
                    try:
                        settled = authority_claimed and _settle_durable(terminal_state, reason_code)
                    except Exception as exc:
                        logger.warning(
                            "Durable no-process settlement failed: execution_id=%s error_type=%s",
                            execution_id,
                            type(exc).__name__,
                        )
                        settled = False
                    if not settled:
                        return ProcessExecutionResult(
                            -1,
                            "",
                            "PROCESS_FINALIZATION_FAILED: durable no-process outcome was not committed",
                        )
                return result

            def _attest_windows_process(job, nonce, process):
                """Bind the suspended process to its kernel job before resume."""
                from app.core.execution_context import (
                    WindowsJobAttestation,
                    WindowsNonScanJobAttestation,
                    canonical_windows_job_attestation_digest,
                    canonical_windows_non_scan_job_attestation_digest,
                )
                from app.core.windows_job import register_attestation

                captured = datetime.now(timezone.utc)
                initial_members = job.members()
                if initial_members != (process.pid,):
                    raise RuntimeError("Windows job did not contain exactly the suspended root")
                if execution_capability is not None:
                    values = {
                        "schema_version": "windows-job-attestation-v1",
                        "proof_type": "JOB_OBJECT",
                        "job_identity": job.name,
                        "job_nonce": nonce,
                        "execution_id": execution_id,
                        "organization_id": execution_capability.decision.organization_id,
                        "worker_identity": execution_capability.worker_identity,
                        "worker_generation": execution_capability.worker_generation,
                        "root_process_id": process.pid,
                        "root_process_start_token": process.start_token(),
                        "initial_members": initial_members,
                        "captured_at": captured,
                        "expires_at": captured + timedelta(seconds=max(timeout, 0) + 300),
                        "verification_result": "VERIFIED",
                    }
                    attestation = WindowsJobAttestation(
                        **values,
                        digest=canonical_windows_job_attestation_digest(values),
                    )
                elif non_scan_context is not None:
                    values = {
                        "schema_version": "windows-non-scan-job-attestation-v1",
                        "proof_type": "JOB_OBJECT",
                        "job_identity": job.name,
                        "job_nonce": nonce,
                        "purpose": non_scan_context.purpose,
                        "worker_identity": non_scan_context.worker_identity,
                        "worker_generation": non_scan_context.worker_generation,
                        "root_process_id": process.pid,
                        "root_process_start_token": process.start_token(),
                        "initial_members": initial_members,
                        "captured_at": captured,
                        "expires_at": captured + timedelta(seconds=max(timeout, 0) + 300),
                        "verification_result": "VERIFIED",
                    }
                    attestation = WindowsNonScanJobAttestation(
                        **values,
                        digest=canonical_windows_non_scan_job_attestation_digest(values),
                    )
                else:
                    raise RuntimeError("Windows launch requires a governed or non-scan capability")
                register_attestation(attestation, job)
                identity = ProcessIdentity(
                    pid=process.pid,
                    process_group_id=None,
                    start_token=attestation.root_process_start_token,
                    windows_attestation=attestation.model_dump_json(),
                )
                return attestation, identity

            try:
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
                            worker_identity=execution_capability.worker_identity,
                            timeout=timeout,
                            max_output_bytes=max_output_bytes,
                        )
                        authority_claimed = True
                        execution_id = execution_capability.execution_id
                        if requested_execution_id is not None and requested_execution_id != execution_id:
                            return _settle_no_process(
                                "EXECUTION_BLOCKED",
                                "EXECUTION_IDENTITY_MISMATCH",
                                ProcessExecutionResult(
                                    126,
                                    "",
                                    "PROCESS_LAUNCH_REJECTED_SECURITY: execution identity mismatch",
                                ),
                            )
                        if execution_context is None:
                            execution_context = execution_capability.issue_execution_context(command=cmd)
                        if type(execution_context) is not GovernedExecutionContext:
                            raise TypeError("typed governed execution context is required")
                        execution_context.assert_bound_to_capability(execution_capability)
                        execution_context.assert_launch(
                            execution_id=execution_capability.execution_id,
                            organization_id=execution_capability.decision.organization_id,
                            command=cmd,
                        )
                    elif non_scan_context is not None:
                        if execution_id is not None:
                            raise ValueError("non-scan capability cannot carry scan execution identity")
                        if type(non_scan_context) is not NonScanExecutionContext:
                            raise TypeError("invalid non-scan context")
                        non_scan_context.assert_issued()
                        non_scan_context.assert_live()
                    else:
                        raise ExecutionDecisionError("launch must declare governed or non-scan capability")
                    if egress_required:
                        return _settle_no_process(
                            "EXECUTION_BLOCKED",
                            "PROCESS_LAUNCH_REJECTED_SECURITY",
                            ProcessExecutionResult(
                                -1,
                                "",
                                "PROCESS_LAUNCH_REJECTED_SECURITY: Enterprise egress network enforcement facility is not configured or verifiably available.",
                            ),
                        )
                    if non_scan_context is not None:
                        try:
                            from app.core.execution_service import get_worker_generation, get_worker_identity
                            deployment_identity = get_worker_identity()
                            deployment_generation = get_worker_generation()
                        except RuntimeError:
                            return _settle_no_process(
                                "EXECUTION_BLOCKED",
                                "PROCESS_LAUNCH_REJECTED_SECURITY",
                                ProcessExecutionResult(
                                    126,
                                    "",
                                    "PROCESS_LAUNCH_REJECTED_SECURITY: deployment worker identity is not configured",
                                ),
                            )
                        if (
                            non_scan_context.worker_identity != deployment_identity
                            or non_scan_context.worker_generation != deployment_generation
                        ):
                            return _settle_no_process(
                                "EXECUTION_BLOCKED",
                                "PROCESS_LAUNCH_REJECTED_SECURITY",
                                ProcessExecutionResult(
                                    126,
                                    "",
                                    "PROCESS_LAUNCH_REJECTED_SECURITY: non-scan execution identity mismatch",
                                ),
                            )
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

                    if cancellation_requested.is_set():
                        return _settle_no_process(
                            "CANCELLED",
                            "EXECUTION_CANCELLED_BEFORE_PROCESS_CREATION",
                            ProcessExecutionResult(
                                130,
                                "",
                                "PROCESS_LAUNCH_CANCELLED: cancellation was requested before process creation",
                            ),
                        )
                    if pre_launch_check is not None:
                        try:
                            pre_launch_ok = bool(pre_launch_check())
                        except Exception as exc:
                            return _settle_no_process(
                                "EXECUTION_BLOCKED",
                                "PROCESS_LAUNCH_REJECTED_SECURITY",
                                ProcessExecutionResult(
                                    126,
                                    "",
                                    f"PROCESS_LAUNCH_REJECTED_SECURITY: pre-launch security verification failed ({type(exc).__name__})",
                                ),
                            )
                        if not pre_launch_ok:
                            return _settle_no_process(
                                "EXECUTION_BLOCKED",
                                "PROCESS_LAUNCH_REJECTED_SECURITY",
                                ProcessExecutionResult(
                                    126,
                                    "",
                                    "PROCESS_LAUNCH_REJECTED_SECURITY: pre-launch security verification failed",
                                ),
                            )
                except (AttributeError, TypeError, ValueError) as exc:
                    if execution_capability is not None and authority_claimed:
                        if not _settle_durable("EXECUTION_BLOCKED", "PROCESS_LAUNCH_REJECTED_SECURITY"):
                            return ProcessExecutionResult(
                                -1,
                                "",
                                "PROCESS_FINALIZATION_FAILED: security rejection outcome was not committed",
                            )
                    return ProcessExecutionResult(
                        126,
                        "",
                        f"PROCESS_LAUNCH_REJECTED_SECURITY: invalid launch capability ({type(exc).__name__})",
                    )
                if cancellation_requested.is_set():
                    return _settle_no_process(
                        "CANCELLED",
                        "EXECUTION_CANCELLED_BEFORE_PROCESS_CREATION",
                        ProcessExecutionResult(130, "", "PROCESS_LAUNCH_CANCELLED: cancellation was requested before process creation"),
                    )
                if os.name == "nt":
                    from app.core.windows_job import WindowsJob, WindowsJobProcess, JobLaunchUncertain
                    from app.core.execution_context import windows_job_name, windows_non_scan_job_name
                    job_nonce = uuid.uuid4().hex
                    if execution_capability is not None:
                        job_identity = windows_job_name(
                            execution_id,
                            execution_capability.decision.organization_id,
                            execution_capability.worker_identity,
                            execution_capability.worker_generation,
                            job_nonce,
                        )
                    elif non_scan_context is not None:
                        job_identity = windows_non_scan_job_name(
                            non_scan_context.purpose,
                            non_scan_context.worker_identity,
                            non_scan_context.worker_generation,
                            job_nonce,
                        )
                    else:
                        raise RuntimeError("Windows launch requires a governed or non-scan capability")
                    windows_job = WindowsJob(job_identity)
                    windows_job_ref[0] = windows_job
                    try:
                        proc = WindowsJobProcess(cmd, job=windows_job, cwd=cwd, env=clean_env)
                    except JobLaunchUncertain as exc:
                        proc = exc.process
                        proc_ref[0] = proc
                        try:
                            windows_attestation, process_identity = _attest_windows_process(
                                windows_job, job_nonce, proc,
                            )
                            process_identity_ref[0] = process_identity
                            process_group_ref[0] = None
                        except Exception:
                            # The process is still suspended.  A local handle is
                            # sufficient to make a best-effort containment
                            # attempt, but no incomplete object may be treated as
                            # a durable execution identity.
                            try:
                                windows_job.terminate()
                            except Exception:
                                pass
                        raise
                else:
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
                # Register immediately after Popen.  Identity capture and the
                # durable ownership write are part of the launch handshake;
                # either may fail after a real process already exists.
                self._register_execution(
                    proc.pid,
                    execution_id=execution_id,
                    process_group_id=str(process_group_id) if process_group_id else None,
                    identity=None,
                )
                if windows_job is not None:
                    windows_attestation, process_identity = _attest_windows_process(
                        windows_job, job_nonce, proc,
                    )
                else:
                    process_identity = self._capture_stable_process_identity(proc.pid, process_group_id)
                process_identity_ref[0] = process_identity
                process_group_ref[0] = process_group_id
                if process_identity is None:
                    retain_execution_ref[0] = True
                    if execution_capability is not None:
                        try:
                            from app.core.execution_service import record_launch_uncertain
                            recorded = record_launch_uncertain(
                                execution_capability,
                                pid=proc.pid,
                                process_group_id=process_group_id,
                                windows_attestation=(process_identity_ref[0].windows_attestation if process_identity_ref[0] else None),
                            )
                        except Exception as exc:
                            logger.error(
                                "Post-Popen identity uncertainty could not be persisted: error_type=%s",
                                type(exc).__name__,
                            )
                            recorded = False
                        if not recorded:
                            return ProcessExecutionResult(
                                -1, "",
                                "PROCESS_FINALIZATION_FAILED: post-Popen identity uncertainty was not committed",
                            )
                    return ProcessExecutionResult(
                        -1, "",
                        "PROCESS_LAUNCH_UNCERTAIN: process identity unavailable; recovery is required",
                    )
                if execution_capability is not None:
                    try:
                        from app.core.execution_service import record_posix_launch
                        if windows_job is not None:
                            from app.core.execution_service import record_windows_launch
                            record_windows_launch(execution_capability, windows_attestation)
                        else:
                            record_posix_launch(
                                execution_capability,
                                pid=proc.pid,
                                process_group_id=process_group_id,
                                session_id=process_identity.session_id if process_identity.session_id is not None else -1,
                                start_token=process_identity.start_token,
                                member_snapshot=process_identity.member_snapshot,
                            )
                    except Exception as exc:
                        termination_confirmed = self.kill_process_tree(
                            proc.pid, process_group_id=process_group_id, identity=process_identity,
                        )
                        # A real Popen has occurred.  Even confirmed
                        # termination does not prove that the durable launch
                        # handshake never happened; persist uncertainty first
                        # and let the recovery primitive perform the only
                        # terminal transition for this post-creation path.
                        retain_execution_ref[0] = True
                        try:
                            from app.core.execution_service import record_launch_uncertain
                            recorded = record_launch_uncertain(
                                execution_capability,
                                pid=proc.pid,
                                process_group_id=process_group_id,
                                start_token=process_identity.start_token,
                                session_id=process_identity.session_id,
                                member_snapshot=process_identity.member_snapshot,
                                windows_attestation=(process_identity_ref[0].windows_attestation if process_identity_ref[0] else None),
                            )
                        except Exception as uncertainty_exc:
                            logger.error(
                                "Post-Popen ownership uncertainty could not be persisted: error_type=%s",
                                type(uncertainty_exc).__name__,
                            )
                            recorded = False
                        if not recorded:
                            return ProcessExecutionResult(
                                -1, "",
                                "PROCESS_FINALIZATION_FAILED: post-Popen ownership uncertainty was not committed",
                            )
                        return ProcessExecutionResult(
                            -1, "",
                            "PROCESS_LAUNCH_UNCERTAIN: durable process ownership commit failed; recovery is required",
                        )
                    execution_capability.mark_started(
                        process_id=proc.pid,
                        process_group_id=str(process_group_id) if process_group_id else None,
                    )
                    launch_committed = True
                if windows_job is not None:
                    proc.resume()
                # Replace the provisional identity-free registration with the
                # verified process identity before any bounded communication.
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
                    cancellation_requested=cancellation_requested,
                )
                if bounded_failure and not termination_confirmed:
                    retain_execution_ref[0] = True
                    if execution_capability is not None and launch_committed:
                        try:
                            from app.core.execution_service import record_launch_uncertain
                            recorded = record_launch_uncertain(
                                execution_capability,
                                pid=proc.pid,
                                process_group_id=process_group_id,
                                start_token=process_identity.start_token if process_identity else None,
                                session_id=process_identity.session_id if process_identity else None,
                                member_snapshot=process_identity.member_snapshot if process_identity else None,
                                windows_attestation=(process_identity_ref[0].windows_attestation if process_identity_ref[0] else None),
                            )
                        except Exception as uncertainty_exc:
                            # The durable state remains governed only when
                            # the database transition succeeds; retain the
                            # process for recovery if the downgrade is fenced.
                            logger.error(
                                "Bounded-execution uncertainty could not be persisted: error_type=%s",
                                type(uncertainty_exc).__name__,
                            )
                            recorded = False
                        if not recorded:
                            return ProcessExecutionResult(
                                -1, stdout,
                                "PROCESS_FINALIZATION_FAILED: bounded-execution uncertainty was not committed",
                            )
                    return ProcessExecutionResult(
                        -1, stdout,
                        "PROCESS_TERMINATION_UNCONFIRMED: process tree remains active\n" + stderr,
                    )
                root_exited = proc.poll() is not None
                if not self._process_tree_empty(
                    process_identity,
                    process_group_id,
                    root_exited=root_exited,
                ):
                    termination_confirmed = self.kill_process_tree(
                        proc.pid, process_group_id=process_group_id, identity=process_identity,
                    )
                    if not termination_confirmed or not self._process_tree_empty(
                        process_identity,
                        process_group_id,
                        root_exited=proc.poll() is not None,
                    ):
                        retain_execution_ref[0] = True
                        if execution_capability is not None:
                            try:
                                from app.core.execution_service import record_launch_uncertain
                                recorded = record_launch_uncertain(
                                    execution_capability,
                                    pid=proc.pid,
                                    process_group_id=process_group_id,
                                    start_token=process_identity.start_token,
                                    session_id=process_identity.session_id,
                                    member_snapshot=process_identity.member_snapshot,
                                    windows_attestation=(process_identity_ref[0].windows_attestation if process_identity_ref[0] else None),
                                )
                            except Exception as uncertainty_exc:
                                logger.error(
                                    "Non-empty process-container uncertainty could not be persisted: error_type=%s",
                                    type(uncertainty_exc).__name__,
                                )
                                recorded = False
                            if not recorded:
                                return ProcessExecutionResult(
                                    -1, stdout,
                                    "PROCESS_FINALIZATION_FAILED: process-container uncertainty was not committed",
                                )
                        return ProcessExecutionResult(
                            -1, stdout,
                                "PROCESS_LAUNCH_UNCERTAIN: owned process container is not empty",
                        )
                if cancellation_requested.is_set():
                    finalization = _finish_durable(
                        "CANCELLED",
                        "EXECUTION_CANCELLED",
                        termination_status="ALREADY_EXITED" if proc.poll() is not None else "KILLED",
                    )
                    if finalization:
                        return finalization
                    return ProcessExecutionResult(
                        130,
                        stdout,
                        "PROCESS_LAUNCH_CANCELLED: cancellation was requested" + (f"\n{stderr}" if stderr else ""),
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
                return _settle_no_process(
                    "FAILED",
                    "EXECUTABLE_NOT_FOUND",
                    ProcessExecutionResult(127, "", f"Executable not found: {e}"),
                )
            except PermissionError as e:
                return _settle_no_process(
                    "EXECUTION_BLOCKED",
                    "EXECUTABLE_PERMISSION_DENIED",
                    ProcessExecutionResult(126, "", f"Permission denied: {e}"),
                )
            except Exception as e:
                termination_confirmed = True
                if proc and proc.pid:
                    if process_identity_ref[0] is None:
                        if windows_job_ref[0] is not None:
                            try:
                                termination_confirmed = bool(windows_job_ref[0].terminate())
                            except Exception:
                                termination_confirmed = False
                        else:
                            termination_confirmed = False
                    else:
                        termination_confirmed = self.kill_process_tree(
                            proc.pid,
                            process_group_id=process_group_ref[0],
                            identity=process_identity_ref[0],
                        )
                if proc is not None and not termination_confirmed:
                    retain_execution_ref[0] = True
                    if execution_capability is None:
                        return ProcessExecutionResult(
                            -1,
                            "",
                            "PROCESS_TERMINATION_UNCONFIRMED: process container remains active after post-launch exception",
                        )
                if execution_capability is not None:
                    if proc is not None:
                        # Popen succeeded but the launch handshake did not
                        # reach a durable committed state. Preserve the exact
                        # execution identity for recovery and never convert
                        # this uncertainty into an ordinary FAILED result.
                        retain_execution_ref[0] = True
                        try:
                            from app.core.execution_service import record_launch_uncertain
                            recorded = record_launch_uncertain(
                                execution_capability,
                                pid=proc.pid,
                                process_group_id=process_group_ref[0],
                                start_token=(process_identity_ref[0].start_token if process_identity_ref[0] else None),
                                session_id=(process_identity_ref[0].session_id if process_identity_ref[0] else None),
                                member_snapshot=(process_identity_ref[0].member_snapshot if process_identity_ref[0] else None),
                                windows_attestation=(process_identity_ref[0].windows_attestation if process_identity_ref[0] else None),
                            )
                        except Exception as uncertainty_exc:
                            logger.error(
                                "Post-Popen exception uncertainty could not be persisted: error_type=%s",
                                type(uncertainty_exc).__name__,
                            )
                            recorded = False
                        if not recorded:
                            return ProcessExecutionResult(
                                -1, "",
                                "PROCESS_FINALIZATION_FAILED: post-Popen exception uncertainty was not committed",
                            )
                        return ProcessExecutionResult(
                            -1, "",
                            "PROCESS_TERMINATION_UNCONFIRMED: process tree remains active"
                            if not termination_confirmed
                            else "PROCESS_LAUNCH_UNCERTAIN: post-launch exception requires recovery",
                        )
                if proc is not None:
                    return ProcessExecutionResult(
                        -1,
                        "",
                        f"PROCESS_LAUNCH_UNCERTAIN: post-launch exception requires recovery ({type(e).__name__})",
                    )
                if not _settle_durable("FAILED", "PROCESS_EXECUTION_EXCEPTION"):
                        return ProcessExecutionResult(-1, "", "PROCESS_FINALIZATION_FAILED: durable exception outcome was not committed")
                return ProcessExecutionResult(-1, "", str(e))
            finally:
                if proc and proc.pid and not retain_execution_ref[0]:
                    self._unregister_execution(proc.pid, execution_id=execution_id)
                    if windows_job is not None:
                        from app.core.windows_job import release_attestation
                        if process_identity_ref[0] and process_identity_ref[0].windows_attestation:
                            release_attestation(_windows_identity_attestation(process_identity_ref[0]).digest)
                        proc.close()
                        windows_job.close()
                elif windows_job is not None and proc is None:
                    windows_job.close()

        worker_task = asyncio.create_task(
            asyncio.to_thread(_run_sync),
            name=f"process-supervisor:{execution_id or 'non-scan'}",
        )

        def _consume_late_worker_result(task: asyncio.Task) -> None:
            try:
                task.result()
            except BaseException as exc:
                logger.error(
                    "Late process-supervisor worker failed after caller cancellation: error_type=%s",
                    type(exc).__name__,
                )

        try:
            return await asyncio.shield(worker_task)
        except asyncio.CancelledError:
            # The caller's cancellation is only a request. The worker thread
            # remains the sole owner of process-tree verification, signalling,
            # and durable settlement. In particular, this task must not signal
            # a provisional PID or turn an identity handshake race into an
            # immediate termination-uncertain result.
            cancellation_requested.set()
            try:
                worker_result = await asyncio.wait_for(
                    asyncio.shield(worker_task),
                    timeout=5.0,
                )
            except asyncio.TimeoutError:
                retain_execution_ref[0] = True
                worker_task.add_done_callback(_consume_late_worker_result)
                raise RuntimeError(
                    "PROCESS_TERMINATION_UNCONFIRMED: process supervisor worker did not settle before the cancellation deadline"
                )
            except BaseException as exc:
                if not isinstance(exc, asyncio.CancelledError):
                    raise
                retain_execution_ref[0] = True
                worker_task.add_done_callback(_consume_late_worker_result)
                raise RuntimeError(
                    "PROCESS_TERMINATION_UNCONFIRMED: process supervisor worker cancellation was not joined"
                ) from exc
            if not isinstance(worker_result, ProcessExecutionResult):
                retain_execution_ref[0] = True
                raise RuntimeError(
                    "PROCESS_TERMINATION_UNCONFIRMED: process supervisor worker returned an invalid cancellation result"
                )
            if retain_execution_ref[0] or worker_result.stderr.startswith(
                (
                    "PROCESS_LAUNCH_UNCERTAIN",
                    "PROCESS_TERMINATION_UNCONFIRMED",
                    "PROCESS_FINALIZATION_FAILED",
                )
            ):
                retain_execution_ref[0] = True
                raise RuntimeError(
                    "PROCESS_TERMINATION_UNCONFIRMED: process identity-bound termination was not confirmed"
                )
            raise


process_supervisor = ProcessSupervisor.get_instance()
