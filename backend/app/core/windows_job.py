"""Checked Win32 job primitives used exclusively by ProcessSupervisor.

Creation uses JOB_LIST and HANDLE_LIST startup attributes: the kernel assigns
the suspended root to its job atomically and only the three standard streams
are inherited. No PID-tree enumeration or shell termination is used here.

Named-object reopening is retained only as a diagnostic observation primitive.
Production recovery never reattaches by name after worker loss: the
``KILL_ON_JOB_CLOSE`` contract destroys the original container and the
process-local attestation registry refuses a same-name replacement.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes as w
import os
import re
import subprocess
import threading
import time
import uuid

class JobError(OSError):
    """A kernel operation failed; callers must preserve launch uncertainty."""


class JobLaunchUncertain(JobError):
    """The kernel created a suspended job member, but stream setup failed."""

    def __init__(self, process):
        super().__init__("Windows process created but launch preparation failed")
        self.process = process


ERROR_ALREADY_EXISTS = 183
ERROR_INSUFFICIENT_BUFFER = 122
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
JOB_OBJECT_QUERY = 0x0004
JOB_OBJECT_TERMINATE = 0x0008
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_SYNCHRONIZE = 0x00100000
CREATE_SUSPENDED = 0x00000004
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_UNICODE_ENVIRONMENT = 0x00000400
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_NO_WINDOW = 0x08000000
STARTF_USESTDHANDLES = 0x00000100
STARTF_USESHOWWINDOW = 0x00000001
SW_HIDE = 0
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D

_MAX_JOB_MEMBERS = 512
_MAX_ATTESTED_JOBS = 4096

_jobs: dict[str, object] = {}
_jobs_lock = threading.RLock()


class _Limits(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
        ("flags", w.DWORD), ("min_working_set", ctypes.c_size_t),
        ("max_working_set", ctypes.c_size_t), ("active_limit", w.DWORD),
        ("affinity", ctypes.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD),
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("basic", _Limits), ("io", ctypes.c_ulonglong * 6),
        ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
        ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t),
    ]


class _Startup(ctypes.Structure):
    _fields_ = [
        ("cb", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR),
        ("title", w.LPWSTR), ("x", w.DWORD), ("y", w.DWORD),
        ("x_size", w.DWORD), ("y_size", w.DWORD), ("x_chars", w.DWORD),
        ("y_chars", w.DWORD), ("fill", w.DWORD), ("flags", w.DWORD),
        ("show", w.WORD), ("reserved_size", w.WORD), ("reserved_bytes", ctypes.c_void_p),
        ("stdin", w.HANDLE), ("stdout", w.HANDLE), ("stderr", w.HANDLE),
    ]


class _StartupEx(ctypes.Structure):
    _fields_ = [("startup", _Startup), ("attributes", ctypes.c_void_p)]


class _ProcessInfo(ctypes.Structure):
    _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]


class _Api:
    """Declare every ABI, including pointer-sized handles on 64-bit Windows."""

    def __init__(self):
        if os.name != "nt":
            raise JobError("Windows Job Objects require Windows")
        self.dll = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
            "OpenJobObjectW": ([w.DWORD, w.BOOL, w.LPCWSTR], w.HANDLE),
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "SetInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
            "QueryInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p], w.BOOL),
            "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
            "IsProcessInJob": ([w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL)], w.BOOL),
            "OpenProcess": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            "GetProcessTimes": ([w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4, w.BOOL),
            "GetExitCodeProcess": ([w.HANDLE, ctypes.POINTER(w.DWORD)], w.BOOL),
            "WaitForSingleObject": ([w.HANDLE, w.DWORD], w.DWORD),
            "ResumeThread": ([w.HANDLE], w.DWORD),
            "InitializeProcThreadAttributeList": ([ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.POINTER(ctypes.c_size_t)], w.BOOL),
            "UpdateProcThreadAttribute": ([ctypes.c_void_p, w.DWORD, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p], w.BOOL),
            "DeleteProcThreadAttributeList": ([ctypes.c_void_p], None),
            "CreateProcessW": ([w.LPCWSTR, w.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, w.BOOL, w.DWORD, ctypes.c_void_p, w.LPCWSTR, ctypes.POINTER(_StartupEx), ctypes.POINTER(_ProcessInfo)], w.BOOL),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.dll, name)
            function.argtypes, function.restype = args, result
            setattr(self, name, function)

    @staticmethod
    def check(result, operation):
        if not result:
            error = ctypes.get_last_error()
            raise JobError(error, f"{operation}: {ctypes.FormatError(error).strip()}")
        return result

    def close(self, handle):
        if handle:
            self.check(self.CloseHandle(handle), "CloseHandle")

    def start_token(self, handle):
        values = [w.FILETIME() for _ in range(4)]
        self.check(self.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)), "GetProcessTimes")
        return f"windows:{(values[0].dwHighDateTime << 32) | values[0].dwLowDateTime}"


class WindowsJob:
    """An owned, non-inheritable handle; its numeric value is never evidence.

    ``reopen=True`` is diagnostic-only. It can inspect a still-existing named
    object, but it cannot satisfy or register a durable attestation.
    """

    def __init__(self, name=None, *, reopen=False):
        self.api = _Api()
        self.lock = threading.RLock()
        self.name = name or f"Local\\CyberAssess-{uuid.uuid4().hex}{uuid.uuid4().hex}"
        if re.fullmatch(r"Local\\CyberAssess-[0-9a-f]{64}", self.name) is None:
            raise JobError("Invalid governed job name")
        self.handle = None
        # A durable attestation is bound to this process-local creation
        # capability.  A reopened handle is useful for diagnostics and native
        # lifecycle tests, but it is never eligible for an assured execution
        # binding because a recreated named object is not distinguishable from
        # the original by name alone.
        self._created_by_current_worker = not reopen
        if reopen:
            try:
                self.handle = self.api.check(
                    self.api.OpenJobObjectW(JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE, False, self.name),
                    "OpenJobObjectW",
                )
                self.verify_limits()
            except BaseException:
                self.close()
                raise
        else:
            ctypes.set_last_error(0)
            self.handle = self.api.check(self.api.CreateJobObjectW(None, self.name), "CreateJobObjectW")
            if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
                self.close()
                raise JobError("Job name already exists")
            try:
                limits = _ExtendedLimits()
                # KILL_ON_JOB_CLOSE; neither breakaway flag is ever enabled.
                limits.basic.flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                self.api.check(self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)), "SetInformationJobObject")
                self.verify_limits()
            except BaseException:
                self.close()
                raise

    def verify_limits(self):
        limits = _ExtendedLimits()
        self.api.check(self.api.QueryInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits), None), "QueryInformationJobObject(limits)")
        if limits.basic.flags != JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE:
            raise JobError("Governed job limits changed")

    def members(self):
        with self.lock:
            if not self.handle:
                raise JobError("Job handle is closed")
            self.verify_limits()
            class _Members(ctypes.Structure):
                _fields_ = [("assigned", w.DWORD), ("count", w.DWORD), ("pids", ctypes.c_size_t * _MAX_JOB_MEMBERS)]
            result = _Members()
            self.api.check(self.api.QueryInformationJobObject(self.handle, 3, ctypes.byref(result), ctypes.sizeof(result), None), "QueryInformationJobObject(members)")
            if result.assigned != result.count or result.count > _MAX_JOB_MEMBERS:
                raise JobError("Job membership exceeds verification bound")
            return tuple(int(result.pids[index]) for index in range(result.count))

    def member_identities(self):
        """Verify every live member belongs to this exact kernel job object."""
        with self.lock:
            members = self.members()
            identities = []
            for pid in members:
                handle = self.api.check(
                    self.api.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, False, pid),
                    "OpenProcess(job member)",
                )
                try:
                    member = w.BOOL()
                    self.api.check(
                        self.api.IsProcessInJob(handle, self.handle, ctypes.byref(member)),
                        "IsProcessInJob(job member)",
                    )
                    if not member.value or self.api.WaitForSingleObject(handle, 0) != WAIT_TIMEOUT:
                        raise JobError("Windows job member is not live in the exact kernel container")
                    identities.append((pid, self.api.start_token(handle)))
                finally:
                    self.api.close(handle)
            if tuple(pid for pid, _token in identities) != members:
                raise JobError("Windows job membership changed during identity verification")
            return tuple(identities)

    def verify_root(self, pid, start_token):
        """Verify a living root in this exact open kernel job object."""
        with self.lock:
            handle = self.api.check(
                self.api.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, False, pid),
                "OpenProcess(root)",
            )
            try:
                member = w.BOOL()
                self.api.check(self.api.IsProcessInJob(handle, self.handle, ctypes.byref(member)), "IsProcessInJob")
                return (
                    bool(member.value)
                    and self.api.start_token(handle) == start_token
                    and self.api.WaitForSingleObject(handle, 0) == WAIT_TIMEOUT
                    and pid in self.members()
                )
            finally:
                self.api.close(handle)

    def verify_attachment(self, attestation, *, allow_empty=True):
        """Verify the exact process-local attested job binding.

        The root is normally present and is revalidated by PID plus creation
        time. If the root has already exited, a non-empty membership query is
        still a valid fact only for the exact handle registered by the current
        worker; a same-name reopened or recreated object is not an assurance
        binding. An empty container is accepted only for that same exact local
        binding as a confirmed already-exited outcome; callers that require a
        live member must pass ``allow_empty=False``.
        """
        from datetime import datetime, timezone
        from app.core.execution_context import WindowsJobAttestation, WindowsNonScanJobAttestation

        if (
            type(attestation) not in {WindowsJobAttestation, WindowsNonScanJobAttestation}
            or attestation.verification_result != "VERIFIED"
            or attestation.expires_at <= datetime.now(timezone.utc)
        ):
            raise JobError("Windows job attestation is unverified or expired")
        with _jobs_lock:
            if _jobs.get(attestation.digest) is not self:
                raise JobError("Windows job is not the exact process-local attested binding")
        if attestation.job_identity != self.name:
            raise JobError("Windows job attestation identity mismatch")
        self.verify_limits()
        members = self.members()
        if members:
            # The named job identity is not sufficient on its own.  Every PID
            # currently reported by the kernel must be reopened, checked for
            # membership in this exact handle, and bound to its start token.
            member_identities = self.member_identities()
        else:
            member_identities = ()
        if attestation.root_process_id in members:
            root_identity = next(
                (token for pid, token in member_identities if pid == attestation.root_process_id),
                None,
            )
            if (
                root_identity != attestation.root_process_start_token
                or not self.verify_root(attestation.root_process_id, attestation.root_process_start_token)
            ):
                raise JobError("Windows root identity or membership mismatch")
            return members
        if not members and allow_empty:
            return members
        if not members:
            raise JobError("Windows job has no recoverable members")
        return members

    def terminate(self, timeout=5.0):
        with self.lock:
            self.verify_limits()
            if not self.members():
                return True
            # Refuse to terminate when the current membership cannot be fully
            # identified in the exact job.  This prevents a partial observation
            # from being reported as a confirmed container termination.
            self.member_identities()
            self.api.check(self.api.TerminateJobObject(self.handle, 130), "TerminateJobObject")
            deadline = time.monotonic() + timeout
            while True:
                if not self.members():
                    return True
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.01)

    def close(self):
        with self.lock:
            if self.handle:
                self.api.close(self.handle)
                self.handle = None


def register_attestation(attestation, job):
    """Bind a newly issued durable proof to the verified live kernel object."""
    from datetime import datetime, timezone
    from app.core.execution_context import WindowsJobAttestation, WindowsNonScanJobAttestation
    if (
        type(attestation) not in {WindowsJobAttestation, WindowsNonScanJobAttestation}
        or type(job) is not WindowsJob
        or not job._created_by_current_worker
        or job.name != attestation.job_identity
        or attestation.verification_result != "VERIFIED"
        or attestation.expires_at <= datetime.now(timezone.utc)
    ):
        raise JobError("Windows job attestation type, state, or identity mismatch")
    if not job.verify_root(attestation.root_process_id, attestation.root_process_start_token):
        raise JobError("Suspended root identity verification failed")
    with _jobs_lock:
        if attestation.digest in _jobs or len(_jobs) >= _MAX_ATTESTED_JOBS:
            raise JobError("Windows job binding duplicate or capacity exceeded")
        _jobs[attestation.digest] = job


def attested_job(attestation, *, for_recovery=False):
    """Return the exact local job object after durable-binding checks.

    A missing local mapping is an intentional recovery block. This function
    never opens a named object by identity after worker restart because a
    recreated same-name object is not the original kernel container.
    """
    from datetime import datetime, timezone
    from app.core.execution_context import WindowsJobAttestation, WindowsNonScanJobAttestation
    if (
        type(attestation) not in {WindowsJobAttestation, WindowsNonScanJobAttestation}
        or attestation.verification_result != "VERIFIED"
        or attestation.expires_at <= datetime.now(timezone.utc)
    ):
        raise JobError("Windows job attestation is unverified or expired")
    with _jobs_lock:
        job = _jobs.get(attestation.digest)
        if job is not None:
            if (
                type(job) is not WindowsJob
                or not job._created_by_current_worker
                or job.name != attestation.job_identity
            ):
                raise JobError("Windows job binding mismatch")
            if for_recovery:
                job.verify_attachment(attestation)
            else:
                job.verify_limits()
            return job
        # KILL_ON_JOB_CLOSE intentionally makes worker loss destroy the
        # container.  A new worker therefore cannot safely reopen by name: a
        # missing process-local binding is an operator-visible recovery block,
        # never permission to attach to a same-name object.
        raise JobError("Windows job binding is unavailable after worker restart")


def require_empty_job(ownership, *, worker_identity=None):
    from app.core.execution_context import validate_windows_ownership
    attestation = validate_windows_ownership(ownership, worker_identity=worker_identity)
    if attested_job(attestation).members():
        raise JobError("Windows job still has active members")
    return attestation


def release_attestation(digest):
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise JobError("Windows attestation digest is invalid")
    with _jobs_lock:
        job = _jobs.pop(digest, None)
        if job:
            job.close()


class WindowsJobProcess:
    """Small Popen-compatible process wrapper retaining the suspended thread.

    The caller receives the created process before identity/DB operations, so
    every post-creation failure can be durably classified as uncertain.
    """

    def __init__(self, command, *, job, cwd=None, env=None):
        import msvcrt

        if type(job) is not WindowsJob or not job.handle:
            raise JobError("Windows governed launch requires an open governed job")
        if (
            not command
            or any(not isinstance(item, str) or not item or "\0" in item for item in command)
            or not os.path.isabs(command[0])
        ):
            raise ValueError("Windows governed launch requires an absolute executable and NUL-free argv")
        if cwd is not None:
            cwd = os.fspath(cwd)
            if not isinstance(cwd, str) or "\0" in cwd:
                raise ValueError("Invalid Windows working directory")
        self.job, self.api, self.args = job, job.api, command
        self.pid, self.process_handle, self.thread_handle = 0, None, None
        self.returncode = None
        self.stdout = self.stderr = None
        descriptors = []
        attributes = None
        initialized = False
        try:
            out_read, out_write = os.pipe()
            descriptors.extend((out_read, out_write))
            err_read, err_write = os.pipe()
            descriptors.extend((err_read, err_write))
            null_fd = os.open(os.devnull, os.O_RDONLY)
            descriptors.append(null_fd)
            child_fds = (null_fd, out_write, err_write)
            for fd in child_fds:
                os.set_inheritable(fd, True)
            handles = (w.HANDLE * 3)(*(msvcrt.get_osfhandle(fd) for fd in child_fds))
            jobs = (w.HANDLE * 1)(job.handle)
            size = ctypes.c_size_t()
            sized = self.api.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
            if sized or not size.value or ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER:
                raise JobError("Unable to size process startup attributes")
            attributes = ctypes.create_string_buffer(size.value)
            self.api.check(self.api.InitializeProcThreadAttributeList(attributes, 2, 0, ctypes.byref(size)), "InitializeProcThreadAttributeList")
            initialized = True
            for key, value in ((PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles), (PROC_THREAD_ATTRIBUTE_JOB_LIST, jobs)):
                self.api.check(self.api.UpdateProcThreadAttribute(attributes, 0, key, value, ctypes.sizeof(value), None, None), "UpdateProcThreadAttribute")
            startup = _StartupEx()
            startup.startup.cb = ctypes.sizeof(startup)
            startup.startup.flags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
            startup.startup.show = SW_HIDE
            startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = handles
            startup.attributes = ctypes.cast(attributes, ctypes.c_void_p)
            info = _ProcessInfo()
            environment = None
            if env is not None:
                if (
                    any(
                        not isinstance(key, str)
                        or not isinstance(value, str)
                        or not key
                        or "=" in key
                        or "\0" in key
                        or "\0" in value
                        for key, value in env.items()
                    )
                    or len({key.upper() for key in env}) != len(env)
                ):
                    raise ValueError("Invalid Windows environment")
                environment = ctypes.create_unicode_buffer("\0".join(f"{key}={value}" for key, value in sorted(env.items(), key=lambda item: item[0].upper())) + "\0\0")
            self.api.check(self.api.CreateProcessW(
                command[0], ctypes.create_unicode_buffer(subprocess.list2cmdline(command)),
                None, None, True,
                EXTENDED_STARTUPINFO_PRESENT
                | CREATE_UNICODE_ENVIRONMENT
                | CREATE_SUSPENDED
                | CREATE_NEW_PROCESS_GROUP
                | CREATE_NO_WINDOW,
                environment, cwd, ctypes.byref(startup), ctypes.byref(info),
            ), "CreateProcessW(JOB_LIST)")
            self.pid, self.process_handle, self.thread_handle = info.pid, info.process, info.thread
            self.stdout = os.fdopen(out_read, "rb", buffering=0)
            descriptors.remove(out_read)
            self.stderr = os.fdopen(err_read, "rb", buffering=0)
            descriptors.remove(err_read)
        except BaseException:
            # If pipe wrapping fails after CreateProcess, the owned job still
            # contains a suspended process. Preserve that fact for the caller.
            if self.pid:
                for stream_name in ("stdout", "stderr"):
                    stream = getattr(self, stream_name)
                    if stream is not None:
                        stream.close()
                        setattr(self, stream_name, None)
                raise JobLaunchUncertain(self) from None
            raise
        finally:
            if initialized:
                self.api.DeleteProcThreadAttributeList(attributes)
            for fd in descriptors:
                os.close(fd)

    def start_token(self):
        return self.api.start_token(self.process_handle)

    def resume(self):
        with self.job.lock:
            if not self.thread_handle:
                raise JobError("Root thread already resumed or closed")
            previous = self.api.ResumeThread(self.thread_handle)
            if previous != 1:
                raise JobError("Unexpected root thread suspend count")
            self.api.close(self.thread_handle)
            self.thread_handle = None

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        result = self.api.WaitForSingleObject(self.process_handle, 0)
        if result == WAIT_TIMEOUT:
            return None
        if result != WAIT_OBJECT_0:
            raise JobError("WaitForSingleObject failed")
        code = w.DWORD()
        self.api.check(self.api.GetExitCodeProcess(self.process_handle, ctypes.byref(code)), "GetExitCodeProcess")
        self.returncode = code.value
        return self.returncode

    def wait(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.poll() is None:
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(self.args, timeout)
            time.sleep(0.01)
        return self.returncode

    def close(self):
        for stream in (self.stdout, self.stderr):
            if stream:
                stream.close()
        for name in ("thread_handle", "process_handle"):
            handle = getattr(self, name)
            if handle:
                self.api.close(handle)
                setattr(self, name, None)
