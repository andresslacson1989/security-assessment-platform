"""Ensure every external-tool launch remains behind ProcessSupervisor."""

from __future__ import annotations

import ast
import asyncio
from dataclasses import replace
import json
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import pytest

from app.core.process_supervisor import (
    CredentialEnvironmentHandoff,
    CredentialExecutionContext,
    ProcessCancellationStatus,
    ProcessExecutionStatus,
    ProcessMemberIdentity,
    ProcessIdentity,
    ProcessSupervisor,
    VerifiedEgressProxy,
)
from app.core.tool_operation_policy import OPERATION_POLICY_REVISION
from app.core.execution_service import issue_non_scan_execution_context


@pytest.mark.skipif(os.name != "nt", reason="Requires the Windows kernel Job Object API")
def test_windows_job_atomic_assignment_and_descendant_termination(tmp_path):
    from app.core.windows_job import WindowsJob, WindowsJobProcess

    marker = tmp_path / "child.pid"
    child = "import time; time.sleep(60)"
    root = (
        "import subprocess,sys,time; from pathlib import Path; "
        f"p=subprocess.Popen([sys.executable,'-c',{child!r}]); "
        f"Path({str(marker)!r}).write_text(str(p.pid)); time.sleep(0.4)"
    )
    job = WindowsJob()
    process = None
    try:
        process = WindowsJobProcess([sys.executable, "-c", root], job=job, env=dict(os.environ))
        assert job.members() == (process.pid,)
        assert not marker.exists(), "suspended root must not execute before durable registration"
        assert job.verify_root(process.pid, process.start_token())
        assert not job.verify_root(process.pid, "windows:1")
        process.resume()
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.exists()
        child_pid = int(marker.read_text())
        assert child_pid in job.members()
        process.wait(timeout=10)
        assert child_pid in job.members(), "root exit must not hide the surviving child"
        assert job.terminate()
        assert job.members() == ()
    finally:
        job.terminate()
        if process:
            process.wait(timeout=5)
            process.close()
        job.close()


@pytest.mark.skipif(os.name != "nt", reason="Requires the Windows kernel Job Object API")
def test_windows_job_restart_attachment_and_name_collision():
    from app.core.windows_job import JobError, WindowsJob, WindowsJobProcess

    job = WindowsJob()
    process = None
    reopened = None
    try:
        process = WindowsJobProcess([sys.executable, "-c", "import time;time.sleep(60)"], job=job)
        token = process.start_token()
        process.resume()
        reopened = WindowsJob(job.name, reopen=True)
        assert reopened.verify_root(process.pid, token)
        with pytest.raises(JobError, match="already exists"):
            WindowsJob(job.name)
        assert reopened.terminate()
        assert job.members() == ()
    finally:
        job.terminate()
        if process:
            process.wait(timeout=5)
            process.close()
        if reopened:
            reopened.close()
        job.close()
    with pytest.raises(JobError):
        WindowsJob(job.name, reopen=True)


@pytest.mark.skipif(os.name != "nt", reason="Requires the Windows kernel Job Object API")
def test_windows_job_recovery_attachment_accepts_only_attested_surviving_members(tmp_path):
    """A root-exit survivor is recoverable only through its exact job proof."""
    from app.core.execution_context import WindowsJobAttestation, canonical_windows_job_attestation_digest, windows_job_name
    from app.core.windows_job import WindowsJob, WindowsJobProcess, attested_job, register_attestation, release_attestation

    execution_id = f"windows-recovery-{uuid.uuid4().hex}"
    organization_id = "org-windows-recovery"
    worker_identity = "worker-windows-recovery"
    worker_generation = "generation-windows-recovery"
    job_nonce = uuid.uuid4().hex
    job = WindowsJob(
        windows_job_name(
            execution_id,
            organization_id,
            worker_identity,
            worker_generation,
            job_nonce,
        )
    )
    marker = tmp_path / "surviving-child.pid"
    child_code = "import time; time.sleep(60)"
    root_code = (
        "import subprocess,sys,time; from pathlib import Path; "
        f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
        f"Path({str(marker)!r}).write_text(str(p.pid)); time.sleep(.2)"
    )
    process = None
    reopened = None
    attestation = None
    try:
        process = WindowsJobProcess(
            [sys.executable, "-c", root_code],
            job=job,
            env=dict(os.environ),
        )
        initial_members = job.members()
        captured = datetime.now(timezone.utc)
        values = {
            "schema_version": "windows-job-attestation-v1",
            "proof_type": "JOB_OBJECT",
            "job_identity": job.name,
            "job_nonce": job_nonce,
            "execution_id": execution_id,
            "organization_id": organization_id,
            "worker_identity": worker_identity,
            "worker_generation": worker_generation,
            "root_process_id": process.pid,
            "root_process_start_token": process.start_token(),
            "initial_members": initial_members,
            "captured_at": captured,
            "expires_at": captured + timedelta(minutes=5),
            "verification_result": "VERIFIED",
        }
        attestation = WindowsJobAttestation(
            **values,
            digest=canonical_windows_job_attestation_digest(values),
        )
        register_attestation(attestation, job)
        assert initial_members == (process.pid,)
        process.resume()
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.exists()
        child_pid = int(marker.read_text())
        process.wait(timeout=10)
        assert child_pid in job.members(), "root exit must not hide a live job member"

        reopened = WindowsJob(job.name, reopen=True)
        assert child_pid in tuple(pid for pid, _token in reopened.member_identities())
        with pytest.raises(OSError, match="exact process-local attested binding"):
            reopened.verify_attachment(attestation)
        assert child_pid in attested_job(attestation, for_recovery=True).members()
        assert job.terminate()
        assert job.members() == ()
    finally:
        if reopened:
            try:
                reopened.terminate()
            except OSError:
                pass
            reopened.close()
        try:
            job.terminate()
        except OSError:
            pass
        if process:
            try:
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
            process.close()
        if attestation:
            try:
                release_attestation(attestation.digest)
            except OSError:
                pass


@pytest.mark.asyncio
async def test_process_supervisor_rejects_ambiguous_governed_and_non_scan_capabilities():
    result = await ProcessSupervisor().execute(
        [sys.executable, "-c", "raise SystemExit(99)"],
        execution_capability=object(),
        non_scan_context=issue_non_scan_execution_context("observation:ambiguous-capability"),
    )

    assert result.returncode == 126
    assert result.execution_status is ProcessExecutionStatus.SECURITY_REJECTED
    assert "both governed and non-scan capabilities" in result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Requires the Windows kernel Job Object API")
def test_windows_worker_crash_kill_on_close_blocks_durable_reattachment(tmp_path):
    """Worker loss kills members and prevents same-name durable reattachment."""
    from app.core.execution_context import WindowsJobAttestation, canonical_windows_job_attestation_digest, windows_job_name
    from app.core.execution_service import load_durable_process_identity
    from app.core.windows_job import JobError, WindowsJob, attested_job

    execution_id = f"windows-loader-{uuid.uuid4().hex}"
    organization_id = "org-windows-loader"
    worker_identity = "worker-windows-loader"
    worker_generation = "generation-windows-loader"
    job_nonce = uuid.uuid4().hex
    job_name = windows_job_name(
        execution_id,
        organization_id,
        worker_identity,
        worker_generation,
        job_nonce,
    )
    worker = None
    recreated = None
    attestation = None

    helper_code = f"""
import importlib.util
import json
import os
import sys
import time

spec = importlib.util.spec_from_file_location("windows_job_worker", {str(Path(__file__).resolve().parents[2] / "backend" / "app" / "core" / "windows_job.py")!r})
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
assert spec.loader is not None
spec.loader.exec_module(module)
job = module.WindowsJob(sys.argv[1])
process = module.WindowsJobProcess([sys.executable, "-c", "import time; time.sleep(120)"], job=job, env=dict(os.environ))
print(json.dumps({{"job_name": job.name, "pid": process.pid, "start_token": process.start_token()}}), flush=True)
process.resume()
while True:
    time.sleep(1)
"""

    class DurableRestartDatabase:
        def __init__(self, run, ownership):
            self.run = run
            self.ownership = ownership

        def get_execution_run(self, requested_execution_id, requested_organization_id):
            assert (requested_execution_id, requested_organization_id) == (execution_id, organization_id)
            return self.run

        def get_process_ownership(self, requested_execution_id, requested_organization_id):
            assert (requested_execution_id, requested_organization_id) == (execution_id, organization_id)
            return self.ownership

    try:
        worker = subprocess.Popen(
            [sys.executable, "-c", helper_code, job_name],
            cwd=str(Path(__file__).resolve().parents[2]),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        line = worker.stdout.readline() if worker.stdout is not None else ""
        launch = json.loads(line)
        assert launch["job_name"] == job_name
        pid = int(launch["pid"])
        assert ProcessSupervisor._pid_exists(pid)
        captured = datetime.now(timezone.utc)
        values = {
            "schema_version": "windows-job-attestation-v1",
            "proof_type": "JOB_OBJECT",
            "job_identity": job_name,
            "job_nonce": job_nonce,
            "execution_id": execution_id,
            "organization_id": organization_id,
            "worker_identity": worker_identity,
            "worker_generation": worker_generation,
            "root_process_id": pid,
            "root_process_start_token": launch["start_token"],
            "initial_members": (pid,),
            "captured_at": captured,
            "expires_at": captured + timedelta(minutes=5),
            "verification_result": "VERIFIED",
        }
        attestation = WindowsJobAttestation(
            **values,
            digest=canonical_windows_job_attestation_digest(values),
        )
        ownership = {
            "container_type": "WINDOWS_JOB",
            "container_identity": attestation.job_identity,
            "execution_id": execution_id,
            "organization_id": organization_id,
            "root_process_id": pid,
            "root_process_start_token": attestation.root_process_start_token,
            "process_group_id": None,
            "session_id": None,
            "worker_generation": worker_generation,
            "launch_commit_state": "COMMITTED",
            "ownership_state": "EXTERNAL_PROCESS_GOVERNED",
            "correlation_id": f"corr-{execution_id}",
            "identity_attestation": attestation.model_dump_json(),
        }
        database = DurableRestartDatabase(
            {
                "execution_id": execution_id,
                "organization_id": organization_id,
                "state": "RUNNING",
                "worker_identity": worker_identity,
                "worker_generation": worker_generation,
                "process_id": None,
                "process_group_id": None,
                "correlation_id": f"corr-{execution_id}",
            },
            ownership,
        )

        # A real worker process exit closes its only job handle.  KILL_ON_CLOSE
        # must terminate the child and remove the named object.
        worker.terminate()
        worker.wait(timeout=10)
        deadline = time.monotonic() + 10
        while ProcessSupervisor._pid_exists(pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not ProcessSupervisor._pid_exists(pid)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                reopened = WindowsJob(job_name, reopen=True)
            except JobError:
                break
            else:
                reopened.close()
                time.sleep(0.02)
        else:
            raise AssertionError("named Windows job remained open after worker exit")

        # A same-name object can now be recreated, but it is a new empty
        # container and must never satisfy the old durable attestation.
        recreated = WindowsJob(job_name)
        assert recreated.members() == ()
        with pytest.raises(JobError, match="exact process-local attested binding"):
            recreated.verify_attachment(attestation)
        with pytest.raises(JobError, match="unavailable after worker restart"):
            attested_job(attestation, for_recovery=True)
        loaded = load_durable_process_identity(database, execution_id, organization_id)
        assert loaded is None
    finally:
        if recreated:
            try:
                recreated.terminate()
            except OSError:
                pass
            recreated.close()
        if worker:
            if worker.poll() is None:
                worker.terminate()
            try:
                worker.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                worker.kill()
                worker.wait(timeout=10)
            if worker.stdout is not None:
                worker.stdout.close()
            if worker.stderr is not None:
                worker.stderr.close()


def test_expired_windows_attestation_stays_recovery_blocked_without_refresh():
    """Expiry fences loader/attachment; changing expiry cannot create a job binding."""
    from app.core.execution_context import (
        ExecutionContextExpiredError,
        WindowsJobAttestation,
        canonical_windows_job_attestation_digest,
        validate_windows_ownership,
        windows_job_name,
    )
    from app.core.windows_job import JobError, attested_job
    from app.core.execution_service import load_durable_process_identity

    execution_id = f"windows-expired-{uuid.uuid4().hex}"
    organization_id = "org-windows-expired"
    worker_identity = "worker-windows-expired"
    worker_generation = "generation-windows-expired"
    job_nonce = uuid.uuid4().hex
    captured = datetime.now(timezone.utc) - timedelta(minutes=10)
    values = {
        "schema_version": "windows-job-attestation-v1", "proof_type": "JOB_OBJECT",
        "job_identity": windows_job_name(execution_id, organization_id, worker_identity, worker_generation, job_nonce),
        "job_nonce": job_nonce, "execution_id": execution_id, "organization_id": organization_id,
        "worker_identity": worker_identity, "worker_generation": worker_generation,
        "root_process_id": 789, "root_process_start_token": "windows:789", "initial_members": (789,),
        "captured_at": captured, "expires_at": captured + timedelta(minutes=5),
        "verification_result": "VERIFIED",
    }
    attestation = WindowsJobAttestation(
        **values,
        digest=canonical_windows_job_attestation_digest(values),
    )
    ownership = {
        "container_type": "WINDOWS_JOB", "container_identity": attestation.job_identity,
        "execution_id": execution_id, "organization_id": organization_id,
        "root_process_id": attestation.root_process_id,
        "root_process_start_token": attestation.root_process_start_token,
        "process_group_id": None, "session_id": None,
        "worker_generation": worker_generation,
        "identity_attestation": attestation.model_dump_json(),
    }

    with pytest.raises(ExecutionContextExpiredError):
        validate_windows_ownership(ownership, worker_identity=worker_identity)
    assert validate_windows_ownership(
        ownership, worker_identity=worker_identity, historical=True,
    ) == attestation
    with pytest.raises(JobError, match="unverified or expired"):
        attested_job(attestation, for_recovery=True)

    class ExpiredDatabase:
        def get_execution_run(self, requested_execution_id, requested_organization_id):
            assert (requested_execution_id, requested_organization_id) == (execution_id, organization_id)
            return {
                "execution_id": execution_id, "organization_id": organization_id,
                "state": "RUNNING", "worker_identity": worker_identity,
                "worker_generation": worker_generation, "process_id": None,
                "process_group_id": None, "correlation_id": f"corr-{execution_id}",
            }

        def get_process_ownership(self, requested_execution_id, requested_organization_id):
            assert (requested_execution_id, requested_organization_id) == (execution_id, organization_id)
            return {
                **ownership,
                "ownership_state": "EXTERNAL_PROCESS_GOVERNED",
                "launch_commit_state": "COMMITTED",
                "correlation_id": f"corr-{execution_id}",
            }

    assert load_durable_process_identity(ExpiredDatabase(), execution_id, organization_id) is None

    refreshed_values = {**values, "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)}
    refreshed = WindowsJobAttestation(
        **refreshed_values,
        digest=canonical_windows_job_attestation_digest(refreshed_values),
    )
    with pytest.raises(JobError, match="unavailable after worker restart"):
        attested_job(refreshed, for_recovery=True)


@pytest.mark.skipif(os.name != "nt", reason="Requires the Windows kernel Job Object API")
def test_windows_supervisor_cancellation_requires_attested_identity():
    """Windows cancellation terminates the job and rejects PID-only recovery."""
    from app.core.execution_context import WindowsJobAttestation, canonical_windows_job_attestation_digest, windows_job_name
    from app.core.windows_job import WindowsJob, WindowsJobProcess, register_attestation, release_attestation

    execution_id = f"windows-cancel-{uuid.uuid4().hex}"
    organization_id = "org-windows-cancel"
    worker_identity = "worker-windows-cancel"
    worker_generation = "generation-windows-cancel"
    job_nonce = uuid.uuid4().hex
    job = WindowsJob(
        windows_job_name(
            execution_id,
            organization_id,
            worker_identity,
            worker_generation,
            job_nonce,
        )
    )
    process = None
    reopened = None
    attestation = None
    unbound_job = None
    unbound_process = None
    try:
        process = WindowsJobProcess(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            job=job,
            env=dict(os.environ),
        )
        captured = datetime.now(timezone.utc)
        values = {
            "schema_version": "windows-job-attestation-v1",
            "proof_type": "JOB_OBJECT",
            "job_identity": job.name,
            "job_nonce": job_nonce,
            "execution_id": execution_id,
            "organization_id": organization_id,
            "worker_identity": worker_identity,
            "worker_generation": worker_generation,
            "root_process_id": process.pid,
            "root_process_start_token": process.start_token(),
            "initial_members": job.members(),
            "captured_at": captured,
            "expires_at": captured + timedelta(minutes=5),
            "verification_result": "VERIFIED",
        }
        attestation = WindowsJobAttestation(
            **values,
            digest=canonical_windows_job_attestation_digest(values),
        )
        register_attestation(attestation, job)
        process.resume()
        supervisor = ProcessSupervisor()
        identity = ProcessIdentity(
            pid=process.pid,
            process_group_id=None,
            start_token=attestation.root_process_start_token,
            windows_attestation=attestation.model_dump_json(),
        )
        supervisor._register_execution(process.pid, execution_id=execution_id, identity=identity)
        reopened = WindowsJob(job.name, reopen=True)
        tampered = replace(identity, start_token="windows:1")
        assert supervisor.cancel_execution(execution_id, process_identity=tampered).status is ProcessCancellationStatus.RECOVERY_BLOCKED

        cancelled = supervisor.cancel_execution(execution_id, process_identity=identity)
        assert cancelled.status is ProcessCancellationStatus.KILLED
        assert reopened.members() == ()
        assert supervisor.cancel_pid(process.pid).status is ProcessCancellationStatus.NOT_FOUND

        unbound_execution_id = f"windows-unbound-{uuid.uuid4().hex}"
        unbound_job = WindowsJob(
            windows_job_name(
                unbound_execution_id,
                organization_id,
                worker_identity,
                worker_generation,
                uuid.uuid4().hex,
            )
        )
        unbound_process = WindowsJobProcess(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            job=unbound_job,
            env=dict(os.environ),
        )
        assert supervisor.cancel_pid(unbound_process.pid).status is ProcessCancellationStatus.RECOVERY_BLOCKED
    finally:
        if attestation:
            try:
                release_attestation(attestation.digest)
            except OSError:
                pass
        if unbound_job:
            try:
                unbound_job.terminate()
            except OSError:
                pass
        if unbound_process:
            try:
                unbound_process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
            unbound_process.close()
        if reopened:
            reopened.close()
        try:
            job.terminate()
        except OSError:
            pass
        if process:
            try:
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
            process.close()


def _terminate_owned_test_session(session_id: int | None) -> None:
    """Clean up only the disposable session created by the current test."""
    if not session_id:
        return
    for member in ProcessSupervisor._posix_session_member_identities(session_id) or []:
        pid, _start_token, _pgid = member
        if pid in {os.getpid(), os.getppid()}:
            continue
        try:
            os.kill(pid, 9)
        except (ProcessLookupError, PermissionError):
            continue
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and ProcessSupervisor._process_session_exists(session_id):
        time.sleep(0.02)


FORBIDDEN_IMPORTS = {"subprocess", "asyncio.subprocess"}
FORBIDDEN_CALLS = {
    ("subprocess", "Popen"),
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("os", "system"),
    ("asyncio", "create_subprocess_exec"),
    ("asyncio", "create_subprocess_shell"),
}


def test_adapters_and_engines_have_no_direct_process_launches():
    repository_root = Path(__file__).resolve().parents[2]
    source_roots = (
        repository_root / "backend" / "app" / "adapters",
        repository_root / "backend" / "app" / "engines",
    )
    violations = []
    for source_root in source_roots:
        for path in source_root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in FORBIDDEN_IMPORTS:
                            violations.append(f"{path}:{node.lineno}: import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if module in FORBIDDEN_IMPORTS:
                        violations.append(f"{path}:{node.lineno}: from {module} import ...")
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        call = (node.func.value.id, node.func.attr)
                        if call in FORBIDDEN_CALLS:
                            violations.append(f"{path}:{node.lineno}: call {call[0]}.{call[1]}")

    assert violations == [], "Direct process launch detected outside ProcessSupervisor: " + "; ".join(violations)


@pytest.mark.asyncio
async def test_supervisor_child_observes_only_reviewed_environment(monkeypatch):
    """Exercise the production launch boundary and inspect the child environment."""
    monkeypatch.delenv("OPERATING_MODE", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("ENTERPRISE_EGRESS_ENFORCEMENT_REQUIRED", raising=False)
    monkeypatch.setenv("HTTP_PROXY", "http://ambient.invalid:8080")
    monkeypatch.setenv("SCANNER_EGRESS_PROXY", "http://scanner.example:3128")

    dangerous = {
        "API_KEY": "secret",
        "AUTH_TOKEN": "secret",
        "JWT_SECRET": "secret",
        "DATABASE_URL": "postgres://secret",
        "LD_PRELOAD": "/tmp/inject.so",
        "LD_LIBRARY_PATH": "/tmp/inject",
        "PYTHONPATH": "/tmp/inject",
        "PYTHONHOME": "/tmp/python",
        "NODE_OPTIONS": "--require /tmp/inject.js",
        "HTTP_PROXY": "http://caller.invalid:8080",
        "HTTPS_PROXY": "http://caller.invalid:8080",
        "ALL_PROXY": "http://caller.invalid:8080",
        "ARBITRARY_CALLER_VARIABLE": "must-not-cross",
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        "GOTOOLCHAIN": "local",
    }
    child_code = "import json, os; print(json.dumps(dict(os.environ), sort_keys=True))"
    result = await ProcessSupervisor.get_instance().execute(
        [sys.executable, "-c", child_code],
        env=dangerous,
        timeout=10.0,
        max_output_bytes=1024 * 1024,
        non_scan_context=issue_non_scan_execution_context("observation:test-reviewed-environment"),
    )

    assert result.execution_status is ProcessExecutionStatus.COMPLETED
    observed = json.loads(result.stdout)
    for key in dangerous:
        if key in {
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
            "GIT_CONFIG_NOSYSTEM", "GIT_TERMINAL_PROMPT",
            "NPM_CONFIG_IGNORE_SCRIPTS", "GOTOOLCHAIN",
        }:
            continue
        if key == "LANG":
            assert observed[key] == "C.UTF-8"
        else:
            assert key not in observed
    for key in ("LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME", "NODE_OPTIONS"):
        assert key not in observed
    assert observed["GIT_CONFIG_NOSYSTEM"] == "1"
    assert observed["GIT_TERMINAL_PROMPT"] == "0"
    assert observed["NPM_CONFIG_IGNORE_SCRIPTS"] == "true"
    assert observed["GOTOOLCHAIN"] == "local"
    assert "HTTP_PROXY" not in observed
    assert "HTTPS_PROXY" not in observed
    assert "ALL_PROXY" not in observed


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object lifecycle is covered by the native assurance job")
async def test_windows_non_scan_launch_uses_attested_job_boundary(monkeypatch):
    """Installer/observation launches cannot use ordinary Windows Popen."""
    import app.core.process_supervisor as process_supervisor_module

    def forbidden_popen(*_args, **_kwargs):
        raise AssertionError("Windows non-scan launch bypassed the Job Object boundary")

    monkeypatch.setattr(process_supervisor_module.subprocess, "Popen", forbidden_popen)
    result = await ProcessSupervisor().execute(
        [sys.executable, "-c", "print('windows-non-scan-job', flush=True)"],
        timeout=10.0,
        non_scan_context=issue_non_scan_execution_context("observation:windows-job-boundary"),
    )
    assert result.execution_status is ProcessExecutionStatus.COMPLETED
    assert result.stdout.strip() == "windows-non-scan-job"


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "nt", reason="Requires the Windows kernel Job Object API")
async def test_windows_non_scan_timeout_output_cancellation_and_exception_are_typed(monkeypatch, tmp_path):
    """Every post-creation non-scan outcome stays inside the exact Job Object."""
    supervisor = ProcessSupervisor()

    timeout_marker = tmp_path / "timeout.pid"
    timeout_code = (
        "from pathlib import Path; import os,time; "
        f"Path({str(timeout_marker)!r}).write_text(str(os.getpid())); "
        "time.sleep(60)"
    )
    timed_out = await supervisor.execute(
        [sys.executable, "-c", timeout_code],
        # The child must have a runner-safe window to start and create its
        # readiness marker before the Job Object timeout is enforced.
        timeout=5.0,
        non_scan_context=issue_non_scan_execution_context("observation:windows-timeout"),
    )
    assert timed_out.execution_status is ProcessExecutionStatus.TIMED_OUT
    deadline = time.monotonic() + 10
    while not timeout_marker.exists() and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
    assert timeout_marker.exists(), "timed-out child did not publish its readiness marker"
    timeout_pid = int(timeout_marker.read_text())
    assert not ProcessSupervisor._pid_exists(timeout_pid)

    output_limited = await supervisor.execute(
        [sys.executable, "-c", "print('x' * 100000, flush=True)"],
        timeout=10.0,
        max_output_bytes=1024,
        non_scan_context=issue_non_scan_execution_context("observation:windows-output-limit"),
    )
    assert output_limited.execution_status is ProcessExecutionStatus.OUTPUT_LIMIT_EXCEEDED

    cancellation_marker = tmp_path / "cancellation.pid"
    cancellation_code = (
        "from pathlib import Path; import os,time; "
        f"Path({str(cancellation_marker)!r}).write_text(str(os.getpid())); "
        "time.sleep(60)"
    )
    cancellation_task = asyncio.create_task(
        supervisor.execute(
            [sys.executable, "-c", cancellation_code],
            timeout=30.0,
            non_scan_context=issue_non_scan_execution_context("observation:windows-cancellation"),
        )
    )
    deadline = time.monotonic() + 10
    while not cancellation_marker.exists() and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
    assert cancellation_marker.exists()
    cancellation_pid = int(cancellation_marker.read_text())
    cancellation_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancellation_task
    deadline = time.monotonic() + 10
    while ProcessSupervisor._pid_exists(cancellation_pid) and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
    assert not ProcessSupervisor._pid_exists(cancellation_pid)

    from app.core.windows_job import WindowsJobProcess

    launched = {}

    def fail_resume(process):
        launched["pid"] = process.pid
        raise RuntimeError("test post-launch resume failure")

    monkeypatch.setattr(WindowsJobProcess, "resume", fail_resume)
    post_launch_failure = await supervisor.execute(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        timeout=10.0,
        non_scan_context=issue_non_scan_execution_context("observation:windows-post-launch-exception"),
    )
    assert post_launch_failure.execution_status is ProcessExecutionStatus.LAUNCH_UNCERTAIN
    assert not ProcessSupervisor._pid_exists(launched["pid"])


@pytest.mark.asyncio
@pytest.mark.skipif(os.name == "nt", reason="POSIX identity-capture path is not the Windows Job Object path")
async def test_identity_capture_failure_after_popen_is_typed_uncertain_and_recoverable(monkeypatch):
    """A real child created before identity capture cannot become ordinary failure."""
    supervisor = ProcessSupervisor()
    launched: list[subprocess.Popen] = []
    original_popen = subprocess.Popen

    def capture_popen(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        launched.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", capture_popen)
    monkeypatch.setattr(supervisor, "_capture_process_identity", lambda *_args: None)

    try:
        result = await supervisor.execute(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=10.0,
            non_scan_context=issue_non_scan_execution_context(
                "observation:identity-capture-failure"
            ),
        )

        assert result.execution_status is ProcessExecutionStatus.LAUNCH_UNCERTAIN
        assert result.stderr.startswith("PROCESS_LAUNCH_UNCERTAIN")
        assert launched
        assert launched[0].poll() is None
    finally:
        for process in launched:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            supervisor._unregister_pid(process.pid)


@pytest.mark.asyncio
async def test_typed_credential_handoff_cannot_release_credentials_without_verifier():
    """Metadata alone must never authorize credential release to a child."""
    handoff = CredentialEnvironmentHandoff(
        organization_id="org-test",
        asset_id="asset-test",
        provider="aws",
        authorization_decision_id="decision-test",
        request_id="request-test",
        operation_policy_revision=OPERATION_POLICY_REVISION,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        credentials={
            "AWS_ACCESS_KEY_ID": "AKIA_TEST",
            "AWS_SECRET_ACCESS_KEY": "secret-test",
            "AWS_SESSION_TOKEN": "session-test",
        },
    )
    context = CredentialExecutionContext(
        organization_id="org-test",
        asset_id="asset-test",
        provider="aws",
        authorization_decision_id="decision-test",
        request_id="request-test",
        operation_policy_revision=OPERATION_POLICY_REVISION,
    )
    child_code = "import json, os; print(json.dumps(dict(os.environ), sort_keys=True))"
    result = await ProcessSupervisor.get_instance().execute(
        [sys.executable, "-c", child_code],
        env={
            "AWS_ACCESS_KEY_ID": "caller-value",
            "AWS_SECRET_ACCESS_KEY": "caller-value",
            "DATABASE_URL": "caller-value",
        },
        credential_handoff=handoff,
        credential_context=context,
        timeout=10.0,
        max_output_bytes=1024 * 1024,
    )

    assert result.execution_status is ProcessExecutionStatus.SECURITY_REJECTED
    assert result.returncode == 126
    assert result.stderr.startswith("PROCESS_LAUNCH_REJECTED_SECURITY")


def test_typed_credential_handoff_rejects_caller_defined_keys_and_is_immutable():
    """Provider policy, not the caller, owns credential keys and material."""
    handoff = CredentialEnvironmentHandoff(
        organization_id="org-test",
        asset_id="asset-test",
        provider="aws",
        authorization_decision_id="decision-test",
        request_id="request-test",
        operation_policy_revision=OPERATION_POLICY_REVISION,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        credentials={"LD_PRELOAD": "/tmp/inject.so"},
    )
    with pytest.raises(ValueError):
        handoff.materialize()
    with pytest.raises(TypeError):
        handoff.credentials["AWS_ACCESS_KEY_ID"] = "mutated"


@pytest.mark.asyncio
async def test_unknown_operation_policy_revision_is_rejected():
    handoff = CredentialEnvironmentHandoff(
        organization_id="org-test",
        asset_id="asset-test",
        provider="aws",
        authorization_decision_id="decision-test",
        request_id="request-test",
        operation_policy_revision="fake-revision",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        credentials={"AWS_ACCESS_KEY_ID": "id", "AWS_SECRET_ACCESS_KEY": "secret"},
    )
    context = CredentialExecutionContext(
        organization_id="org-test",
        asset_id="asset-test",
        provider="aws",
        authorization_decision_id="decision-test",
        request_id="request-test",
        operation_policy_revision="fake-revision",
    )
    result = await ProcessSupervisor.get_instance().execute(
        [sys.executable, "-c", "raise SystemExit(99)"],
        credential_handoff=handoff,
        credential_context=context,
    )
    assert result.execution_status is ProcessExecutionStatus.SECURITY_REJECTED


def test_approved_environment_values_are_validated():
    with pytest.raises(ValueError):
        ProcessSupervisor.sanitize_environment({"NMAPDIR": "..\\outside"})
    with pytest.raises(ValueError):
        ProcessSupervisor.sanitize_environment({"GOTOOLCHAIN": "attacker"})


@pytest.mark.asyncio
async def test_invalid_egress_capability_is_typed_security_rejection():
    invalid_proxy = VerifiedEgressProxy(
        proxy_url="https://proxy.example.test",
        worker_identity="worker-1",
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        verified_by="policy-service",
    )

    result = await ProcessSupervisor.get_instance().execute(
        [sys.executable, "-c", "raise SystemExit(99)"],
        scanner_egress_proxy=invalid_proxy,
    )

    assert result.execution_status is ProcessExecutionStatus.SECURITY_REJECTED
    assert result.returncode == 126
    assert "governed or non-scan capability" in result.stderr


def test_caller_cannot_override_supervisor_baseline(monkeypatch):
    """Caller env may not replace process-resolution or runtime directories."""
    for key in ("PATH", "SYSTEMROOT", "TEMP", "HOME", "TMPDIR"):
        monkeypatch.setenv(key, f"supervisor-{key.lower()}")
    sanitized = ProcessSupervisor.sanitize_environment({
        "PATH": "caller-controlled",
        "SYSTEMROOT": "caller-controlled",
        "TEMP": "caller-controlled",
        "HOME": "caller-controlled",
        "TMPDIR": "caller-controlled",
    })
    for key in ("PATH", "SYSTEMROOT", "TEMP", "HOME", "TMPDIR"):
        assert sanitized[key] == f"supervisor-{key.lower()}"


def test_direct_caller_environment_inputs_are_explicit():
    """Prevent callers from reintroducing ambient environment wholesale."""
    repository_root = Path(__file__).resolve().parents[2]
    caller_files = (
        repository_root / "backend/app/engines/code_sast/git_history_scanner.py",
        repository_root / "backend/app/core/binary_resolver.py",
        repository_root / "backend/app/installers/github_release_installer.py",
        repository_root / "backend/app/installers/nmap_artifact_installer.py",
        repository_root / "backend/app/installers/npm_installer.py",
        repository_root / "backend/app/installers/source_build_installer.py",
        repository_root / "backend/app/installers/system_installer.py",
        repository_root / "backend/app/installers/pip_installer.py",
        repository_root / "backend/app/adapters/base_adapter.py",
        repository_root / "backend/app/adapters/prowler_adapter.py",
    )
    for path in caller_files:
        source = path.read_text(encoding="utf-8")
        assert "{**os.environ" not in source
        assert "os.environ.items()" not in source
    source_build = (repository_root / "backend/app/installers/source_build_installer.py").read_text(encoding="utf-8")
    assert 'env = {"HOME": temp, "PATH": os.environ.get("PATH", "")}' not in source_build


@pytest.mark.skipif(os.name == "nt", reason="POSIX session identity proof is not implemented on Windows")
def test_fresh_supervisor_uses_persisted_identity_after_worker_restart() -> None:
    """A new supervisor may cancel only the exact persisted process tree."""
    root = None
    identity = None
    try:
        root_code = (
            "import subprocess,sys,time; "
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
            "print(child.pid, flush=True); time.sleep(30)"
        )
        root = subprocess.Popen(
            [sys.executable, "-c", root_code],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
        child_line = root.stdout.readline() if root.stdout is not None else ""
        assert child_line.strip().isdigit()
        child_pid = int(child_line.strip())
        identity = ProcessSupervisor._capture_process_identity(root.pid, root.pid)
        assert identity is not None
        assert identity.session_id == os.getsid(root.pid)

        restarted_supervisor = ProcessSupervisor()
        forged_identity = replace(
            identity,
            start_token=identity.start_token.rsplit(":", 1)[0] + ":999999999999",
        )
        rejected = restarted_supervisor.cancel_execution(
            "execution-restart-proof",
            process_identity=forged_identity,
        )
        assert rejected.status is ProcessCancellationStatus.RECOVERY_BLOCKED
        assert root.poll() is None
        assert ProcessSupervisor._pid_exists(child_pid)

        cancelled = restarted_supervisor.cancel_execution(
            "execution-restart-proof",
            process_identity=identity,
        )
        assert cancelled.confirmed is True
        root.wait(timeout=5)
        assert not ProcessSupervisor._pid_exists(root.pid)
        assert not ProcessSupervisor._pid_exists(child_pid)
        assert not ProcessSupervisor._process_group_exists(identity.process_group_id)
    finally:
        if root is not None:
            if root.poll() is None:
                if identity is not None:
                    ProcessSupervisor().cancel_execution(
                        "execution-restart-proof-cleanup",
                        process_identity=identity,
                    )
                try:
                    root.kill()
                except OSError:
                    pass
            try:
                root.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            if root.stdout is not None:
                root.stdout.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX session identity proof is not implemented on Windows")
def test_launch_handshake_captures_descendant_created_after_initial_identity_sample(monkeypatch) -> None:
    """The production handshake includes startup descendants created after its first sample."""
    root = None
    identity = None
    try:
        root_code = (
            "import subprocess,sys,time; "
            "print('root-ready', flush=True); time.sleep(0.05); "
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
            "print(child.pid, flush=True); time.sleep(30)"
        )
        root = subprocess.Popen(
            [sys.executable, "-c", root_code],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
        assert root.stdout is not None
        assert root.stdout.readline().strip() == "root-ready"
        initial = ProcessSupervisor._capture_process_identity(root.pid, root.pid)
        assert initial is not None

        monkeypatch.setattr(ProcessSupervisor, "_LAUNCH_HANDSHAKE_MAX_SECONDS", 0.5)
        monkeypatch.setattr(ProcessSupervisor, "_LAUNCH_HANDSHAKE_STABLE_SECONDS", 0.15)
        identity = ProcessSupervisor()._capture_stable_process_identity(root.pid, root.pid)
        assert identity is not None
        child_line = root.stdout.readline()
        assert child_line.strip().isdigit()
        child_pid = int(child_line.strip())
        assert any(member.pid == child_pid for member in identity.member_snapshot)
        assert any(member.pid == root.pid for member in identity.member_snapshot)
    finally:
        if root is not None:
            if root.poll() is None:
                if identity is not None:
                    ProcessSupervisor().cancel_execution(
                        "execution-startup-descendant-cleanup",
                        process_identity=identity,
                    )
                try:
                    root.kill()
                except OSError:
                    pass
            try:
                root.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            if root.stdout is not None:
                root.stdout.close()


@pytest.mark.asyncio
@pytest.mark.skipif(os.name == "nt", reason="POSIX session identity proof is not implemented on Windows")
async def test_execute_uses_stabilized_launch_identity_for_late_descendant() -> None:
    """The actual execute path owns and closes a descendant created after Popen."""
    root_code = (
        "import subprocess,sys,time; "
        "time.sleep(0.05); "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
        "print(child.pid, flush=True); time.sleep(0.25)"
    )
    result = await ProcessSupervisor().execute(
        [sys.executable, "-c", root_code],
        timeout=5.0,
        non_scan_context=issue_non_scan_execution_context(
            "observation:stabilized-launch-descendant"
        ),
    )
    assert result.returncode == 0
    child_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    assert child_lines and child_lines[-1].isdigit()
    assert not ProcessSupervisor._pid_exists(int(child_lines[-1]))


@pytest.mark.skipif(os.name == "nt", reason="POSIX session identity proof is not implemented on Windows")
def test_root_exit_with_multiple_descendants_recovers_from_attested_snapshot() -> None:
    """A fully attested dead root is safely recovered through its member snapshot."""
    root = None
    identity = None
    child_pids: list[int] = []
    try:
        root_code = (
            "import subprocess,sys,time; "
            "children=[subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']) for _ in range(2)]; "
            "print(' '.join(str(child.pid) for child in children), flush=True); "
            "time.sleep(1)"
        )
        root = subprocess.Popen(
            [sys.executable, "-c", root_code],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
        child_line = root.stdout.readline() if root.stdout is not None else ""
        child_pids = [int(value) for value in child_line.split()]
        assert len(child_pids) == 2
        identity = ProcessSupervisor._capture_process_identity(root.pid, root.pid)
        assert identity is not None
        root.wait(timeout=5)
        assert not ProcessSupervisor._pid_exists(root.pid)
        assert any(ProcessSupervisor._pid_exists(pid) for pid in child_pids)
        assert ProcessSupervisor._process_group_exists(identity.process_group_id)
        assert ProcessSupervisor._process_session_exists(identity.session_id)

        cancelled = ProcessSupervisor().cancel_execution(
            "execution-root-exited-multi-child",
            process_identity=identity,
        )
        assert cancelled.confirmed is True
        assert not any(ProcessSupervisor._pid_exists(pid) for pid in child_pids)
        assert not ProcessSupervisor._process_group_exists(identity.process_group_id)
        assert not ProcessSupervisor._process_session_exists(identity.session_id)
    finally:
        _terminate_owned_test_session(identity.session_id if identity is not None else None)
        if root is not None and root.poll() is None:
            if identity is not None:
                ProcessSupervisor().cancel_execution(
                    "execution-root-exited-multi-child-cleanup",
                    process_identity=identity,
                )
            try:
                root.kill()
            except OSError:
                pass
            try:
                root.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if root is not None and root.stdout is not None:
            root.stdout.close()


def test_root_exit_rejects_member_created_after_attested_snapshot(monkeypatch) -> None:
    """Post-root recovery cannot admit a member absent from the prior snapshot."""
    import app.core.process_supervisor as process_supervisor_module

    previous = ProcessIdentity(
        pid=4100,
        process_group_id=4100,
        start_token="posix:boot:root",
        session_id=4100,
        member_snapshot=(
            ProcessMemberIdentity(4100, 4100, 4100, "posix:boot:root"),
            ProcessMemberIdentity(4101, 4100, 4100, "posix:boot:child"),
        ),
    )
    monkeypatch.setattr(process_supervisor_module.os, "name", "posix")
    monkeypatch.setattr(process_supervisor_module.os, "getpid", lambda: 9000)
    monkeypatch.setattr(process_supervisor_module.os, "getppid", lambda: 9001)
    monkeypatch.setattr(process_supervisor_module, "_read_posix_start_token", lambda _pid: None)
    monkeypatch.setattr(
        ProcessSupervisor,
        "_posix_session_member_identities",
        staticmethod(
            lambda _session_id: [
                (4102, "posix:boot:late", 4100),
                (4101, "posix:boot:child", 4100),
            ]
        ),
    )

    assert ProcessSupervisor._capture_posix_identity_after_root_exit(previous) is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX session identity proof is not implemented on Windows")
def test_root_exit_rejects_descendant_created_after_root_exit(tmp_path) -> None:
    """A late session member cannot become an authorized recovery target."""
    root = None
    identity = None
    session_id = None
    child_pid = None
    late_pid = None
    child_marker = tmp_path / "attested-child.pid"
    ready_marker = tmp_path / "attested-child.ready"
    exit_gate = tmp_path / "root.exit"
    late_marker = tmp_path / "late-descendant.pid"
    try:
        child_code = (
            "import os,subprocess,sys,time\n"
            "from pathlib import Path\n"
            "root_pid=int(sys.argv[1])\n"
            "ready_marker=sys.argv[2]\n"
            "late_marker=sys.argv[3]\n"
            "Path(ready_marker).write_text('ready', encoding='ascii')\n"
            "while os.getppid() == root_pid:\n"
            "    time.sleep(0.01)\n"
            "late=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\n"
            "Path(late_marker).write_text(str(late.pid), encoding='ascii')\n"
            "time.sleep(30)\n"
        )
        root_code = (
            "import os,subprocess,sys,time\n"
            "from pathlib import Path\n"
            f"child=subprocess.Popen([sys.executable,'-c',{child_code!r},str(os.getpid()),"
            f"{str(ready_marker)!r},{str(late_marker)!r}])\n"
            f"Path({str(child_marker)!r}).write_text(str(child.pid), encoding='ascii')\n"
            f"while not Path({str(exit_gate)!r}).exists():\n"
            "    time.sleep(0.01)\n"
        )
        root = subprocess.Popen(
            [sys.executable, "-c", root_code],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        session_id = os.getsid(root.pid)
        deadline = time.monotonic() + 5
        while not child_marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert child_marker.exists(), "root did not publish the child identity"
        child_pid = int(child_marker.read_text(encoding="ascii"))

        deadline = time.monotonic() + 5
        while not ready_marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready_marker.exists(), "attested child did not publish readiness"
        assert not late_marker.exists(), "late descendant was created before root exit"

        identity = ProcessSupervisor._capture_process_identity(root.pid, root.pid)
        assert identity is not None
        previous_pairs = {
            (member.pid, member.start_token)
            for member in identity.member_snapshot
        }
        assert (root.pid, identity.start_token) in previous_pairs
        assert (child_pid, next(
            member.start_token
            for member in identity.member_snapshot
            if member.pid == child_pid
        )) in previous_pairs

        exit_gate.write_text("release", encoding="ascii")
        root.wait(timeout=5)
        assert not ProcessSupervisor._pid_exists(root.pid)

        deadline = time.monotonic() + 5
        while not late_marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert late_marker.exists(), "surviving child did not publish its late descendant"
        late_pid = int(late_marker.read_text(encoding="ascii"))
        assert ProcessSupervisor._pid_exists(child_pid)
        assert ProcessSupervisor._pid_exists(late_pid)
        current_members = ProcessSupervisor._posix_session_member_identities(session_id)
        assert current_members is not None
        assert (child_pid, next(
            start_token
            for member_pid, start_token, _member_pgid in current_members
            if member_pid == child_pid
        )) in previous_pairs
        assert any(member_pid == late_pid for member_pid, _token, _pgid in current_members)
        assert not any(
            member_pid == late_pid and (member_pid, start_token) in previous_pairs
            for member_pid, start_token, _member_pgid in current_members
        )

        cancelled = ProcessSupervisor().cancel_execution(
            "execution-root-exited-late-member",
            process_identity=identity,
        )
        assert cancelled.status is ProcessCancellationStatus.RECOVERY_BLOCKED
        assert cancelled.confirmed is False
        # The late member must still be alive: this assertion proves recovery
        # was blocked by the untrusted newcomer, rather than passing because
        # cleanup happened to kill it.
        assert ProcessSupervisor._pid_exists(child_pid)
        assert ProcessSupervisor._pid_exists(late_pid)
    finally:
        _terminate_owned_test_session(session_id)
        if root is not None:
            try:
                root.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass


@pytest.mark.skipif(os.name == "nt", reason="POSIX session identity proof is not implemented on Windows")
def test_root_exit_with_descendant_in_new_group_recovers_from_attested_snapshot() -> None:
    """A fully attested session member remains recoverable after changing PGID."""
    root = None
    identity = None
    try:
        child_code = (
            "import os,time; os.setpgid(0,0); "
            "print(os.getpgrp(), flush=True); time.sleep(30)"
        )
        root_code = (
            "import subprocess,sys,time; "
            f"child=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
            "print(child.pid, flush=True); time.sleep(1)"
        )
        root = subprocess.Popen(
            [sys.executable, "-c", root_code],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
        child_line = root.stdout.readline() if root.stdout is not None else ""
        assert child_line.strip().isdigit()
        child_pid = int(child_line.strip())
        identity = ProcessSupervisor._capture_process_identity(root.pid, root.pid)
        assert identity is not None
        root.wait(timeout=5)
        assert not ProcessSupervisor._pid_exists(root.pid)
        assert ProcessSupervisor._pid_exists(child_pid)
        assert ProcessSupervisor._process_session_exists(identity.session_id)
        assert not ProcessSupervisor._process_tree_empty(
            identity,
            identity.process_group_id,
            root_exited=True,
        )

        cancelled = ProcessSupervisor().cancel_execution(
            "execution-root-exited-pgid-escape",
            process_identity=identity,
        )
        assert cancelled.confirmed is True
        # A killed grandchild may remain as a zombie until its reaper collects
        # it.  Session emptiness is the authoritative live-process assertion.
        assert not ProcessSupervisor._process_session_exists(identity.session_id)
    finally:
        _terminate_owned_test_session(identity.session_id if identity is not None else None)
        if root is not None and root.poll() is None:
            if identity is not None:
                ProcessSupervisor().cancel_execution(
                    "execution-root-exited-pgid-escape-cleanup",
                    process_identity=identity,
                )
            try:
                root.kill()
            except OSError:
                pass
            try:
                root.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if root is not None and root.stdout is not None:
            root.stdout.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX session identity proof is not implemented on Windows")
def test_session_member_created_during_cancellation_blocks_unproven_recovery() -> None:
    """A membership race fails closed when root ownership can no longer be proven."""
    root = None
    identity = None
    try:
        child_code = (
            "import os,subprocess,sys,time\n"
            "os.setpgid(0,0)\n"
            "for _ in range(16):\n"
            "    subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\n"
            "    time.sleep(.05)\n"
            "time.sleep(30)"
        )
        root_code = (
            "import subprocess,sys,time; "
            f"child=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
            "print(child.pid, flush=True); time.sleep(.2)"
        )
        root = subprocess.Popen(
            [sys.executable, "-c", root_code],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
        child_line = root.stdout.readline() if root.stdout is not None else ""
        assert child_line.strip().isdigit()
        identity = ProcessSupervisor._capture_process_identity(root.pid, root.pid)
        assert identity is not None
        root.wait(timeout=5)

        cancelled = ProcessSupervisor().cancel_execution(
            "execution-session-membership-race",
            process_identity=identity,
        )
        assert cancelled.status is ProcessCancellationStatus.RECOVERY_BLOCKED
    finally:
        _terminate_owned_test_session(identity.session_id if identity is not None else None)
        if root is not None and root.poll() is None:
            try:
                root.kill()
            except OSError:
                pass
            try:
                root.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if root is not None and root.stdout is not None:
            root.stdout.close()


def test_session_emptiness_ignores_zombie_members_but_keeps_live_members(monkeypatch) -> None:
    """A reaped process cannot keep a governed session open."""
    import app.core.process_supervisor as process_supervisor_module

    class Completed:
        returncode = 0
        stdout = "10 42 Z\n11 42 S\n"

    monkeypatch.setattr(process_supervisor_module.os, "name", "posix")
    monkeypatch.setattr(
        process_supervisor_module.subprocess,
        "run",
        lambda *args, **kwargs: Completed(),
    )
    assert ProcessSupervisor._process_session_exists(42) is True


    class ZombieOnly:
        returncode = 0
        stdout = "10 42 Z\n"

    monkeypatch.setattr(
        process_supervisor_module.subprocess,
        "run",
        lambda *args, **kwargs: ZombieOnly(),
    )
    assert ProcessSupervisor._process_session_exists(42) is False


def test_group_identity_requires_complete_fresh_member_identity(monkeypatch) -> None:
    """PGID/SID numbers alone cannot authorize recovery after root exit."""
    identity = ProcessIdentity(4100, 4100, "posix:boot:root", 4100)
    monkeypatch.setattr(
        ProcessSupervisor,
        "_posix_session_member_identities",
        lambda _session_id: [(4101, "posix:boot:foreign", 4100)],
    )
    monkeypatch.setattr(ProcessSupervisor, "_pid_exists", staticmethod(lambda _pid: False))
    monkeypatch.setattr(
        ProcessSupervisor,
        "_capture_process_identity",
        staticmethod(lambda pid, pgid: ProcessIdentity(pid, pgid, "posix:boot:actual", 4100)),
    )
    assert ProcessSupervisor._process_group_identity_matches(identity) is False
    monkeypatch.setattr(ProcessSupervisor, "_posix_session_member_identities", staticmethod(lambda _sid: None))
    assert ProcessSupervisor._process_group_identity_matches(identity) is False


def test_windows_process_tree_recovery_is_explicitly_fail_closed(monkeypatch) -> None:
    """A Windows recovery request without a typed job identity is blocked."""
    import app.core.process_supervisor as supervisor_module

    monkeypatch.setattr(supervisor_module.os, "name", "nt")
    monkeypatch.setattr(supervisor_module.sys, "platform", "win32")
    assert ProcessSupervisor.kill_process_tree(4100) is False
