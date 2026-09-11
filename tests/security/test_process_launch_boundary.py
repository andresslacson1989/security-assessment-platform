"""Ensure every external-tool launch remains behind ProcessSupervisor."""

from __future__ import annotations

import ast
from dataclasses import replace
import json
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from app.core.process_supervisor import (
    CredentialEnvironmentHandoff,
    CredentialExecutionContext,
    ProcessCancellationStatus,
    ProcessExecutionStatus,
    ProcessIdentity,
    ProcessSupervisor,
    VerifiedEgressProxy,
)
from app.core.tool_operation_policy import OPERATION_POLICY_REVISION
from app.core.execution_service import issue_non_scan_execution_context


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
    """Windows cannot claim containment until the Job Object boundary exists."""
    import app.core.process_supervisor as supervisor_module

    monkeypatch.setattr(supervisor_module.sys, "platform", "win32")
    assert ProcessSupervisor.kill_process_tree(4100) is False
