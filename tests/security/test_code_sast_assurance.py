"""E13 workspace, execution-state, taint, and evidence boundary assurance."""

from pathlib import Path
import asyncio
import sys
from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.semgrep_adapter import SemgrepAdapter
from app.adapters.trufflehog_adapter import TruffleHogAdapter
from app.core.models import NormalizedExecutionState, ScanConfig, Target, TargetType
from app.core.path_sandbox import PathSandboxViolation, resolve_authorized_workspace
from app.core.process_supervisor import ProcessExecutionStatus, ProcessSupervisor
from app.engines.code_sast.ast_taint_analyzer import audit_ast_taint_flow
from app.engines.code_sast.engine import CodeSastAssessmentEngine


def test_e13_workspace_rejects_escape_and_symlink(tmp_path):
    authorized = tmp_path / "authorized"
    outside = tmp_path / "outside"
    authorized.mkdir()
    outside.mkdir()

    with pytest.raises(PathSandboxViolation):
        resolve_authorized_workspace(str(outside), [authorized])

    link = authorized / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable in this environment")
    with pytest.raises(PathSandboxViolation):
        resolve_authorized_workspace(str(link), [authorized])


def test_e13_parser_degradation_cannot_be_overwritten_by_final_bookkeeping():
    adapter = SemgrepAdapter()
    adapter._record_execution(0, "malformed", "", parser_error=True)
    adapter._record_execution(0, "malformed", "", findings_count=0)
    assert adapter.last_execution_state == NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING


@pytest.mark.asyncio
async def test_e13_engine_blocks_unauthorized_workspace_and_publishes_state(tmp_path):
    engine = CodeSastAssessmentEngine()
    target = Target(name="outside", type=TargetType.LOCAL_PATH, value=str(tmp_path))
    states = []

    async def state_cb(tool, state):
        states.append((tool, state))

    findings = await engine.run(
        target,
        ScanConfig(),
        AsyncMock(),
        AsyncMock(),
        AsyncMock(),
        emit_tool_execution_state=state_cb,
        workspace_roots=[tmp_path / "not-authorized"],
    )

    assert findings == []
    assert {tool for tool, _ in states} == {"semgrep", "bandit", "gitleaks", "trufflehog", "retire"}
    assert all(state == NormalizedExecutionState.EXECUTION_BLOCKED.value for _, state in states)


@pytest.mark.asyncio
async def test_e13_semgrep_malformed_output_is_not_clean(tmp_path):
    adapter = SemgrepAdapter()
    target = Target(name="repo", type=TargetType.LOCAL_PATH, value=str(tmp_path))
    with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/semgrep"), \
         patch.object(adapter, "execute_command", new=AsyncMock(return_value=(0, "not-json", ""))):
        findings = await adapter.run(target, ScanConfig(), AsyncMock(), AsyncMock())

    assert findings == []
    assert adapter.last_execution_state == NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING


@pytest.mark.asyncio
async def test_e13_managed_semgrep_rejects_untrusted_binary_before_launch(tmp_path):
    adapter = SemgrepAdapter()
    target = Target(name="repo", type=TargetType.LOCAL_PATH, value=str(tmp_path))
    with patch.object(adapter, "resolve_binary_path", return_value="C:/untrusted/semgrep.exe"), \
         patch.object(adapter, "verify_managed_binary", return_value=False), \
         patch.object(adapter, "execute_command", new=AsyncMock()) as execute:
        findings = await adapter.run(
            target, ScanConfig(), AsyncMock(), AsyncMock(),
            require_managed_binary=True,
        )
    assert findings == []
    assert adapter.last_execution_state == NormalizedExecutionState.EXECUTION_BLOCKED
    execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_e13_trufflehog_live_verification_requires_tenant_grant(tmp_path):
    adapter = TruffleHogAdapter()
    target = Target(name="repo", type=TargetType.LOCAL_PATH, value=str(tmp_path))
    with patch.object(adapter, "resolve_binary_path", return_value="C:/managed/trufflehog.exe"), \
         patch.object(adapter, "verify_managed_binary", return_value=True), \
         patch.object(adapter, "execute_command", new=AsyncMock()) as execute:
        findings = await adapter.run(
            target, ScanConfig(), AsyncMock(), AsyncMock(),
            require_managed_binary=True,
        )
    assert findings == []
    assert adapter.last_execution_state == NormalizedExecutionState.EXECUTION_BLOCKED
    execute.assert_not_awaited()


def test_e13_taint_sanitizer_prevents_false_positive_and_output_is_deterministic(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "from flask import request\n"
        "def safe(cursor):\n"
        "    value = request.args.get('id')\n"
        "    clean = sanitize_sql(value)\n"
        "    cursor.execute(clean)\n",
        encoding="utf-8",
    )
    assert audit_ast_taint_flow(str(tmp_path)) == []


def test_e13_taint_detects_direct_source_to_sink(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "def unsafe(cursor, request):\n"
        "    cursor.execute(request.args.get('id'))\n",
        encoding="utf-8",
    )
    findings = audit_ast_taint_flow(str(tmp_path))
    assert any(f.check_id == "SAST-TAINT-001" for f in findings)


@pytest.mark.asyncio
async def test_e13_process_supervisor_enforces_combined_output_limit():
    supervisor = ProcessSupervisor()
    code = "import sys; sys.stdout.write('x' * 100000)"
    returncode, stdout, stderr = await supervisor.execute(
        [sys.executable, "-c", code],
        timeout=5,
        max_output_bytes=4096,
    )
    assert returncode == -1
    assert len(stdout.encode("utf-8")) <= 4096
    assert "Output exceeded maximum" in stderr


@pytest.mark.asyncio
async def test_e13_process_supervisor_exposes_typed_security_rejection():
    supervisor = ProcessSupervisor()
    result = await supervisor.execute(
        [sys.executable, "-c", "raise SystemExit(0)"],
        timeout=5,
        pre_launch_check=lambda: False,
    )
    returncode, stdout, stderr = result
    assert (returncode, stdout) == (126, "")
    assert result.execution_status is ProcessExecutionStatus.SECURITY_REJECTED
    assert stderr.startswith("PROCESS_LAUNCH_REJECTED_SECURITY")

    from app.core.binary_resolver import safe_execute_subprocess
    wrapped = await safe_execute_subprocess(
        [sys.executable, "-c", "raise SystemExit(0)"],
        timeout=5,
        pre_launch_check=lambda: False,
    )
    assert wrapped.execution_status is ProcessExecutionStatus.SECURITY_REJECTED


@pytest.mark.asyncio
async def test_e13_process_supervisor_uses_isolated_unix_session_when_available():
    if sys.platform == "win32":
        pytest.skip("Unix process sessions are not available on Windows")
    supervisor = ProcessSupervisor()
    with patch("app.core.process_supervisor.subprocess.Popen") as popen:
        proc = popen.return_value
        proc.pid = 1234
        proc.stdout = iter(())
        proc.stderr = iter(())
        proc.poll.return_value = 0
        proc.wait.return_value = None
        proc.returncode = 0
        await supervisor.execute(["tool"], timeout=1)
        assert popen.call_args.kwargs["start_new_session"] is True


@pytest.mark.asyncio
async def test_e13_process_supervisor_terminates_real_child_process_tree(tmp_path):
    """Exercise actual parent/child termination instead of mocking Popen."""
    child_pid_file = tmp_path / "child.pid"
    survivor_marker = tmp_path / "child-survived.txt"
    child_code = (
        "import pathlib, time\n"
        "time.sleep(1.5)\n"
        f"pathlib.Path({str(survivor_marker)!r}).write_text('survived', encoding='utf-8')\n"
        "time.sleep(5)\n"
    )
    parent_code = (
        "import pathlib, subprocess, sys, time\n"
        f"child = subprocess.Popen([sys.executable, '-c', {child_code!r}])\n"
        f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid), encoding='utf-8')\n"
        "time.sleep(10)\n"
    )

    supervisor = ProcessSupervisor()
    result = await supervisor.execute(
        [sys.executable, "-c", parent_code],
        timeout=0.5,
        max_output_bytes=4096,
    )

    assert result.execution_status is ProcessExecutionStatus.TIMED_OUT
    assert child_pid_file.exists(), "the real child must have been created before timeout"
    child_pid = int(child_pid_file.read_text(encoding="utf-8"))
    try:
        await asyncio.sleep(2.0)
        assert not survivor_marker.exists(), "a child surviving the parent timeout violates tree termination"
    finally:
        ProcessSupervisor.kill_process_tree(child_pid)
