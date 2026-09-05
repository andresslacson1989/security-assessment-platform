"""
E13.3 — Adversarial Acceptance Tests for Process Ownership and Cancellation Isolation.
Validates:
- Self/host process protection (refusal to terminate os.getpid() or os.getppid()).
- Cancellation of running execution terminates child, leaves parent and sibling intact.
- Cancellation of non-existent execution fails cleanly without sending signals.
- Multi-tenant scan cancellation boundary (IDOR prevention).
- Concurrent sibling execution isolation under cancellation.
"""

import asyncio
import os
import sys
import pytest

from app.core.process_supervisor import ProcessSupervisor, process_supervisor, ProcessExecutionResult, ProcessCancellationStatus
from app.core.orchestrator import orchestrator
from app.core.models import (
    ScanJob,
    ScanStatus,
    ScanProfile,
    Target,
    TargetType,
    utc_now,
)
from app.core.db import db_manager


@pytest.mark.asyncio
async def test_self_and_parent_process_termination_protection():
    """Verify kill_process_tree strictly refuses to terminate current process or parent."""
    supervisor = ProcessSupervisor.get_instance()
    current_pid = os.getpid()
    parent_pid = os.getppid() if hasattr(os, "getppid") else None

    # Attempting to kill current pid must be safely rejected
    supervisor.kill_process_tree(current_pid)
    # Process is still alive and execution proceeds
    assert os.getpid() == current_pid

    if parent_pid:
        supervisor.kill_process_tree(parent_pid)
        assert os.getpid() == current_pid

    # Negative and PID 0/1 must also be safely ignored
    supervisor.kill_process_tree(-1)
    supervisor.kill_process_tree(0)
    supervisor.kill_process_tree(1)


@pytest.mark.asyncio
async def test_cancel_nonexistent_execution_fails_cleanly():
    """A missing execution mapping is explicitly not proof of process exit."""
    supervisor = ProcessSupervisor.get_instance()
    result = supervisor.cancel_execution("non-existent-exec-id")
    assert result.status is ProcessCancellationStatus.NOT_FOUND
    assert result.confirmed is False
    assert supervisor.cancel_pid(99999999) is False


@pytest.mark.asyncio
async def test_concurrent_sibling_execution_isolation():
    """
    Spawns two concurrent subprocess executions.
    Cancelling Execution A must terminate Process A while Process B completes successfully.
    """
    supervisor = ProcessSupervisor.get_instance()

    # Use python sleep script
    cmd_a = [sys.executable, "-c", "import time; time.sleep(10)"]
    cmd_b = [sys.executable, "-c", "import time; time.sleep(0.5); print('sibling done')"]

    exec_a_task = asyncio.create_task(
        supervisor.execute(cmd_a, timeout=10.0, execution_id="exec-sibling-a")
    )
    exec_b_task = asyncio.create_task(
        supervisor.execute(cmd_b, timeout=10.0, execution_id="exec-sibling-b")
    )

    # Allow processes time to spawn
    await asyncio.sleep(0.1)

    # Cancel execution A only
    cancelled_a = supervisor.cancel_execution("exec-sibling-a")
    assert cancelled_a.confirmed is True

    # Execution B must complete cleanly on its own
    res_b = await exec_b_task
    assert "sibling done" in res_b.stdout

    # Execution A task should finish (either via process termination or return code)
    res_a = await exec_a_task
    assert res_a.returncode != 0


@pytest.mark.asyncio
async def test_asyncio_cancellation_does_not_kill_siblings():
    """
    When an asyncio task running execute() is cancelled, only that task's spawned process
    is killed; concurrent sibling execution remains untouched.
    """
    supervisor = ProcessSupervisor.get_instance()

    cmd_a = [sys.executable, "-c", "import time; time.sleep(10)"]
    cmd_b = [sys.executable, "-c", "import time; time.sleep(0.5); print('sibling survives')"]

    task_a = asyncio.create_task(
        supervisor.execute(cmd_a, timeout=10.0, execution_id="exec-async-a")
    )
    task_b = asyncio.create_task(
        supervisor.execute(cmd_b, timeout=10.0, execution_id="exec-async-b")
    )

    await asyncio.sleep(0.1)

    # Cancel task A via asyncio
    task_a.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task_a

    # Task B must succeed unaffected
    res_b = await task_b
    assert "sibling survives" in res_b.stdout


@pytest.mark.asyncio
async def test_tenant_cancellation_isolation_in_orchestrator():
    """
    Verify orchestrator.cancel_scan respects tenant boundaries:
    A tenant cannot cancel a scan belonging to another organization.
    """
    orch = orchestrator

    # Create scan for Tenant Alpha
    job = ScanJob(
        id="scan-tenant-alpha-01",
        target=Target(name="test", type=TargetType.DOMAIN, value="example.com"),
        profile=ScanProfile.QUICK,
        organization_id="org-tenant-alpha",
        status=ScanStatus.RUNNING,
    )
    orch._active_jobs[job.id] = job

    # Attempt to cancel with Tenant Beta's organization_id -> MUST FAIL
    cancelled_by_beta = await orch.cancel_scan(job.id, organization_id="org-tenant-beta")
    assert cancelled_by_beta is False
    assert orch._active_jobs[job.id].status == ScanStatus.RUNNING

    # Attempt to cancel with Tenant Alpha's organization_id -> MUST SUCCEED
    cancelled_by_alpha = await orch.cancel_scan(job.id, organization_id="org-tenant-alpha")
    assert cancelled_by_alpha is True
    assert orch._active_jobs[job.id].status == ScanStatus.CANCELLED
    assert orch._active_jobs[job.id].completed_at is not None

    # Clean up
    orch._active_jobs.pop(job.id, None)
