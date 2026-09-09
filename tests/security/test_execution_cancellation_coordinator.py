"""Contract 03/08 tests for the single execution cancellation coordinator."""

import asyncio

import pytest


@pytest.mark.asyncio
async def test_missing_process_mapping_does_not_confirm_an_active_run():
    from app.core.execution_service import ExecutionCancellationCoordinator
    from app.core.process_supervisor import (
        ProcessCancellationResult,
        ProcessCancellationStatus,
    )

    run = {
        "execution_id": "execution-a",
        "request_id": "request-a",
        "state": "RUNNING",
        "reason_code": None,
    }

    class Database:
        def get_execution_run_for_request(self, request_id, organization_id):
            assert (request_id, organization_id) == ("request-a", "org-a")
            return dict(run)

        def revoke_execution_request(self, request_id, organization_id, actor):
            assert (request_id, organization_id, actor) == ("request-a", "org-a", "admin-a")
            return True

        def get_execution_run(self, execution_id, organization_id):
            assert (execution_id, organization_id) == ("execution-a", "org-a")
            return dict(run)

    class Supervisor:
        def cancel_execution(self, execution_id):
            return ProcessCancellationResult(
                execution_id,
                ProcessCancellationStatus.NOT_FOUND,
            )

    outcome = await ExecutionCancellationCoordinator(Database(), Supervisor()).cancel_request(
        "request-a",
        "org-a",
        actor="admin-a",
    )

    assert outcome.authority_revoked is True
    assert outcome.process_status == "NOT_FOUND"
    assert outcome.process_confirmed is False
    assert outcome.durable_terminal is False
    assert outcome.recovery_required is True
    assert outcome.confirmed is False


@pytest.mark.asyncio
async def test_pre_dispatch_revocation_is_the_only_accepted_no_process_proof():
    from app.core.execution_service import ExecutionCancellationCoordinator

    run = {
        "execution_id": "execution-a",
        "request_id": "request-a",
        "state": "REQUESTED",
        "reason_code": None,
    }
    revoked_run = {
        **run,
        "state": "CANCELLED",
        "reason_code": "EXECUTION_CANCELLED_BEFORE_DISPATCH",
    }

    class Database:
        def get_execution_run_for_request(self, request_id, organization_id):
            return dict(run)

        def revoke_execution_request(self, request_id, organization_id, actor):
            return True

        def get_execution_run(self, execution_id, organization_id):
            return dict(revoked_run)

    class Supervisor:
        def cancel_execution(self, execution_id):
            raise AssertionError("a pre-dispatch cancellation must not signal a process")

    outcome = await ExecutionCancellationCoordinator(Database(), Supervisor()).cancel_request(
        "request-a",
        "org-a",
        actor="admin-a",
    )

    assert outcome.process_status == "NOT_FOUND"
    assert outcome.process_confirmed is False
    assert outcome.durable_terminal is True
    assert outcome.reason_code == "EXECUTION_CANCELLED_BEFORE_DISPATCH"
    assert outcome.recovery_required is False
    assert outcome.confirmed is True


@pytest.mark.asyncio
async def test_coordinator_waits_for_the_owning_task_to_stop():
    from app.core.execution_service import ExecutionCancellationCoordinator

    class Database:
        def get_execution_run_for_request(self, request_id, organization_id):
            return None

        def revoke_execution_request(self, request_id, organization_id, actor):
            return True

    async def worker():
        await asyncio.sleep(60)

    task = asyncio.create_task(worker())
    outcome = await ExecutionCancellationCoordinator(Database(), object()).cancel_request(
        "request-a",
        "org-a",
        actor="admin-a",
        owning_task=task,
    )

    assert task.done()
    assert outcome.task_stopped is True
    assert outcome.confirmed is True


@pytest.mark.asyncio
async def test_unjoined_task_remains_recoverable_after_process_termination(monkeypatch):
    from app.core.execution_service import ExecutionCancellationCoordinator
    from app.core.process_supervisor import ProcessCancellationResult, ProcessCancellationStatus

    run = {
        "execution_id": "execution-a",
        "request_id": "request-a",
        "state": "RUNNING",
        "reason_code": None,
    }
    terminal_run = {
        **run,
        "state": "CANCELLED",
        "reason_code": "EXECUTION_CANCELLED",
    }

    class Database:
        def __init__(self):
            self.lookups = 0

        def get_execution_run_for_request(self, request_id, organization_id):
            return dict(run)

        def revoke_execution_request(self, request_id, organization_id, actor):
            return True

        def get_execution_run(self, execution_id, organization_id):
            self.lookups += 1
            return dict(run if self.lookups == 1 else terminal_run)

    class Supervisor:
        def cancel_execution(self, execution_id):
            return ProcessCancellationResult(execution_id, ProcessCancellationStatus.KILLED)

    async def unjoined_task(*args, **kwargs):
        return False

    monkeypatch.setattr(ExecutionCancellationCoordinator, "stop_task", staticmethod(unjoined_task))
    outcome = await ExecutionCancellationCoordinator(Database(), Supervisor()).cancel_request(
        "request-a",
        "org-a",
        actor="admin-a",
        owning_task=object(),
    )

    assert outcome.authority_revoked is True
    assert outcome.process_status == "KILLED"
    assert outcome.process_confirmed is True
    assert outcome.durable_terminal is True
    assert outcome.task_stopped is False
    assert outcome.recovery_required is True
    assert outcome.confirmed is False


@pytest.mark.asyncio
async def test_terminal_run_revoke_still_revokes_remaining_authority():
    from app.core.execution_service import ExecutionCancellationCoordinator

    class Database:
        def __init__(self):
            self.revoked = []

        def get_execution_run_for_request(self, request_id, organization_id):
            return {
                "execution_id": "execution-terminal",
                "request_id": request_id,
                "state": "SUCCEEDED",
                "reason_code": "PROCESS_TERMINALIZED",
            }

        def revoke_execution_request(self, request_id, organization_id, actor):
            self.revoked.append((request_id, organization_id, actor))
            return True

    database = Database()
    outcome = await ExecutionCancellationCoordinator(database, object()).cancel_request(
        "request-terminal",
        "org-a",
        actor="admin-a",
    )

    assert database.revoked == [("request-terminal", "org-a", "admin-a")]
    assert outcome.authority_revoked is True
    assert outcome.process_status == "ALREADY_EXITED"
    assert outcome.process_confirmed is True
    assert outcome.durable_terminal is True
    assert outcome.recovery_required is False
    assert outcome.confirmed is True


@pytest.mark.asyncio
async def test_orchestrator_does_not_publish_parent_cancelled_for_unconfirmed_child(
    monkeypatch,
):
    from app.core.execution_service import ExecutionCancellationOutcome
    from app.core.models import ScanJob, ScanProfile, ScanStatus, Target, TargetType
    from app.core.orchestrator import ScanOrchestrator

    class Coordinator:
        async def cancel_request(self, request_id, organization_id, *, actor, owning_task=None):
            return ExecutionCancellationOutcome(
                execution_id="execution-a",
                request_id=request_id,
                authority_revoked=True,
                process_status="NOT_FOUND",
                process_confirmed=False,
                durable_terminal=False,
                task_stopped=True,
                recovery_required=True,
            )

        async def stop_task(self, task, *, timeout_seconds):
            return True

    job = ScanJob(
        id="scan-cancel-pending",
        organization_id="org-a",
        authorization_request_id="parent-a",
        target=Target(name="target", type=TargetType.DOMAIN, value="example.com"),
        profile=ScanProfile.QUICK,
        status=ScanStatus.RUNNING,
    )
    orchestrator = ScanOrchestrator()
    orchestrator._cancellation_coordinator = Coordinator()
    orchestrator._active_jobs[job.id] = job

    monkeypatch.setattr(
        "app.core.orchestrator.db_manager.list_scan_execution_ids",
        lambda scan_id, organization_id: ["execution-a"],
    )
    monkeypatch.setattr(
        "app.core.orchestrator.db_manager.get_execution_run",
        lambda execution_id, organization_id: {
            "execution_id": execution_id,
            "request_id": "request-a",
            "state": "RUNNING",
        },
    )

    assert await orchestrator.cancel_scan(job.id, organization_id="org-a") is False
    assert job.status == ScanStatus.RUNNING
