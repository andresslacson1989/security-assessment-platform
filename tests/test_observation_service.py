import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.core.observation_service import BackendObservationService, ObservationState


@pytest.mark.asyncio
async def test_refresh_once_is_single_flight(monkeypatch):
    calls = 0

    async def fake_capabilities(**kwargs):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.02)

    class FakeManager:
        @classmethod
        def get_instance(cls):
            return cls()

        async def get_all_tools_info(self, **kwargs):
            nonlocal calls
            calls += 1
            await asyncio.sleep(0.02)

    monkeypatch.setattr("app.core.observation_service.get_cached_system_capabilities", fake_capabilities)
    monkeypatch.setattr("app.core.observation_service.ToolInstallationManager", FakeManager)
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    results = await asyncio.gather(service.refresh_once(), service.refresh_once())

    assert sum(results) == 1
    assert calls == 2
    assert service.state.last_completed_at is not None
    assert service.state.last_error is None


@pytest.mark.asyncio
async def test_refresh_failure_is_recorded_and_does_not_raise(monkeypatch):
    async def failed_capabilities(**kwargs):
        raise RuntimeError("probe unavailable")

    monkeypatch.setattr("app.core.observation_service.get_cached_system_capabilities", failed_capabilities)
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    assert await service.refresh_once() is False
    assert service.state.last_completed_at is None
    assert "RuntimeError" in service.state.last_error


@pytest.mark.asyncio
async def test_service_stops_and_awaits_task(monkeypatch):
    async def successful_refresh(**kwargs):
        return None

    class FakeManager:
        @classmethod
        def get_instance(cls):
            return cls()

        async def get_all_tools_info(self, **kwargs):
            return []

    monkeypatch.setattr("app.core.observation_service.get_cached_system_capabilities", successful_refresh)
    monkeypatch.setattr("app.core.observation_service.ToolInstallationManager", FakeManager)
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)
    task = service.start()
    await asyncio.sleep(0)
    await service.stop()

    assert task.done()
    assert not service.running


@pytest.mark.asyncio
async def test_reaper_terminates_and_closes_exact_execution_identity(monkeypatch):
    from app.core import db as db_module
    from app.core import process_supervisor as supervisor_module

    candidates = [{
        "execution_id": "run-revoked",
        "organization_id": "org-a",
        "process_id": 4321,
        "terminal_state": "CANCELLED",
        "reason_code": "EXECUTION_CANCELLED",
    }]
    cancelled = []
    closed = []

    class FakeDatabase:
        def list_execution_recovery_candidates(self):
            return candidates

        def reap_execution_dispatch(self, execution_id, organization_id, **kwargs):
            closed.append((execution_id, organization_id, kwargs))
            return True

    class FakeSupervisor:
        def cancel_execution(self, execution_id):
            cancelled.append(execution_id)
            return True

    monkeypatch.setattr(db_module, "db_manager", FakeDatabase())
    monkeypatch.setattr(supervisor_module, "process_supervisor", FakeSupervisor())
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    assert await service.reap_execution_authority_once() == 1
    assert cancelled == ["run-revoked"]
    assert closed == [(
        "run-revoked", "org-a",
        {"terminal_state": "CANCELLED", "reason_code": "EXECUTION_CANCELLED", "actor": "execution-reaper"},
    )]


@pytest.mark.asyncio
async def test_reaper_keeps_process_backlog_open_when_termination_is_unconfirmed(monkeypatch):
    from app.core import db as db_module
    from app.core import process_supervisor as supervisor_module
    from app.core.process_supervisor import ProcessCancellationResult, ProcessCancellationStatus

    closed = []

    class FakeDatabase:
        def list_execution_recovery_candidates(self):
            return [{
                "execution_id": "run-orphan",
                "organization_id": "org-a",
                "process_id": 9876,
                "terminal_state": "CANCELLED",
                "reason_code": "EXECUTION_CANCELLED",
            }]

        def reap_execution_dispatch(self, *args, **kwargs):
            closed.append((args, kwargs))
            return True

    class FakeSupervisor:
        def cancel_execution(self, execution_id):
            return ProcessCancellationResult(execution_id, ProcessCancellationStatus.NOT_FOUND, 9876)

    monkeypatch.setattr(db_module, "db_manager", FakeDatabase())
    monkeypatch.setattr(supervisor_module, "process_supervisor", FakeSupervisor())
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    assert await service.reap_execution_authority_once() == 0
    assert closed == []


@pytest.mark.asyncio
async def test_production_reaper_settles_uncertain_execution_with_distinct_recovery_identity(tmp_path, monkeypatch):
    """The real observer path uses a recovery lease, not the process worker binding."""
    from app.core import db as db_module
    from app.core import process_supervisor as supervisor_module
    from app.core.process_supervisor import ProcessCancellationResult, ProcessCancellationStatus
    from tests.security.test_execution_decision_authority import _seed_execution_for_termination_settlement

    database = db_module.DatabaseManager(tmp_path / "observer-production-recovery.db")
    _seed_execution_for_termination_settlement(
        database,
        execution_id="run-observer-production-recovery",
        request_id="request-observer-production-recovery",
        decision_id="decision-observer-production-recovery",
    )
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_process_ownership "
            "SET ownership_state='LAUNCH_UNCERTAIN', launch_commit_state='UNCERTAIN' "
            "WHERE execution_id=? AND organization_id=?",
            ("run-observer-production-recovery", "org-settlement"),
        )

    class FakeSupervisor:
        def cancel_execution(self, execution_id, **kwargs):
            assert execution_id == "run-observer-production-recovery"
            assert kwargs["process_identity"] is not None
            return ProcessCancellationResult(
                execution_id, ProcessCancellationStatus.ALREADY_EXITED, 4242,
            )

    monkeypatch.setattr(db_module, "db_manager", database)
    monkeypatch.setattr(supervisor_module, "process_supervisor", FakeSupervisor())
    monkeypatch.setattr(
        "app.core.execution_service.get_worker_generation",
        lambda: "observer-recovery-generation",
    )
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    assert await service.reap_execution_authority_once() == 1
    with database._connection_scope() as conn:
        run = conn.execute(
            "SELECT state FROM execution_runs WHERE execution_id=? AND organization_id=?",
            ("run-observer-production-recovery", "org-settlement"),
        ).fetchone()
        attempt = conn.execute(
            "SELECT worker_identity, worker_generation, status "
            "FROM execution_recovery_attempts WHERE execution_id=? AND organization_id=? "
            "ORDER BY completed_at DESC LIMIT 1",
            ("run-observer-production-recovery", "org-settlement"),
        ).fetchone()
    assert run["state"] == "FAILED"
    assert attempt["worker_identity"] == "execution-recovery-coordinator"
    assert attempt["worker_generation"] == "observer-recovery-generation"
    assert attempt["status"] == "CONFIRMED_TERMINATED"


@pytest.mark.asyncio
async def test_production_reaper_persists_and_retries_unconfirmed_governed_recovery(tmp_path, monkeypatch):
    """Unconfirmed exact-process recovery is durable and re-enumerable."""
    from app.core import db as db_module
    from app.core import process_supervisor as supervisor_module
    from app.core.process_supervisor import ProcessCancellationResult, ProcessCancellationStatus
    from tests.security.test_execution_decision_authority import _seed_execution_for_termination_settlement

    database = db_module.DatabaseManager(tmp_path / "observer-governed-retry.db")
    execution_id = "run-observer-governed-retry"
    _seed_execution_for_termination_settlement(
        database,
        execution_id=execution_id,
        request_id="request-observer-governed-retry",
        decision_id="decision-observer-governed-retry",
    )
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_requests SET state='REVOKED' "
            "WHERE id=? AND organization_id=?",
            ("request-observer-governed-retry", "org-settlement"),
        )

    supervisor_status = [ProcessCancellationStatus.NOT_FOUND]
    supervisor_calls = []

    class FakeSupervisor:
        def cancel_execution(self, requested_execution_id, **kwargs):
            assert requested_execution_id == execution_id
            assert kwargs["process_identity"] is not None
            supervisor_calls.append(supervisor_status[0])
            return ProcessCancellationResult(
                requested_execution_id,
                supervisor_status[0],
                4242,
            )

    monkeypatch.setattr(db_module, "db_manager", database)
    monkeypatch.setattr(supervisor_module, "process_supervisor", FakeSupervisor())
    monkeypatch.setattr(
        "app.core.execution_service.get_worker_generation",
        lambda: "observer-recovery-generation",
    )
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    assert await service.reap_execution_authority_once() == 0
    with database._connection_scope() as conn:
        deferred = conn.execute(
            "SELECT r.state, p.ownership_state, s.status, s.next_retry_at, "
            "s.last_outcome, s.last_error, a.worker_identity, a.worker_generation, "
            "a.status AS attempt_status, a.cancellation_status "
            "FROM execution_runs r "
            "JOIN execution_process_ownership p ON p.execution_id=r.execution_id "
            "AND p.organization_id=r.organization_id "
            "JOIN execution_recovery_state s ON s.execution_id=r.execution_id "
            "AND s.organization_id=r.organization_id "
            "JOIN execution_recovery_attempts a ON a.execution_id=r.execution_id "
            "AND a.organization_id=r.organization_id "
            "WHERE r.execution_id=? AND r.organization_id=? "
            "ORDER BY a.attempt_number DESC LIMIT 1",
            (execution_id, "org-settlement"),
        ).fetchone()
        candidates_before_retry = database.list_execution_recovery_candidates()
    assert deferred["state"] == "RUNNING"
    assert deferred["ownership_state"] == "EXTERNAL_PROCESS_GOVERNED"
    assert deferred["status"] == "DEFERRED"
    assert deferred["next_retry_at"] is not None
    assert deferred["last_outcome"] == "termination_not_found"
    assert deferred["last_error"] is not None
    assert deferred["worker_identity"] == "execution-recovery-coordinator"
    assert deferred["worker_generation"] == "observer-recovery-generation"
    assert deferred["attempt_status"] == "DEFERRED"
    assert deferred["cancellation_status"] == "NOT_FOUND"
    assert all(item["execution_id"] != execution_id for item in candidates_before_retry)

    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_recovery_state SET next_retry_at=? "
            "WHERE execution_id=? AND organization_id=?",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), execution_id, "org-settlement"),
        )
    candidates_after_retry = database.list_execution_recovery_candidates()
    assert any(item["execution_id"] == execution_id for item in candidates_after_retry)
    supervisor_status[0] = ProcessCancellationStatus.ALREADY_EXITED

    assert await service.reap_execution_authority_once() == 1
    assert supervisor_calls == [
        ProcessCancellationStatus.NOT_FOUND,
        ProcessCancellationStatus.ALREADY_EXITED,
    ]
    with database._connection_scope() as conn:
        settled = conn.execute(
            "SELECT r.state, p.ownership_state, s.status, s.next_retry_at "
            "FROM execution_runs r "
            "JOIN execution_process_ownership p ON p.execution_id=r.execution_id "
            "AND p.organization_id=r.organization_id "
            "JOIN execution_recovery_state s ON s.execution_id=r.execution_id "
            "AND s.organization_id=r.organization_id "
            "WHERE r.execution_id=? AND r.organization_id=?",
            (execution_id, "org-settlement"),
        ).fetchone()
    assert settled["state"] == "CANCELLED"
    assert settled["ownership_state"] == "TERMINAL"
    assert settled["status"] == "CONFIRMED_TERMINATED"
    assert settled["next_retry_at"] is None


@pytest.mark.parametrize("run_state", ["REQUESTED", "STARTING", "RUNNING"])
@pytest.mark.asyncio
async def test_production_reaper_persists_missing_identity_without_supervisor(
    tmp_path, monkeypatch, run_state
):
    """Missing identity is durable, tenant-scoped, retryable, and non-terminal."""
    from app.core import db as db_module
    from app.core import process_supervisor as supervisor_module
    from tests.security.test_execution_decision_authority import _seed_execution_for_termination_settlement

    database = db_module.DatabaseManager(tmp_path / "observer-missing-identity.db")
    execution_id = "run-observer-missing-identity"
    request_id = "request-observer-missing-identity"
    _seed_execution_for_termination_settlement(
        database,
        execution_id=execution_id,
        request_id=request_id,
        decision_id="decision-observer-missing-identity",
    )
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_requests SET state='REVOKED' WHERE id=? AND organization_id=?",
            (request_id, "org-settlement"),
        )
        conn.execute(
            "UPDATE execution_runs SET state=? WHERE execution_id=? AND organization_id=?",
            (run_state, execution_id, "org-settlement"),
        )
        conn.execute(
            """UPDATE execution_process_ownership
                  SET container_identity=NULL, root_process_id=NULL,
                      root_process_start_token=NULL, process_group_id=NULL,
                      session_id=NULL, identity_attestation=NULL
                WHERE execution_id=? AND organization_id=?""",
            (execution_id, "org-settlement"),
        )

    class NeverCalledSupervisor:
        def cancel_execution(self, *_args, **_kwargs):
            raise AssertionError("missing durable identity must not call supervisor")

    monkeypatch.setattr(db_module, "db_manager", database)
    monkeypatch.setattr(supervisor_module, "process_supervisor", NeverCalledSupervisor())
    monkeypatch.setattr(
        "app.core.execution_service.get_worker_generation",
        lambda: "observer-recovery-generation",
    )
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    assert await service.reap_execution_authority_once() == 0
    with database._connection_scope() as conn:
        state = conn.execute(
            "SELECT status, next_retry_at, last_outcome, last_error, attempt_number "
            "FROM execution_recovery_state WHERE execution_id=? AND organization_id=?",
            (execution_id, "org-settlement"),
        ).fetchone()
        ownership = conn.execute(
            "SELECT ownership_state, container_identity, root_process_id, "
            "root_process_start_token, process_group_id, session_id, identity_attestation "
            "FROM execution_process_ownership WHERE execution_id=? AND organization_id=?",
            (execution_id, "org-settlement"),
        ).fetchone()
        attempt = conn.execute(
            "SELECT worker_identity, worker_generation, status, cancellation_status, "
            "reason_code FROM execution_recovery_attempts WHERE execution_id=? "
            "AND organization_id=? ORDER BY attempt_number DESC LIMIT 1",
            (execution_id, "org-settlement"),
        ).fetchone()
    assert state["status"] == "DEFERRED"
    assert state["next_retry_at"] is not None
    assert state["last_outcome"] == "identity_unavailable"
    assert state["last_error"] is not None
    assert state["attempt_number"] == 1
    assert ownership["ownership_state"] == "EXTERNAL_PROCESS_GOVERNED"
    assert all(ownership[field] is None for field in (
        "container_identity", "root_process_id", "root_process_start_token",
        "process_group_id", "session_id", "identity_attestation",
    ))
    assert attempt["worker_identity"] == "execution-recovery-coordinator"
    assert attempt["worker_generation"] == "observer-recovery-generation"
    assert attempt["status"] == "DEFERRED"
    assert attempt["cancellation_status"] == "IDENTITY_UNAVAILABLE"
    assert attempt["reason_code"] == "EXECUTION_RECOVERY_IDENTITY_UNAVAILABLE"
    assert len(database.recovery_health("org-settlement")) == 1
    assert database.recovery_health("other-tenant") == []
    assert all(item["execution_id"] != execution_id for item in database.list_execution_recovery_candidates())

    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_recovery_state SET next_retry_at=? "
            "WHERE execution_id=? AND organization_id=?",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), execution_id, "org-settlement"),
        )
    assert any(item["execution_id"] == execution_id for item in database.list_execution_recovery_candidates())
    assert await service.reap_execution_authority_once() == 0

    assert database.settle_execution_after_confirmed_termination(
        execution_id,
        "org-settlement",
        terminal_state="CANCELLED",
        reason_code="EXECUTION_CANCELLED",
        termination_status="ALREADY_EXITED",
        process_id=4242,
        process_group_id="4242",
        process_start_token="posix:00000000-0000-0000-0000-000000000001:12345",
        session_id=4242,
        worker_identity="worker-settlement",
        worker_generation="generation-settlement",
        actor="execution-reaper",
    ) is False
    with database._connection_scope() as conn:
        final = conn.execute(
            "SELECT state FROM execution_runs WHERE execution_id=? AND organization_id=?",
            (execution_id, "org-settlement"),
        ).fetchone()
    assert final["state"] == run_state


@pytest.mark.parametrize("launch_commit_state", ["NOT_ATTEMPTED", "UNCERTAIN"])
@pytest.mark.asyncio
async def test_production_reaper_persists_unknown_missing_identity_until_bounded_exhaustion(
    tmp_path, monkeypatch, launch_commit_state
):
    """UNKNOWN ownership remains durable, retryable, isolated, and non-terminal."""
    from app.core import db as db_module
    from app.core import process_supervisor as supervisor_module
    from tests.security.test_execution_decision_authority import _seed_execution_for_termination_settlement

    database = db_module.DatabaseManager(tmp_path / "observer-unknown-missing-identity.db")
    execution_id = "run-observer-unknown-missing-identity"
    request_id = "request-observer-unknown-missing-identity"
    _seed_execution_for_termination_settlement(
        database,
        execution_id=execution_id,
        request_id=request_id,
        decision_id="decision-observer-unknown-missing-identity",
    )
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_requests SET state='REVOKED' WHERE id=? AND organization_id=?",
            (request_id, "org-settlement"),
        )
        conn.execute(
            """UPDATE execution_process_ownership
                      SET ownership_state='UNKNOWN', launch_commit_state=?,
                      container_identity=NULL, root_process_id=NULL,
                      root_process_start_token=NULL, process_group_id=NULL,
                      session_id=NULL, identity_attestation=NULL
                WHERE execution_id=? AND organization_id=?""",
            (launch_commit_state, execution_id, "org-settlement"),
        )

    class NeverCalledSupervisor:
        def cancel_execution(self, *_args, **_kwargs):
            raise AssertionError("UNKNOWN missing identity must not call supervisor")

    monkeypatch.setattr(db_module, "db_manager", database)
    monkeypatch.setattr(supervisor_module, "process_supervisor", NeverCalledSupervisor())
    monkeypatch.setattr(
        "app.core.execution_service.get_worker_generation",
        lambda: "observer-unknown-recovery-generation",
    )
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    assert await service.reap_execution_authority_once() == 0
    with database._connection_scope() as conn:
        state = conn.execute(
            "SELECT status, next_retry_at, last_outcome, last_error, attempt_number "
            "FROM execution_recovery_state WHERE execution_id=? AND organization_id=?",
            (execution_id, "org-settlement"),
        ).fetchone()
        ownership = conn.execute(
            "SELECT ownership_state, launch_commit_state, container_identity, root_process_id "
            "FROM execution_process_ownership WHERE execution_id=? AND organization_id=?",
            (execution_id, "org-settlement"),
        ).fetchone()
    assert state["status"] == "DEFERRED"
    assert state["attempt_number"] == 1
    assert state["next_retry_at"] is not None
    assert state["last_outcome"] == "identity_unavailable"
    assert state["last_error"] is not None
    assert ownership["ownership_state"] == "UNKNOWN"
    assert ownership["launch_commit_state"] == launch_commit_state
    assert ownership["container_identity"] is None
    assert ownership["root_process_id"] is None
    assert len(database.recovery_health("org-settlement")) == 1
    assert database.recovery_health("other-tenant") == []
    assert all(item["execution_id"] != execution_id for item in database.list_execution_recovery_candidates())

    for expected_attempt in range(2, 6):
        with database._connection_scope() as conn:
            conn.execute(
                "UPDATE execution_recovery_state SET next_retry_at=? "
                "WHERE execution_id=? AND organization_id=?",
                (
                    (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
                    execution_id,
                    "org-settlement",
                ),
            )
        assert any(item["execution_id"] == execution_id for item in database.list_execution_recovery_candidates())
        assert await service.reap_execution_authority_once() == 0
        with database._connection_scope() as conn:
            state = conn.execute(
                "SELECT status, next_retry_at, attempt_number FROM execution_recovery_state "
                "WHERE execution_id=? AND organization_id=?",
                (execution_id, "org-settlement"),
            ).fetchone()
        assert state["attempt_number"] == expected_attempt
        if expected_attempt < 5:
            assert state["status"] == "DEFERRED"
            assert state["next_retry_at"] is not None
        else:
            assert state["status"] == "EXHAUSTED"
            assert state["next_retry_at"] is None

    with database._connection_scope() as conn:
        run = conn.execute(
            "SELECT state FROM execution_runs WHERE execution_id=? AND organization_id=?",
            (execution_id, "org-settlement"),
        ).fetchone()
        attempts = conn.execute(
            "SELECT COUNT(*) AS count FROM execution_recovery_attempts "
            "WHERE execution_id=? AND organization_id=?",
            (execution_id, "org-settlement"),
        ).fetchone()
    assert run["state"] == "RUNNING"
    assert attempts["count"] == 5
    assert database.list_execution_recovery_candidates() == []


@pytest.mark.asyncio
async def test_production_reaper_isolates_candidate_failure_and_persists_later_candidate(tmp_path, monkeypatch, caplog):
    """One candidate failure cannot prevent durable handling of the next one."""
    from types import SimpleNamespace

    from app.core import db as db_module
    from app.core import process_supervisor as supervisor_module
    from app.core.execution_service import record_posix_launch
    from app.core.models import ExecutionRunRecord
    from app.core.process_supervisor import ProcessCancellationResult, ProcessCancellationStatus
    from app.core.tool_operation_policy import OPERATION_POLICY_REVISION
    from tests.security.test_execution_decision_authority import _seed_execution_for_termination_settlement

    database = db_module.DatabaseManager(tmp_path / "observer-candidate-isolation.db")
    first_execution = "run-observer-isolation-first"
    _seed_execution_for_termination_settlement(
        database,
        execution_id=first_execution,
        request_id="request-observer-isolation-first",
        decision_id="decision-observer-isolation-first",
    )

    second_execution = "run-observer-isolation-second"
    second_request = "request-observer-isolation-second"
    second_decision = "decision-observer-isolation-second"
    now = datetime.now(timezone.utc)
    created_at = now.isoformat()
    expires_at = (now + timedelta(minutes=5)).isoformat()
    operation_options = '{"output_format":"json-asff","provider":"aws","quiet":true}'
    with database._connection_scope() as conn:
        conn.execute(
            """INSERT INTO execution_requests
               (id, idempotency_key, request_fingerprint, organization_id, asset_id,
                target_id, authorization_decision_id, target_policy_version, tool_id,
                operation_family, operation_options_json, operation_policy_revision,
                requested_by_user_id, state, created_at, expires_at, approved_decision_id)
               VALUES (?, ?, ?, 'org-settlement', 'asset-settlement', 'target-settlement',
                       'auth-settlement', 'v1', 'prowler', 'cloud_audit', ?, ?,
                       'admin-settlement', 'AUTHORIZED', ?, ?, ?)""",
            (second_request, f"idem-{second_request}", "e" * 64, operation_options,
             OPERATION_POLICY_REVISION, created_at, expires_at, second_decision),
        )
        conn.execute(
            """INSERT INTO execution_decisions
               (id, organization_id, project_id, asset_id, target_id,
                authorization_decision_id, target_policy_version, tool_id,
                operation_family, operation_options_json, operation_policy_revision,
                approval_state, approver_user_id, session_jti, worker_identity,
                created_at, expires_at)
               VALUES (?, 'org-settlement', NULL, 'asset-settlement', 'target-settlement',
                       'auth-settlement', 'v1', 'prowler', 'cloud_audit', ?, ?,
                       'APPROVED', 'admin-settlement', 'session-isolation-second',
                       'worker-settlement', ?, ?)""",
            (second_decision, operation_options, OPERATION_POLICY_REVISION, created_at, expires_at),
        )
    database.create_execution_run(
        ExecutionRunRecord(
            execution_id=second_execution,
            request_id=second_request,
            organization_id="org-settlement",
            worker_identity="worker-settlement",
            worker_generation="generation-settlement",
            correlation_id=f"corr-{second_execution}",
        )
    )
    with database._connection_scope() as conn:
        conn.execute(
            "INSERT INTO execution_dispatch_intents "
            "(execution_id, organization_id, state, attempt_count, created_at) "
            "VALUES (?, 'org-settlement', 'PENDING', 0, ?)",
            (second_execution, created_at),
        )
    authority = database.claim_execution_authority(
        second_decision,
        "org-settlement",
        "session-isolation-second",
        "worker-settlement",
        OPERATION_POLICY_REVISION,
    )
    assert authority is not None
    assert database.transition_execution_run(
        second_execution,
        "org-settlement",
        "STARTING",
        "RUNNING",
        worker_identity="worker-settlement",
        dispatch_claim_token=authority.dispatch.token,
    )
    capability = SimpleNamespace(
        execution_id=second_execution,
        decision=SimpleNamespace(id=second_decision, organization_id="org-settlement"),
        claim_token=authority.decision.token,
        dispatch_claim_token=authority.dispatch.token,
        worker_identity="worker-settlement",
        worker_generation="generation-settlement",
        database=database,
    )
    record_posix_launch(
        capability,
        pid=5252,
        process_group_id=5252,
        session_id=5252,
        start_token="posix:00000000-0000-0000-0000-000000000002:12345",
        member_snapshot=(SimpleNamespace(
            pid=5252,
            process_group_id=5252,
            session_id=5252,
            start_token="posix:00000000-0000-0000-0000-000000000002:12345",
        ),),
    )
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_requests SET state='REVOKED' "
            "WHERE id IN (?, ?)",
            ("request-observer-isolation-first", second_request),
        )

    class FakeSupervisor:
        def cancel_execution(self, execution_id, **kwargs):
            assert kwargs["process_identity"] is not None
            if execution_id == first_execution:
                raise RuntimeError("first candidate supervisor failure")
            return ProcessCancellationResult(
                execution_id,
                ProcessCancellationStatus.NOT_FOUND,
                5252,
            )

    monkeypatch.setattr(db_module, "db_manager", database)
    monkeypatch.setattr(supervisor_module, "process_supervisor", FakeSupervisor())
    monkeypatch.setattr(
        "app.core.execution_service.get_worker_generation",
        lambda: "observer-recovery-generation",
    )
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    assert await service.reap_execution_authority_once() == 0
    with database._connection_scope() as conn:
        first = conn.execute(
            "SELECT status, next_retry_at, last_error FROM execution_recovery_state "
            "WHERE execution_id=? AND organization_id=?",
            (first_execution, "org-settlement"),
        ).fetchone()
        second = conn.execute(
            "SELECT status, next_retry_at, last_error FROM execution_recovery_state "
            "WHERE execution_id=? AND organization_id=?",
            (second_execution, "org-settlement"),
        ).fetchone()
    assert first["status"] == "REQUESTED"
    assert second["status"] == "DEFERRED"
    assert second["next_retry_at"] is not None
    assert second["last_error"] is not None
    assert "first candidate supervisor failure" in caplog.text
    assert "unconfirmed process termination" in service.state.last_recovery_error


@pytest.mark.asyncio
async def test_reaper_settles_durable_no_process_without_supervisor_inference(monkeypatch):
    from app.core import db as db_module
    from app.core import process_supervisor as supervisor_module

    closed = []

    class FakeDatabase:
        def list_execution_recovery_candidates(self):
            return [{
                "execution_id": "run-no-process",
                "organization_id": "org-a",
                "process_id": None,
                "run_state": "STARTING",
                "dispatch_state": "CLAIMED",
                "ownership_state": "NO_EXTERNAL_PROCESS",
                "terminal_state": "CANCELLED",
                "reason_code": "EXECUTION_CANCELLED",
            }]

        def get_process_ownership(self, execution_id, organization_id):
            assert (execution_id, organization_id) == ("run-no-process", "org-a")
            return {
                "execution_id": execution_id,
                "organization_id": organization_id,
                "ownership_state": "NO_EXTERNAL_PROCESS",
                "worker_generation": "generation-a",
            }

        def get_execution_run(self, execution_id, organization_id):
            return {
                "execution_id": execution_id,
                "organization_id": organization_id,
                "state": "STARTING",
            }

        def settle_execution_after_confirmed_termination(self, execution_id, organization_id, **kwargs):
            closed.append((execution_id, organization_id, kwargs))
            return True

    class FakeSupervisor:
        def cancel_execution(self, *_args, **_kwargs):
            raise AssertionError("positive no-process evidence must not call the supervisor")

    monkeypatch.setattr(db_module, "db_manager", FakeDatabase())
    monkeypatch.setattr(supervisor_module, "process_supervisor", FakeSupervisor())
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    assert await service.reap_execution_authority_once() == 1
    assert closed == [(
        "run-no-process",
        "org-a",
        {
            "terminal_state": "CANCELLED",
            "reason_code": "EXECUTION_CANCELLED_BEFORE_PROCESS_CREATION",
            "termination_status": "NO_EXTERNAL_PROCESS",
            "worker_generation": "generation-a",
            "actor": "execution-reaper",
        },
    )]


@pytest.mark.asyncio
async def test_reaper_defers_starting_unknown_ownership_without_supervisor_inference(monkeypatch):
    from app.core import db as db_module
    from app.core import process_supervisor as supervisor_module

    class FakeDatabase:
        def list_execution_recovery_candidates(self):
            return [{
                "execution_id": "run-starting-unknown",
                "organization_id": "org-a",
                "process_id": None,
                "run_state": "STARTING",
                "dispatch_state": "CLAIMED",
                "ownership_state": "UNKNOWN",
                "terminal_state": "CANCELLED",
                "reason_code": "EXECUTION_CANCELLED",
            }]

        def get_process_ownership(self, execution_id, organization_id):
            return {
                "execution_id": execution_id,
                "organization_id": organization_id,
                "ownership_state": "UNKNOWN",
            }

        def get_execution_run(self, execution_id, organization_id):
            return {
                "execution_id": execution_id,
                "organization_id": organization_id,
                "state": "STARTING",
            }

    class FakeSupervisor:
        def cancel_execution(self, *_args, **_kwargs):
            raise AssertionError("STARTING/UNKNOWN recovery must not infer process absence")

    monkeypatch.setattr(db_module, "db_manager", FakeDatabase())
    monkeypatch.setattr(supervisor_module, "process_supervisor", FakeSupervisor())
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    assert await service.reap_execution_authority_once() == 0
    assert "durable process identity unavailable" in service.state.last_recovery_error


@pytest.mark.asyncio
async def test_reaper_enumeration_failure_isolated_in_observation_state(monkeypatch):
    from app.core import db as db_module

    class FailingDatabase:
        def list_execution_recovery_candidates(self):
            raise RuntimeError("temporary database outage")

    monkeypatch.setattr(db_module, "db_manager", FailingDatabase())
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    assert await service.reap_execution_authority_once() == 0
    assert "temporary database outage" in service.state.last_recovery_error


@pytest.mark.asyncio
async def test_capability_refresh_preserves_recovery_health_state(monkeypatch):
    async def successful_refresh(**kwargs):
        return None

    class FakeManager:
        @classmethod
        def get_instance(cls):
            return cls()

        async def get_all_tools_info(self, **kwargs):
            return []

    monkeypatch.setattr("app.core.observation_service.get_cached_system_capabilities", successful_refresh)
    monkeypatch.setattr("app.core.observation_service.ToolInstallationManager", FakeManager)
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)
    service._state = ObservationState(last_recovery_error="orphan remains", last_recovered_count=2)

    assert await service.refresh_once() is True
    assert service.state.last_recovery_error == "orphan remains"
    assert service.state.last_recovered_count == 2


@pytest.mark.asyncio
async def test_application_lifespan_owns_observation_service(monkeypatch):
    from app import main

    events = []

    class FakeService:
        def __init__(self):
            events.append("constructed")

        def start(self):
            events.append("started")
            return None

        async def stop(self):
            events.append("stopped")

    monkeypatch.setattr(main, "BackendObservationService", FakeService)
    async with main.lifespan(main.app):
        assert events == ["constructed", "started"]
    assert events == ["constructed", "started", "stopped"]
