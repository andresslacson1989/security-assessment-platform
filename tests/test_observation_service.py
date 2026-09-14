import asyncio
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import pytest

from app.core.observation_service import BackendObservationService, ObservationState


@pytest.fixture(autouse=True)
def _guard_runtime_database_for_observation_vectors(tmp_path, monkeypatch):
    """Keep every observer vector on a disposable database and detect writes."""
    repository_root = Path(__file__).resolve().parents[1]
    runtime_database = repository_root / "data" / "cyberassess.db"
    runtime_database_exists = runtime_database.is_file()
    before_digest = (
        sha256(runtime_database.read_bytes()).hexdigest()
        if runtime_database_exists
        else None
    )
    before_mtime = runtime_database.stat().st_mtime_ns if runtime_database_exists else None
    configured_database = os.environ.get("CYBERASSESS_DB_PATH")
    if configured_database:
        assert Path(configured_database).resolve() != runtime_database.resolve()
    monkeypatch.setenv("CYBERASSESS_DB_PATH", str(tmp_path / "observer-disposable.sqlite3"))
    yield
    if runtime_database_exists:
        assert runtime_database.is_file()
        assert sha256(runtime_database.read_bytes()).hexdigest() == before_digest
        assert runtime_database.stat().st_mtime_ns == before_mtime
    else:
        assert not runtime_database.exists()


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
    from app.core.process_supervisor import ProcessCancellationResult, ProcessCancellationStatus

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
        def list_execution_recovery_candidates(self, _limit=100):
            return candidates

        def reap_execution_dispatch(self, execution_id, organization_id, **kwargs):
            closed.append((execution_id, organization_id, kwargs))
            return True

    class FakeSupervisor:
        def cancel_execution(self, execution_id):
            cancelled.append(execution_id)
            return ProcessCancellationResult(
                execution_id,
                ProcessCancellationStatus.ALREADY_EXITED,
                4321,
            )

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
async def test_reaper_does_not_treat_untyped_truthy_result_as_termination_confirmation(monkeypatch):
    """Legacy/untyped supervisor results remain non-terminal evidence."""
    from app.core import db as db_module
    from app.core import process_supervisor as supervisor_module

    closed = []

    class FakeDatabase:
        def list_execution_recovery_candidates(self, _limit=100):
            return [{
                "execution_id": "run-untyped-cancellation",
                "organization_id": "org-a",
                "process_id": 9876,
                "run_state": "RUNNING",
                "terminal_state": "CANCELLED",
                "reason_code": "EXECUTION_CANCELLED",
            }]

        def reap_execution_dispatch(self, *args, **kwargs):
            closed.append((args, kwargs))
            return True

    class FakeSupervisor:
        def cancel_execution(self, _execution_id):
            return True

    monkeypatch.setattr(db_module, "db_manager", FakeDatabase())
    monkeypatch.setattr(supervisor_module, "process_supervisor", FakeSupervisor())
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    assert await service.reap_execution_authority_once() == 0
    assert closed == []


def test_termination_status_accepts_exact_typed_result_and_rejects_lookalikes():
    """The observer boundary accepts only the exact supervisor result type."""
    from app.core.process_supervisor import ProcessCancellationResult, ProcessCancellationStatus

    execution_id = "run-termination-status-boundary"

    assert BackendObservationService._termination_status(
        ProcessCancellationResult(
            execution_id,
            ProcessCancellationStatus.KILLED,
            9876,
        ),
        execution_id,
    ) == "KILLED"
    assert BackendObservationService._termination_status(
        ProcessCancellationResult(
            execution_id,
            ProcessCancellationStatus.ALREADY_EXITED,
            9876,
        ),
        execution_id,
    ) == "ALREADY_EXITED"

    expected_execution_id = execution_id

    class TruthyLookalike:
        execution_id = expected_execution_id
        status = ProcessCancellationStatus.KILLED
        confirmed = True

        def __bool__(self):
            return True

    class ResultSubclass(ProcessCancellationResult):
        pass

    assert BackendObservationService._termination_status(
        TruthyLookalike(),
        execution_id,
    ) == "UNKNOWN"
    assert BackendObservationService._termination_status(
        ProcessCancellationResult(
            "different-execution",
            ProcessCancellationStatus.KILLED,
            9876,
        ),
        execution_id,
    ) == "UNKNOWN"
    assert BackendObservationService._termination_status(
        ProcessCancellationResult(
            execution_id,
            ProcessCancellationStatus.KILLED.value,
            9876,
        ),
        execution_id,
    ) == "UNKNOWN"
    assert BackendObservationService._termination_status(
        ResultSubclass(
            execution_id,
            ProcessCancellationStatus.KILLED,
            9876,
        ),
        execution_id,
    ) == "UNKNOWN"


@pytest.mark.asyncio
async def test_reaper_keeps_process_backlog_open_when_termination_is_unconfirmed(monkeypatch):
    from app.core import db as db_module
    from app.core import process_supervisor as supervisor_module
    from app.core.process_supervisor import ProcessCancellationResult, ProcessCancellationStatus

    closed = []

    class FakeDatabase:
        def list_execution_recovery_candidates(self, _limit=100):
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
async def test_supervisor_timeout_remains_owned_through_shutdown(tmp_path):
    """A timed-out exact cancellation stays owned after bounded observer shutdown."""
    from app.core.db import DatabaseManager
    from app.core.process_supervisor import ProcessCancellationResult, ProcessCancellationStatus
    from tests.security.test_execution_decision_authority import _seed_execution_for_termination_settlement

    database = DatabaseManager(tmp_path / "observer-timeout-recovery.db")
    execution_id = "run-observer-timeout-recovery"
    request_id = "request-observer-timeout-recovery"
    _seed_execution_for_termination_settlement(
        database,
        execution_id=execution_id,
        request_id=request_id,
        decision_id="decision-observer-timeout-recovery",
    )
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_requests SET state='REVOKED' WHERE id=? AND organization_id=?",
            (request_id, "org-settlement"),
        )

    entered = threading.Event()
    release = threading.Event()

    class SlowSupervisor:
        def cancel_execution(self, requested_execution_id, **kwargs):
            assert requested_execution_id == execution_id
            assert kwargs["process_identity"] is not None
            entered.set()
            release.wait(timeout=5)
            return ProcessCancellationResult(
                requested_execution_id,
                ProcessCancellationStatus.NOT_FOUND,
            )

    service = BackendObservationService(
        interval_seconds=60,
        # Allow disposable SQLite enumeration and executor scheduling to
        # complete before the deliberately blocked supervisor times out.
        refresh_timeout_seconds=1,
        shutdown_timeout_seconds=0.2,
        database=database,
        supervisor=SlowSupervisor(),
    )
    try:
        assert await service.reap_execution_authority_once() == 0
        assert entered.is_set()
        with database._connection_scope() as conn:
            state = conn.execute(
                "SELECT status, attempt_number, next_retry_at, last_outcome, last_error "
                "FROM execution_recovery_state WHERE execution_id=? AND organization_id=?",
                (execution_id, "org-settlement"),
            ).fetchone()
            run = conn.execute(
                "SELECT state FROM execution_runs WHERE execution_id=? AND organization_id=?",
                (execution_id, "org-settlement"),
            ).fetchone()
            attempt = conn.execute(
                "SELECT status, cancellation_status, error_code "
                "FROM execution_recovery_attempts WHERE execution_id=? AND organization_id=? "
                "ORDER BY attempt_number DESC LIMIT 1",
                (execution_id, "org-settlement"),
            ).fetchone()
        assert state["status"] == "DEFERRED"
        assert state["attempt_number"] == 1
        assert state["next_retry_at"] is not None
        assert state["last_outcome"] == "termination_timeout"
        assert "exceeded the recovery timeout" in state["last_error"]
        assert run["state"] == "RUNNING"
        assert attempt["status"] == "DEFERRED"
        assert attempt["cancellation_status"] == "TIMEOUT"
        assert "exceeded the recovery timeout" in attempt["error_code"]
        assert service.state.last_recovery_error == (
            f"unconfirmed process termination timeout: execution_id={execution_id}"
        )
        assert len(service._pending_supervisor_cancellations) == 1
        pending = next(iter(service._pending_supervisor_cancellations.values()))
        assert pending.execution_id == execution_id
        assert pending.organization_id == "org-settlement"
        assert pending.started.is_set()
        assert pending.future.cancelled() is False
        assert not service._recovery_workers

        started_at = time.monotonic()
        await service.stop()
        assert time.monotonic() - started_at < 0.4
        assert service._pending_supervisor_cancellations
        with pytest.raises(RuntimeError, match="supervisor cancellation is unresolved"):
            service.start()

        release.set()
        for _ in range(40):
            if not service._pending_supervisor_cancellations:
                break
            await asyncio.sleep(0.01)
        assert not service._pending_supervisor_cancellations
        with database._connection_scope() as conn:
            run_after_completion = conn.execute(
                "SELECT state FROM execution_runs WHERE execution_id=? AND organization_id=?",
                (execution_id, "org-settlement"),
            ).fetchone()
        assert run_after_completion["state"] == "RUNNING"
        assert "late supervisor cancellation completed" in (service.state.last_recovery_error or "")
    finally:
        release.set()
        if service._pending_supervisor_cancellations:
            await service.stop()


def _seed_revoked_observer_recovery(database, *, execution_id: str, request_id: str) -> None:
    """Create a real governed recovery candidate before an observer invocation."""
    from tests.security.test_execution_decision_authority import _seed_execution_for_termination_settlement

    _seed_execution_for_termination_settlement(
        database,
        execution_id=execution_id,
        request_id=request_id,
        decision_id=f"decision-{execution_id}",
    )
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_requests SET state='REVOKED' WHERE id=? AND organization_id=?",
            (request_id, "org-settlement"),
        )


@pytest.mark.asyncio
async def test_supervisor_timeout_does_not_overlap_next_recovery(tmp_path, monkeypatch):
    """A second cadence cannot start another cancellation while the first remains owned."""
    from app.core.db import DatabaseManager
    from app.core.process_supervisor import ProcessCancellationResult, ProcessCancellationStatus

    database = DatabaseManager(tmp_path / "observer-supervisor-no-overlap.db")
    execution_id = "run-observer-supervisor-no-overlap"
    _seed_revoked_observer_recovery(
        database,
        execution_id=execution_id,
        request_id="request-observer-supervisor-no-overlap",
    )
    entered = threading.Event()
    release = threading.Event()
    invocations = 0

    class SlowSupervisor:
        def cancel_execution(self, requested_execution_id, *, process_identity=None):
            nonlocal invocations
            assert requested_execution_id == execution_id
            assert process_identity is not None
            invocations += 1
            entered.set()
            release.wait(timeout=5)
            return ProcessCancellationResult(
                requested_execution_id,
                ProcessCancellationStatus.NOT_FOUND,
            )

    service = BackendObservationService(
        interval_seconds=60,
        # Keep the test independent of host scheduling while the supervisor
        # remains blocked beyond the observer timeout budget.
        refresh_timeout_seconds=1,
        shutdown_timeout_seconds=0.05,
        database=database,
        supervisor=SlowSupervisor(),
    )
    # Make the durable retry immediately eligible so the second call reaches
    # the owned-operation conflict fence rather than merely sleeping on backoff.
    monkeypatch.setattr(
        service,
        "_retry_at",
        lambda _attempt, _maximum: (
            "DEFERRED",
            datetime.now(timezone.utc) - timedelta(seconds=2),
        ),
    )
    try:
        assert await service.reap_execution_authority_once() == 0
        assert entered.is_set()
        assert invocations == 1
        assert len(service._pending_supervisor_cancellations) == 1

        assert await service.reap_execution_authority_once() == 0
        assert invocations == 1
        assert len(service._pending_supervisor_cancellations) == 1
        assert "supervisor cancellation pending" in (
            service.state.last_recovery_error or ""
        )
        with database._connection_scope() as conn:
            recovery = conn.execute(
                "SELECT status, owner, lease_token, attempt_number "
                "FROM execution_recovery_state "
                "WHERE execution_id=? AND organization_id=?",
                (execution_id, "org-settlement"),
            ).fetchone()
            attempts = conn.execute(
                "SELECT attempt_number, status, cancellation_status "
                "FROM execution_recovery_attempts "
                "WHERE execution_id=? AND organization_id=? "
                "ORDER BY attempt_number, completed_at",
                (execution_id, "org-settlement"),
            ).fetchall()
        assert tuple(recovery) == ("DEFERRED", None, None, 1)
        assert [tuple(row) for row in attempts] == [(1, "DEFERRED", "TIMEOUT")]
    finally:
        release.set()
        for _ in range(40):
            if not service._pending_supervisor_cancellations:
                break
            await asyncio.sleep(0.01)
        await service.stop()


@pytest.mark.asyncio
async def test_uncertain_supervisor_timeout_does_not_claim_second_recovery_lease(
    tmp_path,
    monkeypatch,
):
    """An owned uncertain cancellation fences lease and attempt overlap."""
    from app.core.db import DatabaseManager
    from app.core.process_supervisor import ProcessCancellationResult, ProcessCancellationStatus
    from tests.security.test_execution_decision_authority import _seed_execution_for_termination_settlement

    database = DatabaseManager(tmp_path / "observer-uncertain-supervisor-no-overlap.db")
    execution_id = "run-observer-uncertain-supervisor-no-overlap"
    request_id = "request-observer-uncertain-supervisor-no-overlap"
    _seed_execution_for_termination_settlement(
        database,
        execution_id=execution_id,
        request_id=request_id,
        decision_id="decision-observer-uncertain-supervisor-no-overlap",
    )
    organization_id = "org-settlement"
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_requests SET state='REVOKED' "
            "WHERE id=? AND organization_id=?",
            (request_id, organization_id),
        )
        conn.execute(
            "UPDATE execution_process_ownership "
            "SET ownership_state='LAUNCH_UNCERTAIN', launch_commit_state='UNCERTAIN' "
            "WHERE execution_id=? AND organization_id=?",
            (execution_id, organization_id),
        )

    entered = threading.Event()
    release = threading.Event()
    active_lock = threading.Lock()
    invocations = 0
    active_invocations = 0
    max_active_invocations = 0
    completed_invocations = []

    class SlowFirstSupervisor:
        def cancel_execution(self, requested_execution_id, *, process_identity=None):
            nonlocal invocations, active_invocations, max_active_invocations
            assert requested_execution_id == execution_id
            assert process_identity is not None
            with active_lock:
                invocations += 1
                call_number = invocations
                active_invocations += 1
                max_active_invocations = max(max_active_invocations, active_invocations)
            try:
                if call_number == 1:
                    entered.set()
                    release.wait(timeout=5)
                completed_invocations.append(call_number)
                return ProcessCancellationResult(
                    requested_execution_id,
                    ProcessCancellationStatus.NOT_FOUND,
                )
            finally:
                with active_lock:
                    active_invocations -= 1

    service = BackendObservationService(
        interval_seconds=60,
        refresh_timeout_seconds=1,
        shutdown_timeout_seconds=0.05,
        database=database,
        supervisor=SlowFirstSupervisor(),
    )
    # The retry is deliberately at least one second in the past so the second
    # cadence is eligible and must be stopped by the owned-operation gate.
    monkeypatch.setattr(
        service,
        "_retry_at",
        lambda _attempt, _maximum: (
            "DEFERRED",
            datetime.now(timezone.utc) - timedelta(seconds=2),
        ),
    )
    try:
        assert await service.reap_execution_authority_once() == 0
        assert entered.is_set()
        assert invocations == 1
        assert len(service._pending_supervisor_cancellations) == 1
        with database._connection_scope() as conn:
            first_recovery = conn.execute(
                "SELECT status, owner, lease_token, attempt_number "
                "FROM execution_recovery_state "
                "WHERE execution_id=? AND organization_id=?",
                (execution_id, organization_id),
            ).fetchone()
            first_attempts = conn.execute(
                "SELECT attempt_number, status, cancellation_status "
                "FROM execution_recovery_attempts "
                "WHERE execution_id=? AND organization_id=? "
                "ORDER BY attempt_number, completed_at",
                (execution_id, organization_id),
            ).fetchall()
        assert tuple(first_recovery) == ("DEFERRED", None, None, 1)
        # The append-only attempt ledger retains the immutable lease claim and
        # its single completion record.  Only the completion record is the
        # current outcome; no attempt remains in progress.
        assert [tuple(row) for row in first_attempts] == [
            (1, "IN_PROGRESS", None),
            (1, "DEFERRED", "termination_timeout"),
        ]

        # The second eligible cadence must not claim attempt 2 while the
        # original exact-process supervisor future is still blocked.
        assert await service.reap_execution_authority_once() == 0
        assert invocations == 1
        assert len(service._pending_supervisor_cancellations) == 1
        assert "supervisor cancellation pending" in (
            service.state.last_recovery_error or ""
        )
        with database._connection_scope() as conn:
            second_recovery = conn.execute(
                "SELECT status, owner, lease_token, attempt_number "
                "FROM execution_recovery_state "
                "WHERE execution_id=? AND organization_id=?",
                (execution_id, organization_id),
            ).fetchone()
            second_attempts = conn.execute(
                "SELECT attempt_number, status, cancellation_status "
                "FROM execution_recovery_attempts "
                "WHERE execution_id=? AND organization_id=? "
                "ORDER BY attempt_number, completed_at",
                (execution_id, organization_id),
            ).fetchall()
            run = conn.execute(
                "SELECT state FROM execution_runs "
                "WHERE execution_id=? AND organization_id=?",
                (execution_id, organization_id),
            ).fetchone()
        assert tuple(second_recovery) == ("DEFERRED", None, None, 1)
        assert [tuple(row) for row in second_attempts] == [
            (1, "IN_PROGRESS", None),
            (1, "DEFERRED", "termination_timeout"),
        ]
        assert run["state"] == "RUNNING"
        assert second_attempts[-1][1] == "DEFERRED"
        latest_second_attempts = {}
        for row in second_attempts:
            latest_second_attempts[row["attempt_number"]] = row
        assert all(
            row["status"] != "IN_PROGRESS"
            for row in latest_second_attempts.values()
        )

        release.set()
        for _ in range(100):
            if not service._pending_supervisor_cancellations:
                break
            await asyncio.sleep(0.01)
        assert not service._pending_supervisor_cancellations
        assert completed_invocations == [1]

        # Only after the original future is consumed may the next eligible
        # cadence acquire a new durable lease and invoke the supervisor again.
        assert await service.reap_execution_authority_once() == 0
        assert invocations == 2
        assert max_active_invocations == 1
        assert completed_invocations == [1, 2]
        assert not service._pending_supervisor_cancellations
        with database._connection_scope() as conn:
            final_recovery = conn.execute(
                "SELECT status, owner, lease_token, attempt_number "
                "FROM execution_recovery_state "
                "WHERE execution_id=? AND organization_id=?",
                (execution_id, organization_id),
            ).fetchone()
            final_attempts = conn.execute(
                "SELECT attempt_number, status, cancellation_status "
                "FROM execution_recovery_attempts "
                "WHERE execution_id=? AND organization_id=? "
                "ORDER BY attempt_number, completed_at",
                (execution_id, organization_id),
            ).fetchall()
        assert tuple(final_recovery) == ("DEFERRED", None, None, 2)
        assert [tuple(row) for row in final_attempts] == [
            (1, "IN_PROGRESS", None),
            (1, "DEFERRED", "termination_timeout"),
            (2, "IN_PROGRESS", None),
            (2, "DEFERRED", "termination_not_found"),
        ]
        latest_final_attempts = {}
        for row in final_attempts:
            latest_final_attempts[row["attempt_number"]] = row
        assert all(
            row["status"] != "IN_PROGRESS"
            for row in latest_final_attempts.values()
        )
    finally:
        release.set()
        for _ in range(600):
            if not service._pending_supervisor_cancellations:
                break
            await asyncio.sleep(0.01)
        await service.stop()


@pytest.mark.asyncio
async def test_late_supervisor_result_does_not_terminalize_stale_recovery(tmp_path):
    """A late KILLED result has no callback authority to settle a timed-out run."""
    from app.core.db import DatabaseManager
    from app.core.process_supervisor import ProcessCancellationResult, ProcessCancellationStatus

    database = DatabaseManager(tmp_path / "observer-late-supervisor-result.db")
    execution_id = "run-observer-late-supervisor-result"
    _seed_revoked_observer_recovery(
        database,
        execution_id=execution_id,
        request_id="request-observer-late-supervisor-result",
    )
    entered = threading.Event()
    release = threading.Event()

    class LateKilledSupervisor:
        def cancel_execution(self, requested_execution_id, *, process_identity=None):
            assert requested_execution_id == execution_id
            assert process_identity is not None
            entered.set()
            release.wait(timeout=5)
            return ProcessCancellationResult(
                requested_execution_id,
                ProcessCancellationStatus.KILLED,
            )

    service = BackendObservationService(
        interval_seconds=60,
        # Keep the test independent of host scheduling while the supervisor
        # remains blocked beyond the observer timeout budget.
        refresh_timeout_seconds=1,
        database=database,
        supervisor=LateKilledSupervisor(),
    )
    try:
        assert await service.reap_execution_authority_once() == 0
        assert entered.is_set()
        release.set()
        for _ in range(40):
            if not service._pending_supervisor_cancellations:
                break
            await asyncio.sleep(0.01)
        assert not service._pending_supervisor_cancellations
        with database._connection_scope() as conn:
            run = conn.execute(
                "SELECT state FROM execution_runs WHERE execution_id=? AND organization_id=?",
                (execution_id, "org-settlement"),
            ).fetchone()
            recovery = conn.execute(
                "SELECT status, last_outcome FROM execution_recovery_state "
                "WHERE execution_id=? AND organization_id=?",
                (execution_id, "org-settlement"),
            ).fetchone()
        assert run["state"] == "RUNNING"
        assert recovery["status"] == "DEFERRED"
        assert recovery["last_outcome"] == "termination_timeout"
        assert "status=KILLED" in (service.state.last_recovery_error or "")
    finally:
        release.set()
        await service.stop()


@pytest.mark.asyncio
async def test_late_supervisor_failure_is_consumed_and_visible(tmp_path):
    """A late supervisor exception remains recoverable without an unhandled task."""
    from app.core.db import DatabaseManager

    database = DatabaseManager(tmp_path / "observer-late-supervisor-failure.db")
    execution_id = "run-observer-late-supervisor-failure"
    _seed_revoked_observer_recovery(
        database,
        execution_id=execution_id,
        request_id="request-observer-late-supervisor-failure",
    )
    entered = threading.Event()
    release = threading.Event()

    class LateFailureSupervisor:
        def cancel_execution(self, requested_execution_id, *, process_identity=None):
            assert requested_execution_id == execution_id
            assert process_identity is not None
            entered.set()
            release.wait(timeout=5)
            raise RuntimeError("late supervisor failure")

    service = BackendObservationService(
        interval_seconds=60,
        # Keep the test independent of host scheduling while the supervisor
        # remains blocked beyond the observer timeout budget.
        refresh_timeout_seconds=1,
        shutdown_timeout_seconds=0.05,
        database=database,
        supervisor=LateFailureSupervisor(),
    )
    try:
        assert await service.reap_execution_authority_once() == 0
        assert entered.is_set()
        await service.stop()
        assert service._pending_supervisor_cancellations
        release.set()
        for _ in range(40):
            if not service._pending_supervisor_cancellations:
                break
            await asyncio.sleep(0.01)
        assert not service._pending_supervisor_cancellations
        with database._connection_scope() as conn:
            run = conn.execute(
                "SELECT state FROM execution_runs WHERE execution_id=? AND organization_id=?",
                (execution_id, "org-settlement"),
            ).fetchone()
            recovery = conn.execute(
                "SELECT status, last_outcome FROM execution_recovery_state "
                "WHERE execution_id=? AND organization_id=?",
                (execution_id, "org-settlement"),
            ).fetchone()
        assert run["state"] == "RUNNING"
        assert recovery["status"] == "DEFERRED"
        assert recovery["last_outcome"] == "termination_timeout"
        assert "late supervisor cancellation failed" in (service.state.last_recovery_error or "")
    finally:
        release.set()
        await service.stop()


@pytest.mark.asyncio
async def test_reaper_reclaims_expired_uncertain_recovery_lease(tmp_path, monkeypatch):
    """A crashed recovery owner is re-claimable only after its lease expires."""
    from app.core.db import DatabaseManager
    from app.core.process_supervisor import ProcessCancellationResult, ProcessCancellationStatus
    from tests.security.test_execution_decision_authority import _seed_execution_for_termination_settlement

    database = DatabaseManager(tmp_path / "observer-expired-recovery-lease.db")
    execution_id = "run-observer-expired-recovery-lease"
    _seed_execution_for_termination_settlement(
        database,
        execution_id=execution_id,
        request_id="request-observer-expired-recovery-lease",
        decision_id="decision-observer-expired-recovery-lease",
    )
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_requests SET state='REVOKED' WHERE id=? AND organization_id=?",
            ("request-observer-expired-recovery-lease", "org-settlement"),
        )
        conn.execute(
            "UPDATE execution_process_ownership SET ownership_state='LAUNCH_UNCERTAIN', launch_commit_state='UNCERTAIN' "
            "WHERE execution_id=? AND organization_id=?",
            (execution_id, "org-settlement"),
        )

    original_lease = database.claim_recovery(
        execution_id,
        "org-settlement",
        "crashed-recovery-owner",
        "crashed-recovery-generation",
        lease_seconds=30,
    )
    assert original_lease is not None
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_recovery_state SET lease_expires_at=? WHERE execution_id=? AND organization_id=?",
            (
                (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
                execution_id,
                "org-settlement",
            ),
        )

    candidates = database.list_execution_recovery_candidates()
    assert any(item["execution_id"] == execution_id for item in candidates)

    class RecoverySupervisor:
        def cancel_execution(self, requested_execution_id, *, process_identity=None):
            assert requested_execution_id == execution_id
            assert process_identity is not None
            return ProcessCancellationResult(
                requested_execution_id,
                ProcessCancellationStatus.ALREADY_EXITED,
                process_identity.pid,
            )

    monkeypatch.setattr(
        "app.core.execution_service.get_worker_generation",
        lambda: "replacement-recovery-generation",
    )
    service = BackendObservationService(
        interval_seconds=60,
        refresh_timeout_seconds=1,
        database=database,
        supervisor=RecoverySupervisor(),
    )
    try:
        assert await service.reap_execution_authority_once() == 1
    finally:
        await service.stop()

    with database._connection_scope() as conn:
        state = conn.execute(
            "SELECT status, attempt_number, owner, lease_token FROM execution_recovery_state "
            "WHERE execution_id=? AND organization_id=?",
            (execution_id, "org-settlement"),
        ).fetchone()
        attempts = conn.execute(
            "SELECT attempt_number, status, worker_identity, worker_generation "
            "FROM execution_recovery_attempts WHERE execution_id=? AND organization_id=? "
            "ORDER BY attempt_number",
            (execution_id, "org-settlement"),
        ).fetchall()
    assert tuple(state)[:2] == ("CONFIRMED_TERMINATED", 2)
    assert state["owner"] is None
    assert state["lease_token"] is None
    assert [tuple(row) for row in attempts] == [
        (1, "IN_PROGRESS", "crashed-recovery-owner", "crashed-recovery-generation"),
        (2, "IN_PROGRESS", "execution-recovery-coordinator", "replacement-recovery-generation"),
        (2, "CONFIRMED_TERMINATED", "execution-recovery-coordinator", "replacement-recovery-generation"),
    ]


@pytest.mark.asyncio
async def test_observation_shutdown_cleanly_cancels_cancellable_background_workers():
    """A cooperative background worker does not create a false timeout alert."""
    service = BackendObservationService(
        interval_seconds=60,
        refresh_timeout_seconds=1,
        shutdown_timeout_seconds=0.05,
    )
    release = asyncio.Event()

    async def wait_forever():
        await release.wait()

    worker = asyncio.create_task(wait_forever())
    service._track_recovery_worker(worker)

    await service.stop()

    assert worker.done()
    assert service.state.last_recovery_error is None


@pytest.mark.asyncio
async def test_observation_shutdown_does_not_abandon_lifecycle_task():
    """A cancellation-resistant lifecycle task is tracked and not restarted."""
    service = BackendObservationService(
        interval_seconds=60,
        refresh_timeout_seconds=1,
        shutdown_timeout_seconds=0.05,
    )
    release = asyncio.Event()

    async def cancellation_resistant_loop():
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                continue

    service._run = cancellation_resistant_loop
    task = service.start()
    await asyncio.sleep(0)
    try:
        await service.stop()

        assert service._task is None
        assert service.running is False
        assert service.state.last_recovery_error == (
            "recovery worker shutdown timed out; late result remains isolated"
        )
        with pytest.raises(RuntimeError, match="cannot restart"):
            service.start()
    finally:
        release.set()
        await asyncio.wait_for(asyncio.shield(task), timeout=1)
        await service.stop()


@pytest.mark.asyncio
async def test_production_reaper_settles_uncertain_execution_with_distinct_recovery_identity(tmp_path, monkeypatch):
    """The real observer path uses a recovery lease, not the process worker binding."""
    import json

    from app.core import db as db_module
    from app.core.execution_context import decode_execution_proof
    from app.core.models import AuditAction
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
            "SELECT attempt_id, worker_identity, worker_generation, status, cancellation_status "
            "FROM execution_recovery_attempts WHERE execution_id=? AND organization_id=? "
            "ORDER BY completed_at DESC LIMIT 1",
            ("run-observer-production-recovery", "org-settlement"),
        ).fetchone()
        ownership = conn.execute(
            "SELECT no_process_proof FROM execution_process_ownership "
            "WHERE execution_id=? AND organization_id=?",
            ("run-observer-production-recovery", "org-settlement"),
        ).fetchone()
        recovery_audit = conn.execute(
            "SELECT details_json FROM audit_events "
            "WHERE organization_id=? AND action=? "
            "AND object_type='execution_recovery_attempt' AND object_id=? "
            "ORDER BY sequence_number DESC LIMIT 1",
            (
                "org-settlement",
                AuditAction.EXECUTION_RECOVERY_ATTEMPT_RECORDED.value,
                attempt["attempt_id"],
            ),
        ).fetchone()
    assert run["state"] == "FAILED"
    assert attempt["worker_identity"] == "execution-recovery-coordinator"
    assert attempt["worker_generation"] == "observer-recovery-generation"
    assert attempt["status"] == "CONFIRMED_TERMINATED"
    assert attempt["cancellation_status"] == ProcessCancellationStatus.ALREADY_EXITED.value
    assert ownership is not None and ownership["no_process_proof"]
    proof = decode_execution_proof(
        ownership["no_process_proof"],
        expected_proof_type="TERMINATION_CONFIRMED",
    )
    assert proof["termination_status"] == ProcessCancellationStatus.ALREADY_EXITED.value
    assert recovery_audit is not None
    assert json.loads(recovery_audit["details_json"])["termination_status"] == (
        ProcessCancellationStatus.ALREADY_EXITED.value
    )


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
        def list_execution_recovery_candidates(self, _limit=100):
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
        def list_execution_recovery_candidates(self, _limit=100):
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
        def list_execution_recovery_candidates(self, _limit=100):
            raise RuntimeError("temporary database outage")

    monkeypatch.setattr(db_module, "db_manager", FailingDatabase())
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)

    assert await service.reap_execution_authority_once() == 0
    assert "temporary database outage" in service.state.last_recovery_error


@pytest.mark.asyncio
async def test_reaper_uses_configured_bounded_recovery_batch(monkeypatch):
    """Recovery enumeration receives the service-owned batch bound."""
    from app.core import db as db_module

    requested_limits = []

    class BoundedDatabase:
        def list_execution_recovery_candidates(self, limit):
            requested_limits.append(limit)
            return []

    monkeypatch.setattr(db_module, "db_manager", BoundedDatabase())
    service = BackendObservationService(
        interval_seconds=60,
        refresh_timeout_seconds=1,
        recovery_batch_size=3,
    )

    assert await service.reap_execution_authority_once() == 0
    assert requested_limits == [3]


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


@pytest.mark.asyncio
async def test_late_durable_write_remains_tracked_and_requires_reconciliation():
    """A write that exceeds its wait budget cannot become an invisible mutation."""
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)
    service.durable_write_timeout_seconds = 0.01
    entered = threading.Event()
    release = threading.Event()
    calls = 0

    def slow_write():
        nonlocal calls
        calls += 1
        entered.set()
        release.wait(timeout=1)
        return True

    with pytest.raises(asyncio.TimeoutError):
        await service._durable_recovery_write("test-late-write", slow_write)
    assert entered.is_set()
    assert service._pending_durable_writes

    # A second caller for the same durable operation must join the submitted
    # work rather than schedule another transaction while the first is late.
    with pytest.raises(asyncio.TimeoutError):
        await service._durable_recovery_write("test-late-write", slow_write)
    assert calls == 1

    release.set()
    for _ in range(20):
        if not service._pending_durable_writes:
            break
        await asyncio.sleep(0.01)

    assert not service._pending_durable_writes
    assert service.state.last_recovery_error == (
        "late durable write completed: operation=test-late-write "
        "identity=test-late-write:no-execution:no-organization; reconciliation required"
    )
    assert "cancelled" not in service.state.last_recovery_error


@pytest.mark.asyncio
async def test_late_durable_write_remains_owned_through_bounded_shutdown():
    """Shutdown never turns a running database write into a false cancellation."""
    service = BackendObservationService(
        interval_seconds=60,
        refresh_timeout_seconds=1,
        shutdown_timeout_seconds=0.05,
    )
    service.durable_write_timeout_seconds = 0.01
    entered = threading.Event()
    release = threading.Event()
    completed = threading.Event()

    def slow_write():
        entered.set()
        release.wait(timeout=1)
        completed.set()
        return True

    with pytest.raises(asyncio.TimeoutError):
        await service._durable_recovery_write("shutdown-late-write", slow_write)
    assert entered.is_set()
    assert service._pending_durable_writes

    started_at = time.monotonic()
    await service.stop()
    elapsed = time.monotonic() - started_at

    assert elapsed < 0.25
    assert service._pending_durable_writes
    assert completed.is_set() is False
    assert "shutdown timed out" in (service.state.last_recovery_error or "")
    with pytest.raises(RuntimeError, match="durable recovery write is unresolved"):
        service.start()

    release.set()
    for _ in range(40):
        if not service._pending_durable_writes:
            break
        await asyncio.sleep(0.01)

    assert completed.is_set()
    assert not service._pending_durable_writes
    assert "late durable write completed" in (service.state.last_recovery_error or "")
    assert "cancelled" not in (service.state.last_recovery_error or "")


@pytest.mark.asyncio
async def test_caller_cancellation_does_not_cancel_started_durable_write():
    """Cancelling an async waiter leaves the submitted database operation owned."""
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)
    service.durable_write_timeout_seconds = 1
    entered = threading.Event()
    release = threading.Event()
    completed = threading.Event()

    def slow_write():
        entered.set()
        release.wait(timeout=1)
        completed.set()
        return True

    waiter = asyncio.create_task(
        service._durable_recovery_write("caller-cancelled-write", slow_write)
    )
    for _ in range(20):
        if entered.is_set():
            break
        await asyncio.sleep(0.01)
    assert entered.is_set()
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter

    assert service._pending_durable_writes
    assert completed.is_set() is False
    release.set()
    for _ in range(40):
        if not service._pending_durable_writes:
            break
        await asyncio.sleep(0.01)

    assert completed.is_set()
    assert not service._pending_durable_writes
    assert "caller interrupted" not in (service.state.last_recovery_error or "")
    assert "late durable write completed" in (service.state.last_recovery_error or "")


@pytest.mark.asyncio
async def test_conflicting_pending_durable_write_payload_is_rejected_without_second_invocation():
    """One identity cannot silently join a different terminal/recovery payload."""
    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1)
    service.durable_write_timeout_seconds = 0.01
    entered = threading.Event()
    release = threading.Event()
    invocations = 0

    def delayed_write(execution_id, organization_id, *, terminal_state):
        nonlocal invocations
        assert (execution_id, organization_id, terminal_state) == (
            "execution-conflict",
            "organization-conflict",
            "DEFERRED",
        )
        invocations += 1
        entered.set()
        release.wait(timeout=1)
        return True

    with pytest.raises(asyncio.TimeoutError):
        await service._durable_recovery_write(
            "conflicting-pending-write",
            delayed_write,
            "execution-conflict",
            "organization-conflict",
            terminal_state="DEFERRED",
        )
    assert entered.is_set()
    with pytest.raises(RuntimeError, match="conflicting pending durable write payload"):
        await service._durable_recovery_write(
            "conflicting-pending-write",
            delayed_write,
            "execution-conflict",
            "organization-conflict",
            terminal_state="FAILED",
        )
    assert invocations == 1
    assert len(service._pending_durable_writes) == 1

    release.set()
    for _ in range(40):
        if not service._pending_durable_writes:
            break
        await asyncio.sleep(0.01)
    assert not service._pending_durable_writes


@pytest.mark.asyncio
async def test_cancellation_resistant_non_write_worker_remains_owned_and_fences_restart():
    """A non-write worker cannot be dropped or overlap a new observer lifecycle."""
    service = BackendObservationService(
        interval_seconds=60,
        refresh_timeout_seconds=1,
        shutdown_timeout_seconds=0.05,
    )
    release = asyncio.Event()

    async def cancellation_resistant_worker():
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                continue

    worker = asyncio.create_task(cancellation_resistant_worker())
    service._track_recovery_worker(worker)
    try:
        started_at = time.monotonic()
        await service.stop()
        elapsed = time.monotonic() - started_at

        assert elapsed < 0.25
        assert worker in service._recovery_workers
        assert not service._pending_durable_writes
        assert service.state.last_recovery_error == (
            "recovery worker shutdown timed out; late result remains isolated"
        )
        with pytest.raises(RuntimeError, match="recovery worker is unresolved"):
            service.start()
    finally:
        release.set()
        await asyncio.wait_for(asyncio.shield(worker), timeout=1)
        await asyncio.sleep(0)
    assert not service._recovery_workers


@pytest.mark.asyncio
async def test_late_durable_write_failure_is_consumed_after_shutdown():
    """A late database error stays visible without an unhandled task failure."""
    service = BackendObservationService(
        interval_seconds=60,
        refresh_timeout_seconds=1,
        shutdown_timeout_seconds=0.05,
    )
    service.durable_write_timeout_seconds = 0.01
    entered = threading.Event()
    release = threading.Event()

    def failing_write():
        entered.set()
        release.wait(timeout=1)
        raise RuntimeError("late write failed")

    with pytest.raises(asyncio.TimeoutError):
        await service._durable_recovery_write("shutdown-late-failure", failing_write)
    assert entered.is_set()

    await service.stop()
    assert service._pending_durable_writes
    release.set()
    for _ in range(40):
        if not service._pending_durable_writes:
            break
        await asyncio.sleep(0.01)

    assert not service._pending_durable_writes
    assert service.state.last_recovery_error == (
        "late durable write failed: operation=shutdown-late-failure "
        "identity=shutdown-late-failure:no-execution:no-organization error=RuntimeError; "
        "reconciliation required"
    )


@pytest.mark.asyncio
async def test_late_durable_recovery_write_remains_visible_to_fresh_service(tmp_path):
    """A new lifecycle sees durable recovery state, not a clean in-memory result."""
    from app.core.db import DatabaseManager
    from tests.security.test_execution_decision_authority import _seed_execution_for_termination_settlement

    database = DatabaseManager(tmp_path / "late-write-reconciliation.db")
    execution_id = "run-late-write-reconciliation"
    organization_id = "org-settlement"
    _seed_execution_for_termination_settlement(
        database,
        execution_id=execution_id,
        request_id="request-late-write-reconciliation",
        decision_id="decision-late-write-reconciliation",
    )
    with database._connection_scope() as connection:
        connection.execute(
            "UPDATE execution_process_ownership "
            "SET ownership_state='LAUNCH_UNCERTAIN', launch_commit_state='UNCERTAIN' "
            "WHERE execution_id=? AND organization_id=?",
            (execution_id, organization_id),
        )
    lease = database.claim_recovery(
        execution_id,
        organization_id,
        "late-write-owner",
        "late-write-generation",
        lease_seconds=30,
    )
    assert lease is not None

    service = BackendObservationService(
        interval_seconds=60,
        refresh_timeout_seconds=1,
        shutdown_timeout_seconds=0.05,
        database=database,
    )
    service.durable_write_timeout_seconds = 0.01
    entered = threading.Event()
    release = threading.Event()

    def delayed_completion(requested_execution_id, requested_organization_id):
        assert (requested_execution_id, requested_organization_id) == (execution_id, organization_id)
        entered.set()
        release.wait(timeout=1)
        return database.complete_recovery(
            execution_id,
            organization_id,
            "late-write-owner",
            lease["lease_token"],
            "late-write-generation",
            status="DEFERRED",
            outcome="late_write_reconciliation",
            error="caller timeout retained durable recovery ownership",
            next_retry_at=datetime.now(timezone.utc) + timedelta(seconds=30),
        )

    with pytest.raises(asyncio.TimeoutError):
        await service._durable_recovery_write(
            "complete-recovery-late-reconciliation",
            delayed_completion,
            execution_id,
            organization_id,
        )
    assert entered.is_set()
    await service.stop()

    # A fresh service has no shared in-memory marker, so this assertion proves
    # the existing tenant-bound recovery projection—not memory—remains the
    # source of truth during the ambiguous interval.
    fresh_service = BackendObservationService(
        interval_seconds=60,
        refresh_timeout_seconds=1,
        database=database,
    )
    before_completion = fresh_service.database.recovery_health(organization_id)
    assert any(
        row["execution_id"] == execution_id and row["status"] == "IN_PROGRESS"
        for row in before_completion
    )

    release.set()
    for _ in range(40):
        if not service._pending_durable_writes:
            break
        await asyncio.sleep(0.01)
    assert not service._pending_durable_writes

    after_completion = fresh_service.database.recovery_health(organization_id)
    recovered = next(row for row in after_completion if row["execution_id"] == execution_id)
    assert recovered["status"] == "DEFERRED"
    assert recovered["last_outcome"] == "late_write_reconciliation"
    # The original lease is already consumed: replay cannot create a second
    # recovery completion or terminal state.
    assert database.complete_recovery(
        execution_id,
        organization_id,
        "late-write-owner",
        lease["lease_token"],
        "late-write-generation",
        status="DEFERRED",
        outcome="late_write_reconciliation",
        error="caller timeout retained durable recovery ownership",
        next_retry_at=datetime.now(timezone.utc) + timedelta(seconds=30),
    ) is False
    with database._connection_scope() as connection:
        attempts = connection.execute(
            "SELECT status FROM execution_recovery_attempts "
            "WHERE execution_id=? AND organization_id=? ORDER BY requested_at, completed_at",
            (execution_id, organization_id),
        ).fetchall()
    assert [row["status"] for row in attempts] == ["IN_PROGRESS", "DEFERRED"]


@pytest.mark.asyncio
async def test_fresh_service_uses_durable_recovery_when_completion_callback_loop_is_unavailable(
    tmp_path,
    monkeypatch,
):
    """A closed callback loop cannot turn a late write into clean memory-only state."""
    from app.core import observation_service as observation_module
    from app.core.db import DatabaseManager
    from tests.security.test_execution_decision_authority import _seed_execution_for_termination_settlement

    database = DatabaseManager(tmp_path / "closed-loop-reconciliation.db")
    execution_id = "run-closed-loop-reconciliation"
    organization_id = "org-settlement"
    _seed_execution_for_termination_settlement(
        database,
        execution_id=execution_id,
        request_id="request-closed-loop-reconciliation",
        decision_id="decision-closed-loop-reconciliation",
    )
    with database._connection_scope() as connection:
        connection.execute(
            "UPDATE execution_process_ownership "
            "SET ownership_state='LAUNCH_UNCERTAIN', launch_commit_state='UNCERTAIN' "
            "WHERE execution_id=? AND organization_id=?",
            (execution_id, organization_id),
        )
    lease = database.claim_recovery(
        execution_id,
        organization_id,
        "closed-loop-owner",
        "closed-loop-generation",
        lease_seconds=30,
    )
    assert lease is not None

    service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1, database=database)
    service.durable_write_timeout_seconds = 0.01
    entered = threading.Event()
    release = threading.Event()

    def delayed_completion(requested_execution_id, requested_organization_id):
        assert (requested_execution_id, requested_organization_id) == (execution_id, organization_id)
        entered.set()
        release.wait(timeout=1)
        return database.complete_recovery(
            execution_id,
            organization_id,
            "closed-loop-owner",
            lease["lease_token"],
            "closed-loop-generation",
            status="DEFERRED",
            outcome="closed_loop_late_write",
            error="completion callback was unavailable",
            next_retry_at=datetime.now(timezone.utc) + timedelta(seconds=30),
        )

    class ClosedCompletionLoop:
        def call_soon_threadsafe(self, *_args, **_kwargs):
            raise RuntimeError("event loop is closed")

    original_running_loop = observation_module.asyncio.get_running_loop
    monkeypatch.setattr(
        observation_module.asyncio,
        "get_running_loop",
        lambda: ClosedCompletionLoop(),
    )
    try:
        with pytest.raises(asyncio.TimeoutError):
            await service._durable_recovery_write(
                "complete-recovery-closed-loop",
                delayed_completion,
                execution_id,
                organization_id,
            )
    finally:
        monkeypatch.setattr(observation_module.asyncio, "get_running_loop", original_running_loop)
    assert entered.is_set()
    release.set()
    pending = next(iter(service._pending_durable_writes.values()))
    for _ in range(40):
        if pending.future.done():
            break
        await asyncio.sleep(0.01)
    assert pending.future.done()
    # The original service cannot process the completion callback, but the
    # atomic durable state remains available to the next lifecycle.
    assert service._pending_durable_writes
    fresh_service = BackendObservationService(interval_seconds=60, refresh_timeout_seconds=1, database=database)
    row = next(
        item
        for item in fresh_service.database.recovery_health(organization_id)
        if item["execution_id"] == execution_id
    )
    assert row["status"] == "DEFERRED"
    assert row["last_outcome"] == "closed_loop_late_write"
    service._reconcile_completed_owned_operations()
    assert not service._pending_durable_writes
    async def idle_lifecycle():
        await asyncio.sleep(3600)

    monkeypatch.setattr(service, "_run", idle_lifecycle)
    service.start()
    assert service.running
    await service.stop()
