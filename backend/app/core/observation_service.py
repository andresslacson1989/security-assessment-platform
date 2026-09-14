"""Lifecycle-managed backend observation of the 26-tool fleet.

Observations are deliberately separate from authentication and execution
authorization.  The service refreshes process-local snapshots only; every
execution path retains its own live trust and version checks.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.adapters import get_cached_system_capabilities
from app.installers.manager import ToolInstallationManager

logger = logging.getLogger("cyberassess.observation")

DEFAULT_INTERVAL_SECONDS = 60.0
DEFAULT_REFRESH_TIMEOUT_SECONDS = 120.0
DEFAULT_SHUTDOWN_TIMEOUT_SECONDS = 10.0
DEFAULT_RECOVERY_BATCH_SIZE = 25
MAX_RECOVERY_BATCH_SIZE = 100
# SQLite's configured busy timeout is five seconds.  Recovery writes include
# audit-chain persistence, so their bounded confirmation budget must exceed
# that database-level lock interval; otherwise a committed recovery can be
# falsely reported as failed.
MINIMUM_DURABLE_WRITE_TIMEOUT_SECONDS = 10.0
# Recovery writes are deliberately isolated from cancellable asyncio waiters.
# A caller may stop waiting, but it must never thereby cancel or lose the
# underlying transaction.  The executor is bounded so recovery cannot create
# an unbounded thread pool under repeated timeout conditions.
_DURABLE_WRITE_EXECUTOR = ThreadPoolExecutor(
    max_workers=4,
    thread_name_prefix="cyberassess-durable-write",
)
# Supervisor cancellation can affect a real process tree.  It therefore has
# the same ownership requirement as a late database transaction, but it uses a
# distinct bounded pool so database/audit contention cannot starve exact
# cancellation work (or vice versa).
_SUPERVISOR_CANCELLATION_EXECUTOR = ThreadPoolExecutor(
    max_workers=4,
    thread_name_prefix="cyberassess-supervisor-cancel",
)


def _bounded_env_float(name: str, default: float, *, minimum: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("Ignoring invalid observation setting %s", name)
        return default
    return value if value >= minimum else default


def _bounded_env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Ignoring invalid observation setting %s", name)
        return default
    return value if minimum <= value <= maximum else default


@dataclass(frozen=True)
class ObservationState:
    last_started_at: Optional[datetime] = None
    last_completed_at: Optional[datetime] = None
    last_error: Optional[str] = None
    last_recovery_error: Optional[str] = None
    last_recovered_count: int = 0


@dataclass
class _DurableWriteOperation:
    """One submitted database operation whose actual completion is owned."""

    operation: str
    identity: str
    request_fingerprint: str
    execution_id: Optional[str]
    organization_id: Optional[str]
    started: threading.Event
    future: Future[Any]
    caller_timed_out: bool = False
    caller_interrupted: bool = False
    shutdown_pending: bool = False


@dataclass
class _SupervisorCancellationOperation:
    """One exact-process cancellation whose real thread remains owned."""

    operation: str
    identity: str
    request_fingerprint: str
    execution_id: str
    organization_id: str
    process_identity_fingerprint: str
    recovery_worker_generation: str
    recovery_attempt: Optional[int]
    started: threading.Event
    future: Future[Any]
    caller_timed_out: bool = False
    caller_interrupted: bool = False
    shutdown_pending: bool = False


class BackendObservationService:
    """Refreshes backend-owned capability and toolbox snapshots periodically."""

    def __init__(
        self,
        *,
        interval_seconds: Optional[float] = None,
        refresh_timeout_seconds: Optional[float] = None,
        shutdown_timeout_seconds: Optional[float] = None,
        recovery_batch_size: Optional[int] = None,
        database: Any = None,
        supervisor: Any = None,
    ) -> None:
        self.interval_seconds = interval_seconds or _bounded_env_float(
            "CYBERASSESS_OBSERVATION_INTERVAL_SECONDS",
            DEFAULT_INTERVAL_SECONDS,
            minimum=1.0,
        )
        self.refresh_timeout_seconds = refresh_timeout_seconds or _bounded_env_float(
            "CYBERASSESS_OBSERVATION_TIMEOUT_SECONDS",
            DEFAULT_REFRESH_TIMEOUT_SECONDS,
            minimum=1.0,
        )
        # Process and network observation must remain promptly bounded, but a
        # committed lifecycle write must not be relabeled as a process timeout
        # merely because a local transaction (including audit evidence) needs
        # more than a tiny test/configured observation interval.  This remains
        # bounded and is intentionally not an execution-process timeout.
        self.durable_write_timeout_seconds = max(
            self.refresh_timeout_seconds,
            MINIMUM_DURABLE_WRITE_TIMEOUT_SECONDS,
        )
        self.shutdown_timeout_seconds = shutdown_timeout_seconds or _bounded_env_float(
            "CYBERASSESS_OBSERVATION_SHUTDOWN_TIMEOUT_SECONDS",
            DEFAULT_SHUTDOWN_TIMEOUT_SECONDS,
            minimum=1.0,
        )
        configured_batch_size = recovery_batch_size
        if configured_batch_size is None:
            configured_batch_size = _bounded_env_int(
                "CYBERASSESS_RECOVERY_BATCH_SIZE",
                DEFAULT_RECOVERY_BATCH_SIZE,
                minimum=1,
                maximum=MAX_RECOVERY_BATCH_SIZE,
            )
        if (
            type(configured_batch_size) is not int
            or not 1 <= configured_batch_size <= MAX_RECOVERY_BATCH_SIZE
        ):
            raise ValueError(
                f"recovery_batch_size must be an integer between 1 and {MAX_RECOVERY_BATCH_SIZE}"
            )
        self.recovery_batch_size = configured_batch_size
        self._database = database
        self._supervisor = supervisor
        self._refresh_lock = asyncio.Lock()
        self._recovery_lock = asyncio.Lock()
        self._recovery_workers: set[asyncio.Task] = set()
        # This collection owns the actual concurrent-futures handles, not
        # merely the asyncio waiters used by the caller.  It is intentionally
        # separate from cancellation-eligible recovery/lifecycle tasks.
        self._pending_durable_writes: dict[str, _DurableWriteOperation] = {}
        # Exact supervisor cancellation is a process-affecting operation, not
        # an ordinary cancellation-eligible lifecycle worker.  A timeout of
        # its asyncio view never releases ownership of the thread that may
        # still inspect or terminate the attested process tree.
        self._pending_supervisor_cancellations: dict[
            str, _SupervisorCancellationOperation
        ] = {}
        self._task: Optional[asyncio.Task[None]] = None
        self._stopping_lifecycle_task: Optional[asyncio.Task[None]] = None
        self._state = ObservationState()

    @property
    def state(self) -> ObservationState:
        return self._state

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def database(self) -> Any:
        """Resolve the authoritative database lazily for test and app lifecycles."""
        if self._database is None:
            from app.core.db import db_manager

            self._database = db_manager
        return self._database

    @property
    def supervisor(self) -> Any:
        """Resolve the process supervisor lazily without creating a second control plane."""
        if self._supervisor is None:
            from app.core.process_supervisor import process_supervisor

            self._supervisor = process_supervisor
        return self._supervisor

    def _track_recovery_worker(self, task: asyncio.Task[Any]) -> None:
        """Track a cancellation worker and consume any late result."""
        self._recovery_workers.add(task)
        task.add_done_callback(self._recovery_worker_done)

    @staticmethod
    def _durable_write_identity(operation: str, args: tuple[Any, ...]) -> tuple[str, Optional[str], Optional[str]]:
        """Derive a stable, non-secret identity for one recovery write."""
        execution_id = args[0] if args and isinstance(args[0], str) and args[0].strip() else None
        organization_id = (
            args[1]
            if len(args) > 1 and isinstance(args[1], str) and args[1].strip()
            else None
        )
        identity = ":".join(
            value
            for value in (operation, execution_id or "no-execution", organization_id or "no-organization")
        )
        return identity, execution_id, organization_id

    @staticmethod
    def _canonical_durable_write_value(value: Any) -> Any:
        """Return a deterministic, non-logged representation for fingerprinting."""
        if value is None or isinstance(value, (bool, int, float, str)):
            return value
        if isinstance(value, datetime):
            return {"type": "datetime", "value": value.isoformat()}
        if isinstance(value, (tuple, list)):
            return [
                BackendObservationService._canonical_durable_write_value(item)
                for item in value
            ]
        if isinstance(value, dict):
            return {
                str(key): BackendObservationService._canonical_durable_write_value(item)
                for key, item in sorted(value.items(), key=lambda item: str(item[0]))
            }
        return {
            "type": f"{type(value).__module__}.{type(value).__qualname__}",
            "representation": repr(value),
        }

    @classmethod
    def _durable_write_request_fingerprint(
        cls,
        operation: str,
        method: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> str:
        """Bind a pending join to its complete call payload without logging it."""
        payload = {
            "operation": operation,
            "method": (
                f"{getattr(method, '__module__', type(method).__module__)}."
                f"{getattr(method, '__qualname__', type(method).__qualname__)}"
            ),
            "args": cls._canonical_durable_write_value(args),
            "kwargs": cls._canonical_durable_write_value(kwargs),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _record_pending_durable_write(
        self,
        operation: _DurableWriteOperation,
        *,
        condition: str,
    ) -> None:
        """Keep a caller timeout or shutdown visibly non-clean."""
        self._record_recovery_error(
            (
                f"durable write {condition}: operation={operation.operation} "
                f"identity={operation.identity}; reconciliation required"
            ),
            self._state.last_recovered_count,
        )

    def _consume_durable_write_completion(self, operation: _DurableWriteOperation) -> None:
        """Consume one actual future result and preserve late-write evidence."""
        current = self._pending_durable_writes.get(operation.identity)
        if current is not operation:
            return
        self._pending_durable_writes.pop(operation.identity, None)
        if operation.future.cancelled():
            # A concurrent Future can only become cancelled before it starts.
            # Once the thread has started, Python cannot truthfully claim that
            # cancellation stopped the database call.
            self._record_recovery_error(
                (
                    f"durable write cancelled before start: operation={operation.operation} "
                    f"identity={operation.identity}; reconciliation required"
                ),
                self._state.last_recovered_count,
            )
            return
        try:
            operation.future.result()
        except Exception as exc:
            if operation.caller_timed_out or operation.caller_interrupted or operation.shutdown_pending:
                self._record_recovery_error(
                    (
                        f"late durable write failed: operation={operation.operation} "
                        f"identity={operation.identity} error={type(exc).__name__}; "
                        "reconciliation required"
                    ),
                    self._state.last_recovered_count,
                )
            else:
                logger.warning(
                    "Durable recovery write failed before caller timeout: operation=%s identity=%s error_type=%s",
                    operation.operation,
                    operation.identity,
                    type(exc).__name__,
                )
            return
        if operation.caller_timed_out or operation.caller_interrupted or operation.shutdown_pending:
            self._record_recovery_error(
                (
                    f"late durable write completed: operation={operation.operation} "
                    f"identity={operation.identity}; reconciliation required"
                ),
                self._state.last_recovered_count,
            )

    def _schedule_durable_write_completion(
        self,
        loop: asyncio.AbstractEventLoop,
        operation: _DurableWriteOperation,
    ) -> None:
        """Return completion processing to the owning event loop when alive."""
        try:
            loop.call_soon_threadsafe(self._consume_durable_write_completion, operation)
        except RuntimeError:
            # Forced process termination can close the event loop while a
            # database thread is still running.  The database transaction's
            # existing tenant/lease compare-and-swap fence remains the durable
            # source of truth for the next process; do not fabricate a local
            # cancellation or terminal result here.
            logger.warning(
                "Durable recovery write completed after event-loop closure: operation=%s identity=%s",
                operation.operation,
                operation.identity,
            )

    def _get_or_submit_durable_write(
        self,
        operation: str,
        method: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> _DurableWriteOperation:
        """Return one owned operation; never duplicate a pending write."""
        identity, execution_id, organization_id = self._durable_write_identity(operation, args)
        request_fingerprint = self._durable_write_request_fingerprint(
            operation,
            method,
            args,
            kwargs,
        )
        existing = self._pending_durable_writes.get(identity)
        if existing is not None:
            if not existing.future.done():
                if existing.request_fingerprint != request_fingerprint:
                    raise RuntimeError(
                        "conflicting pending durable write payload for the same recovery identity"
                    )
                return existing
            self._consume_durable_write_completion(existing)

        started = threading.Event()

        def invoke() -> Any:
            started.set()
            return method(*args, **kwargs)

        future = _DURABLE_WRITE_EXECUTOR.submit(invoke)
        submitted = _DurableWriteOperation(
            operation=operation,
            identity=identity,
            request_fingerprint=request_fingerprint,
            execution_id=execution_id,
            organization_id=organization_id,
            started=started,
            future=future,
        )
        self._pending_durable_writes[identity] = submitted
        loop = asyncio.get_running_loop()
        future.add_done_callback(
            lambda _completed: self._schedule_durable_write_completion(loop, submitted)
        )
        return submitted

    @staticmethod
    def _consume_durable_waiter_result(waiter: asyncio.Future[Any]) -> None:
        """Consume wrapper failures; the concurrent Future owns the result."""
        if waiter.cancelled():
            return
        try:
            waiter.exception()
        except (asyncio.CancelledError, Exception):
            # The real result/exception is consumed exactly once from the
            # concurrent Future by _consume_durable_write_completion().  This
            # callback exists solely to prevent a detached bounded waiter from
            # producing an unhandled asyncio-Future warning.
            return

    @classmethod
    def _durable_write_waiter(cls, operation: _DurableWriteOperation) -> asyncio.Future[Any]:
        """Create a non-owning asyncio view whose exception is always consumed."""
        waiter = asyncio.wrap_future(operation.future)
        waiter.add_done_callback(cls._consume_durable_waiter_result)
        return waiter

    async def _durable_recovery_write(
        self,
        operation: str,
        method: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Wait boundedly without cancelling or losing the submitted transaction."""
        submitted = self._get_or_submit_durable_write(operation, method, args, kwargs)
        waiter = self._durable_write_waiter(submitted)
        try:
            return await asyncio.wait_for(
                asyncio.shield(waiter),
                timeout=self.durable_write_timeout_seconds,
            )
        except asyncio.TimeoutError:
            submitted.caller_timed_out = True
            self._record_pending_durable_write(submitted, condition="timed out")
            raise
        except asyncio.CancelledError:
            # The caller/lifecycle stopped waiting; the concurrent Future
            # remains owned until its real completion callback consumes it.
            submitted.caller_interrupted = True
            self._record_pending_durable_write(submitted, condition="caller interrupted")
            raise

    @staticmethod
    def _supervisor_cancellation_identity(
        execution_id: str,
        organization_id: str,
    ) -> str:
        """Return the single-flight key for one tenant-bound execution."""
        return ":".join(("supervisor-cancel", execution_id, organization_id))

    @classmethod
    def _process_identity_fingerprint(cls, process_identity: Any) -> str:
        """Bind cancellation to the entire attested process proof without logging it."""
        members = getattr(process_identity, "member_snapshot", ()) if process_identity else ()
        payload = {
            "pid": getattr(process_identity, "pid", None),
            "process_group_id": getattr(process_identity, "process_group_id", None),
            "start_token": getattr(process_identity, "start_token", None),
            "session_id": getattr(process_identity, "session_id", None),
            "windows_attestation": getattr(process_identity, "windows_attestation", None),
            "member_snapshot": [
                {
                    "pid": getattr(member, "pid", None),
                    "process_group_id": getattr(member, "process_group_id", None),
                    "session_id": getattr(member, "session_id", None),
                    "start_token": getattr(member, "start_token", None),
                }
                for member in members
            ],
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @classmethod
    def _supervisor_cancellation_request_fingerprint(
        cls,
        *,
        execution_id: str,
        organization_id: str,
        process_identity_fingerprint: str,
        recovery_worker_generation: str,
        recovery_lease_token: Optional[str],
        recovery_attempt: Optional[int],
    ) -> str:
        """Fingerprint every authority/proof value governing a cancellation call."""
        payload = {
            "operation": "supervisor-cancel",
            "execution_id": execution_id,
            "organization_id": organization_id,
            "process_identity_fingerprint": process_identity_fingerprint,
            "recovery_worker_generation": recovery_worker_generation,
            # The lease token is never retained or logged.  It contributes only
            # to the one-way request fingerprint which prevents a second
            # cadence from joining a cancellation from another recovery lease.
            "recovery_lease_token": recovery_lease_token,
            "recovery_attempt": recovery_attempt,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _record_pending_supervisor_cancellation(
        self,
        operation: _SupervisorCancellationOperation,
        *,
        condition: str,
    ) -> None:
        self._record_recovery_error(
            (
                f"supervisor cancellation {condition}: operation={operation.operation} "
                f"identity={operation.identity}; reconciliation required"
            ),
            self._state.last_recovered_count,
        )

    def _supervisor_cancellation_requires_reconciliation(
        self,
        *,
        execution_id: str,
        organization_id: str,
    ) -> bool:
        """Fence recovery while one exact tenant-bound cancellation is pending.

        The recovery lock serializes observer cadences, but it does not own the
        concurrent-future work submitted to the supervisor executor.  A
        timed-out caller therefore leaves a real process-affecting operation
        in flight after the durable recovery projection has been made
        retryable.  Reconcile completed operations before checking the
        identity-keyed collection, then leave the durable projection untouched
        while an unfinished operation remains.  This prevents a later cadence
        from claiming a new lease/attempt or submitting a second cancellation
        for the same execution and tenant.
        """
        self._reconcile_completed_owned_operations()
        identity = self._supervisor_cancellation_identity(
            execution_id,
            organization_id,
        )
        operation = self._pending_supervisor_cancellations.get(identity)
        if operation is None:
            return False
        if operation.future.done():
            # The callback may be waiting behind another event-loop turn.  A
            # completed operation is safe to consume synchronously here and
            # does not block a fresh eligible recovery attempt.
            self._consume_supervisor_cancellation_completion(operation)
            operation = self._pending_supervisor_cancellations.get(identity)
            if operation is None:
                return False
        self._record_recovery_error(
            (
                f"supervisor cancellation pending: operation={operation.operation} "
                f"identity={operation.identity}; reconciliation required"
            ),
            self._state.last_recovered_count,
        )
        return True

    def _consume_supervisor_cancellation_completion(
        self,
        operation: _SupervisorCancellationOperation,
    ) -> None:
        """Consume a late cancellation result without terminalizing from a callback."""
        current = self._pending_supervisor_cancellations.get(operation.identity)
        if current is not operation:
            return
        self._pending_supervisor_cancellations.pop(operation.identity, None)
        if operation.future.cancelled():
            self._record_recovery_error(
                (
                    f"supervisor cancellation cancelled before start: operation={operation.operation} "
                    f"identity={operation.identity}; reconciliation required"
                ),
                self._state.last_recovered_count,
            )
            return
        try:
            result = operation.future.result()
        except Exception as exc:
            if operation.caller_timed_out or operation.caller_interrupted or operation.shutdown_pending:
                self._record_recovery_error(
                    (
                        f"late supervisor cancellation failed: operation={operation.operation} "
                        f"identity={operation.identity} error={type(exc).__name__}; "
                        "reconciliation required"
                    ),
                    self._state.last_recovered_count,
                )
            else:
                logger.warning(
                    "Supervisor cancellation failed before caller timeout: operation=%s identity=%s error_type=%s",
                    operation.operation,
                    operation.identity,
                    type(exc).__name__,
                )
            return
        if operation.caller_timed_out or operation.caller_interrupted or operation.shutdown_pending:
            # A result observed after its caller has persisted a retryable
            # state has no authority to settle the run.  Only a subsequent
            # recovery cadence with a fresh lease and confirmed-termination
            # coordinator path may consume it into durable terminal state.
            status = getattr(getattr(result, "status", None), "value", None)
            self._record_recovery_error(
                (
                    f"late supervisor cancellation completed: operation={operation.operation} "
                    f"identity={operation.identity} status={status or type(result).__name__}; "
                    "reconciliation required"
                ),
                self._state.last_recovered_count,
            )

    def _schedule_supervisor_cancellation_completion(
        self,
        loop: asyncio.AbstractEventLoop,
        operation: _SupervisorCancellationOperation,
    ) -> None:
        """Schedule local completion accounting only while the owner loop lives."""
        try:
            loop.call_soon_threadsafe(self._consume_supervisor_cancellation_completion, operation)
        except RuntimeError:
            logger.warning(
                "Supervisor cancellation completed after event-loop closure: operation=%s identity=%s",
                operation.operation,
                operation.identity,
            )

    def _get_or_submit_supervisor_cancellation(
        self,
        *,
        execution_id: str,
        organization_id: str,
        process_identity: Any,
        recovery_worker_generation: str,
        recovery_lease_token: Optional[str],
        recovery_attempt: Optional[int],
    ) -> _SupervisorCancellationOperation:
        """Submit exactly one attested cancellation for an unresolved recovery."""
        identity = self._supervisor_cancellation_identity(execution_id, organization_id)
        process_identity_fingerprint = self._process_identity_fingerprint(process_identity)
        request_fingerprint = self._supervisor_cancellation_request_fingerprint(
            execution_id=execution_id,
            organization_id=organization_id,
            process_identity_fingerprint=process_identity_fingerprint,
            recovery_worker_generation=recovery_worker_generation,
            recovery_lease_token=recovery_lease_token,
            recovery_attempt=recovery_attempt,
        )
        existing = self._pending_supervisor_cancellations.get(identity)
        if existing is not None:
            if not existing.future.done():
                if existing.request_fingerprint != request_fingerprint:
                    raise RuntimeError(
                        "conflicting pending supervisor cancellation for the same recovery identity"
                    )
                return existing
            self._consume_supervisor_cancellation_completion(existing)

        started = threading.Event()
        supervisor = self.supervisor

        def invoke() -> Any:
            started.set()
            if process_identity is None:
                return supervisor.cancel_execution(execution_id)
            return supervisor.cancel_execution(
                execution_id,
                process_identity=process_identity,
            )

        future = _SUPERVISOR_CANCELLATION_EXECUTOR.submit(invoke)
        submitted = _SupervisorCancellationOperation(
            operation="supervisor-cancel",
            identity=identity,
            request_fingerprint=request_fingerprint,
            execution_id=execution_id,
            organization_id=organization_id,
            process_identity_fingerprint=process_identity_fingerprint,
            recovery_worker_generation=recovery_worker_generation,
            recovery_attempt=recovery_attempt,
            started=started,
            future=future,
        )
        self._pending_supervisor_cancellations[identity] = submitted
        loop = asyncio.get_running_loop()
        future.add_done_callback(
            lambda _completed: self._schedule_supervisor_cancellation_completion(loop, submitted)
        )
        return submitted

    @staticmethod
    def _consume_supervisor_cancellation_waiter_result(waiter: asyncio.Future[Any]) -> None:
        if waiter.cancelled():
            return
        try:
            waiter.exception()
        except (asyncio.CancelledError, Exception):
            return

    @classmethod
    def _supervisor_cancellation_waiter(
        cls,
        operation: _SupervisorCancellationOperation,
    ) -> asyncio.Future[Any]:
        waiter = asyncio.wrap_future(operation.future)
        waiter.add_done_callback(cls._consume_supervisor_cancellation_waiter_result)
        return waiter

    async def _owned_supervisor_cancellation(
        self,
        *,
        execution_id: str,
        organization_id: str,
        process_identity: Any,
        recovery_worker_generation: str,
        recovery_lease_token: Optional[str] = None,
        recovery_attempt: Optional[int] = None,
    ) -> Any:
        """Bound the waiter, never the underlying exact-process operation."""
        submitted = self._get_or_submit_supervisor_cancellation(
            execution_id=execution_id,
            organization_id=organization_id,
            process_identity=process_identity,
            recovery_worker_generation=recovery_worker_generation,
            recovery_lease_token=recovery_lease_token,
            recovery_attempt=recovery_attempt,
        )
        waiter = self._supervisor_cancellation_waiter(submitted)
        try:
            return await asyncio.wait_for(
                asyncio.shield(waiter),
                timeout=self.refresh_timeout_seconds,
            )
        except asyncio.TimeoutError:
            submitted.caller_timed_out = True
            self._record_pending_supervisor_cancellation(submitted, condition="timed out")
            raise
        except asyncio.CancelledError:
            submitted.caller_interrupted = True
            self._record_pending_supervisor_cancellation(submitted, condition="caller interrupted")
            raise

    def _reconcile_completed_owned_operations(self) -> None:
        """Consume completed owned futures before lifecycle state is evaluated."""
        for operation in tuple(self._pending_durable_writes.values()):
            if operation.future.done():
                self._consume_durable_write_completion(operation)
        for operation in tuple(self._pending_supervisor_cancellations.values()):
            if operation.future.done():
                self._consume_supervisor_cancellation_completion(operation)

    def _recovery_worker_done(self, task: asyncio.Task[Any]) -> None:
        self._recovery_workers.discard(task)
        if task.cancelled():
            return
        try:
            task.result()
        except Exception as exc:
            # A timed-out recovery worker may finish after the cycle has
            # persisted a retryable outcome.  It remains isolated from the
            # next cycle, but its result must not become an unobserved error.
            logger.warning(
                "Late execution recovery worker failed: error_type=%s",
                type(exc).__name__,
            )

    @staticmethod
    def _retry_at(attempt_number: int, max_attempts: int) -> tuple[str, Optional[datetime]]:
        """Return bounded durable retry state for one recovery attempt."""
        status = "EXHAUSTED" if attempt_number >= max_attempts else "DEFERRED"
        retry_at = None if status == "EXHAUSTED" else datetime.now(timezone.utc) + timedelta(
            seconds=min(300, 5 * (2 ** min(attempt_number - 1, 6)))
        )
        return status, retry_at

    def _record_recovery_error(self, message: str, recovered_count: int) -> None:
        self._state = ObservationState(
            last_started_at=self._state.last_started_at,
            last_completed_at=self._state.last_completed_at,
            last_error=self._state.last_error,
            last_recovery_error=message[:512],
            last_recovered_count=recovered_count,
        )

    @staticmethod
    def _termination_status(cancellation: Any, execution_id: str) -> str:
        """Return only an exact typed supervisor status for durable evidence.

        Recovery must not infer confirmed termination from truthiness.  The
        process boundary returns a typed ``ProcessCancellationResult``; an
        untyped test double or legacy result is therefore treated as unknown
        and remains retryable rather than being allowed to settle a run.
        """
        from app.core.process_supervisor import normalize_cancellation_result

        status, _confirmed = normalize_cancellation_result(
            cancellation,
            execution_id=execution_id,
        )
        return status

    async def refresh_once(self) -> bool:
        """Refresh both snapshots once, with single-flight and an aggregate bound."""
        if self._refresh_lock.locked():
            return False
        async with self._refresh_lock:
            started = datetime.now(timezone.utc)
            self._state = ObservationState(
                last_started_at=started,
                last_completed_at=self._state.last_completed_at,
                last_error=None,
                last_recovery_error=self._state.last_recovery_error,
                last_recovered_count=self._state.last_recovered_count,
            )
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        get_cached_system_capabilities(force_refresh=True),
                        ToolInstallationManager.get_instance().get_all_tools_info(force_refresh=True),
                    ),
                    timeout=self.refresh_timeout_seconds,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"[:512]
                self._state = ObservationState(
                    last_started_at=started,
                    last_completed_at=self._state.last_completed_at,
                    last_error=message,
                    last_recovery_error=self._state.last_recovery_error,
                    last_recovered_count=self._state.last_recovered_count,
                )
                logger.warning("Backend tool observation failed: error=%s", message)
                return False

            self._state = ObservationState(
                last_started_at=started,
                last_completed_at=datetime.now(timezone.utc),
                last_error=None,
                last_recovery_error=self._state.last_recovery_error,
                last_recovered_count=self._state.last_recovered_count,
            )
            return True

    async def reap_execution_authority_once(self) -> int:
        if self._recovery_lock.locked():
            return 0
        async with self._recovery_lock:
            return await self._reap_execution_authority_once()

    async def _reap_execution_authority_once(self) -> int:
        """Terminate and durably close authority-lost executions by exact ID."""
        from app.core.execution_service import (
            get_worker_generation,
            load_durable_process_identity,
        )

        database = self.database
        recovery_owner = "execution-recovery-coordinator"
        recovery_worker_generation = get_worker_generation()
        max_recovery_attempts = 5
        durable_identity_api = callable(getattr(database, "get_process_ownership", None))

        try:
            candidates = await asyncio.wait_for(
                asyncio.to_thread(
                    database.list_execution_recovery_candidates,
                    self.recovery_batch_size,
                ),
                timeout=self.refresh_timeout_seconds,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"[:512]
            self._state = ObservationState(
                last_started_at=self._state.last_started_at,
                last_completed_at=self._state.last_completed_at,
                last_error=self._state.last_error,
                last_recovery_error=message,
                last_recovered_count=0,
            )
            logger.warning("Execution authority recovery enumeration failed: error=%s", message)
            return 0
        reaped = 0
        for candidate in candidates:
            execution_id = candidate["execution_id"]
            if candidate.get("ownership_state") in {"LAUNCH_UNCERTAIN", "RECOVERY_BLOCKED"}:
                # Uncertain ownership has a separate lease and settlement
                # protocol.  A NOT_FOUND result is deliberately not treated
                # as proof that a process is gone; only the supervisor's
                # confirmed result can close the durable run.
                if self._supervisor_cancellation_requires_reconciliation(
                    execution_id=execution_id,
                    organization_id=candidate["organization_id"],
                ):
                    continue
                try:
                    lease = await self._durable_recovery_write(
                        "claim-recovery-lease",
                        database.claim_recovery,
                        execution_id,
                        candidate["organization_id"],
                        recovery_owner,
                        recovery_worker_generation,
                        lease_seconds=30,
                    )
                    if not lease:
                        continue
                    durable_identity = None
                    if durable_identity_api:
                        durable_identity = await asyncio.wait_for(
                            asyncio.to_thread(
                                load_durable_process_identity,
                                database,
                                execution_id,
                                candidate["organization_id"],
                            ),
                            timeout=self.refresh_timeout_seconds,
                        )
                        if durable_identity is None:
                            attempt_number = int(lease["attempt_number"])
                            status, retry_at = self._retry_at(
                                attempt_number,
                                max_recovery_attempts,
                            )
                            await self._durable_recovery_write(
                                "complete-recovery-identity-unavailable",
                                database.complete_recovery,
                                execution_id,
                                candidate["organization_id"],
                                recovery_owner,
                                lease["lease_token"],
                                recovery_worker_generation,
                                status=status,
                                outcome="durable_identity_unavailable",
                                error="persisted process identity could not be validated; recovery remains fenced",
                                next_retry_at=retry_at,
                            )
                            continue
                    try:
                        cancellation = await self._owned_supervisor_cancellation(
                            execution_id=execution_id,
                            organization_id=candidate["organization_id"],
                            process_identity=(durable_identity if durable_identity_api else None),
                            recovery_worker_generation=recovery_worker_generation,
                            recovery_lease_token=lease["lease_token"],
                            recovery_attempt=int(lease["attempt_number"]),
                        )
                    except asyncio.TimeoutError:
                        # ``shield`` leaves the identity-bound supervisor call
                        # running.  Release only the recovery lease here; a
                        # timeout from a database operation must remain a
                        # database/recovery error and must not be relabeled as
                        # a process-termination timeout.
                        attempt_number = int(lease["attempt_number"])
                        status, retry_at = self._retry_at(
                            attempt_number,
                            max_recovery_attempts,
                        )
                        persisted = await self._durable_recovery_write(
                            "complete-recovery-timeout",
                            database.complete_recovery,
                            execution_id,
                            candidate["organization_id"],
                            recovery_owner,
                            lease["lease_token"],
                            recovery_worker_generation,
                            status=status,
                            outcome="termination_timeout",
                            error="identity-bound termination exceeded the recovery timeout; retry remains fenced",
                            next_retry_at=retry_at,
                        )
                        if not persisted:
                            raise RuntimeError(
                                "timed-out recovery lease could not be durably released"
                            )
                        self._record_recovery_error(
                            "unconfirmed process termination timeout: "
                            f"execution_id={execution_id}",
                            reaped,
                        )
                        continue
                    termination_status = self._termination_status(
                        cancellation,
                        execution_id,
                    )
                    if termination_status in {"KILLED", "ALREADY_EXITED"}:
                        closed = await self._durable_recovery_write(
                            "settle-recovery-execution",
                            database.settle_recovery_execution,
                            execution_id,
                            candidate["organization_id"],
                            recovery_owner,
                            lease["lease_token"],
                            recovery_worker_generation,
                            termination_status=termination_status,
                        )
                        if closed:
                            reaped += 1
                        continue
                    attempt_number = int(lease["attempt_number"])
                    status, retry_at = self._retry_at(
                        attempt_number,
                        max_recovery_attempts,
                    )
                    persisted = await self._durable_recovery_write(
                        "complete-recovery-unconfirmed",
                        database.complete_recovery,
                        execution_id,
                        candidate["organization_id"],
                        recovery_owner,
                        lease["lease_token"],
                        recovery_worker_generation,
                        status=status,
                        outcome=f"termination_{termination_status.lower()}",
                        error="termination was not confirmed; automatic recovery remains fenced",
                        next_retry_at=retry_at,
                    )
                    if not persisted:
                        raise RuntimeError(
                            "unconfirmed recovery outcome was not durably committed"
                        )
                    continue
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    message = f"{type(exc).__name__}: {exc}"[:512]
                    logger.warning(
                        "Uncertain execution recovery failed: execution_id=%s error=%s",
                        execution_id, message,
                    )
                    self._state = ObservationState(
                        last_started_at=self._state.last_started_at,
                        last_completed_at=self._state.last_completed_at,
                        last_error=self._state.last_error,
                        last_recovery_error=message,
                        last_recovered_count=reaped,
                    )
                continue
            # The supervisor registry is keyed by the durable execution ID;
            # after a worker restart, the persisted process identity must be
            # reloaded and supplied explicitly.  A missing identity leaves an
            # active execution open for operator/recovery evidence; it is never
            # treated as proof that a PID no longer exists.
            try:
                ownership = None
                durable_identity = None
                if durable_identity_api:
                    ownership = await asyncio.wait_for(
                        asyncio.to_thread(
                            database.get_process_ownership,
                            execution_id,
                            candidate["organization_id"],
                        ),
                        timeout=self.refresh_timeout_seconds,
                    )
                    durable_identity = await asyncio.wait_for(
                        asyncio.to_thread(
                            load_durable_process_identity,
                            database,
                            execution_id,
                            candidate["organization_id"],
                        ),
                        timeout=self.refresh_timeout_seconds,
                    )

                candidate_run_state = candidate.get("run_state")
                candidate_dispatch_state = candidate.get("dispatch_state")
                ownership_state = candidate.get("ownership_state")

                # A pending dispatch has not acquired a process authority.  It
                # can be closed only with the explicit pre-dispatch proof.
                if (
                    durable_identity_api
                    and ownership_state in {"UNKNOWN", "NO_EXTERNAL_PROCESS"}
                    and candidate_run_state == "REQUESTED"
                    and candidate_dispatch_state == "PENDING"
                ):
                    pre_dispatch_terminal_state = (
                        "CANCELLED"
                        if candidate["terminal_state"] == "CANCELLED"
                        else "EXECUTION_BLOCKED"
                    )
                    pre_dispatch_reason = (
                        "EXECUTION_CANCELLED_BEFORE_DISPATCH"
                        if pre_dispatch_terminal_state == "CANCELLED"
                        else "EXECUTION_AUTHORITY_REVOKED_OR_EXPIRED"
                    )
                    closed = await self._durable_recovery_write(
                        "settle-pre-dispatch",
                        database.settle_execution_after_confirmed_termination,
                        execution_id,
                        candidate["organization_id"],
                        terminal_state=pre_dispatch_terminal_state,
                        reason_code=pre_dispatch_reason,
                        termination_status="PRE_DISPATCH",
                        worker_generation=(ownership or {}).get("worker_generation"),
                        actor="execution-reaper",
                    )
                    if closed:
                        reaped += 1
                    continue

                # A launch worker may have durably proved that the process
                # was never created while the run was STARTING.  After a
                # restart, that positive no-process evidence is the only
                # safe path; do not ask a fresh supervisor to infer safety
                # from a missing in-memory PID mapping.
                if (
                    durable_identity_api
                    and ownership_state == "NO_EXTERNAL_PROCESS"
                    and candidate_run_state == "STARTING"
                    and candidate_dispatch_state in {"CLAIMED", "BLOCKED"}
                ):
                    no_process_outcome = {
                        ("CANCELLED", "EXECUTION_CANCELLED"): (
                            "CANCELLED", "EXECUTION_CANCELLED_BEFORE_PROCESS_CREATION",
                        ),
                        ("EXECUTION_BLOCKED", "EXECUTION_AUTHORITY_REVOKED_OR_EXPIRED"): (
                            "EXECUTION_BLOCKED", "EXECUTION_AUTHORITY_REVOKED_OR_EXPIRED",
                        ),
                        ("TIMED_OUT", "EXECUTION_AUTHORITY_EXPIRED"): (
                            "TIMED_OUT", "EXECUTION_AUTHORITY_EXPIRED",
                        ),
                    }.get((candidate["terminal_state"], candidate["reason_code"]))
                    if no_process_outcome is not None:
                        closed = await self._durable_recovery_write(
                            "settle-no-external-process",
                            database.settle_execution_after_confirmed_termination,
                            execution_id,
                            candidate["organization_id"],
                            terminal_state=no_process_outcome[0],
                            reason_code=no_process_outcome[1],
                            termination_status="NO_EXTERNAL_PROCESS",
                            worker_generation=(ownership or {}).get("worker_generation"),
                            actor="execution-reaper",
                        )
                        if closed:
                            reaped += 1
                        continue

                # An active run with no independently reloadable identity is
                # never evidence that no process exists.  Persist the
                # identity-unavailable recovery outcome for real database
                # managers so the condition survives a worker restart and is
                # visible to tenant-scoped recovery health.  Legacy test
                # doubles without this DAL method retain the conservative
                # in-memory-only behavior.
                if (
                    durable_identity_api
                    and durable_identity is None
                    and ownership_state in {"UNKNOWN", "EXTERNAL_PROCESS_GOVERNED"}
                    and (
                        ownership_state == "EXTERNAL_PROCESS_GOVERNED"
                        or
                        candidate_run_state in {"STARTING", "RUNNING"}
                        or candidate.get("process_id") is not None
                        or ownership_state == "UNKNOWN"
                    )
                ):
                    message = "durable process identity unavailable; execution recovery remains fenced"
                    logger.warning(
                        "Execution recovery deferred: identity unavailable execution_id=%s",
                        execution_id,
                    )
                    record_recovery = getattr(
                        database, "record_unavailable_governed_recovery", None
                    )
                    if callable(record_recovery):
                        attempt_number = int(candidate.get("attempt_number") or 0) + 1
                        exhausted = attempt_number >= max_recovery_attempts
                        retry_at = None if exhausted else datetime.now(timezone.utc) + timedelta(
                            seconds=min(300, 5 * (2 ** min(attempt_number - 1, 6)))
                        )
                        persisted = await self._durable_recovery_write(
                            "record-identity-unavailable",
                            record_recovery,
                            execution_id,
                            candidate["organization_id"],
                            # Before launch ownership is intentionally an
                            # unbound UNKNOWN/NONE row.  The run's generation
                            # is the durable authority fence; the DAL accepts
                            # the initial unbound shape only after re-reading
                            # the tenant/run/decision binding in its transaction.
                            worker_generation=candidate.get("run_worker_generation"),
                            recovery_worker_identity=recovery_owner,
                            recovery_worker_generation=recovery_worker_generation,
                            outcome="identity_unavailable",
                            error=message,
                            next_retry_at=retry_at,
                            exhausted=exhausted,
                            actor="execution-reaper",
                        )
                        if not persisted:
                            raise RuntimeError(
                                "durable identity-unavailable recovery outcome was not committed"
                            )
                    self._state = ObservationState(
                        last_started_at=self._state.last_started_at,
                        last_completed_at=self._state.last_completed_at,
                        last_error=self._state.last_error,
                        last_recovery_error=message,
                        last_recovered_count=reaped,
                    )
                    continue

                if self._supervisor_cancellation_requires_reconciliation(
                    execution_id=execution_id,
                    organization_id=candidate["organization_id"],
                ):
                    continue
                try:
                    cancellation = await self._owned_supervisor_cancellation(
                        execution_id=execution_id,
                        organization_id=candidate["organization_id"],
                        process_identity=(
                            durable_identity
                            if durable_identity_api and durable_identity is not None
                            else None
                        ),
                        recovery_worker_generation=recovery_worker_generation,
                        recovery_attempt=int(candidate.get("attempt_number") or 0) + 1,
                    )
                except asyncio.TimeoutError:
                    # ``shield`` leaves the identity-bound supervisor call
                    # running.  Its timeout is still durable evidence of
                    # incomplete recovery, so preserve the exact identity
                    # and make a bounded retry visible to recovery health.
                    message = (
                        f"unconfirmed process termination timeout: execution_id={execution_id}"
                    )[:512]
                    if durable_identity_api and durable_identity is not None:
                        attempt_number = int(candidate.get("attempt_number") or 0) + 1
                        exhausted = attempt_number >= max_recovery_attempts
                        _status, retry_at = self._retry_at(
                            attempt_number,
                            max_recovery_attempts,
                        )
                        persisted = await self._durable_recovery_write(
                            "record-governed-timeout",
                            database.record_unconfirmed_governed_recovery,
                            execution_id,
                            candidate["organization_id"],
                            process_id=durable_identity.pid,
                            process_group_id=(
                                str(durable_identity.process_group_id)
                                if durable_identity.process_group_id is not None else None
                            ),
                            process_start_token=durable_identity.start_token,
                            session_id=durable_identity.session_id,
                            recovery_worker_identity=recovery_owner,
                            recovery_worker_generation=recovery_worker_generation,
                            termination_status="TIMEOUT",
                            outcome="termination_timeout",
                            error="identity-bound termination exceeded the recovery timeout; automatic recovery remains fenced",
                            next_retry_at=retry_at,
                            exhausted=exhausted,
                            actor="execution-reaper",
                        )
                        if not persisted:
                            raise RuntimeError(
                                "timed-out governed recovery outcome was not committed"
                            )
                    self._record_recovery_error(message, reaped)
                    continue
                termination_status = self._termination_status(
                    cancellation,
                    execution_id,
                )
                confirmed = termination_status in {"KILLED", "ALREADY_EXITED"}
                if (
                    candidate.get("process_id") is not None
                    or candidate_run_state == "RUNNING"
                    or durable_identity_api
                ) and not confirmed:
                    message = (
                        f"unconfirmed process termination: execution_id={execution_id} "
                        f"status={termination_status}"
                    )[:512]
                    logger.warning(
                        "Execution recovery deferred: termination not confirmed execution_id=%s status=%s",
                        execution_id, termination_status,
                    )
                    if durable_identity_api and durable_identity is not None:
                        attempt_number = int(candidate.get("attempt_number") or 0) + 1
                        exhausted = attempt_number >= max_recovery_attempts
                        _status, retry_at = self._retry_at(
                            attempt_number,
                            max_recovery_attempts,
                        )
                        persisted = await self._durable_recovery_write(
                            "record-governed-unconfirmed",
                            database.record_unconfirmed_governed_recovery,
                            execution_id,
                            candidate["organization_id"],
                            process_id=durable_identity.pid,
                            process_group_id=(str(durable_identity.process_group_id) if durable_identity.process_group_id is not None else None),
                            process_start_token=durable_identity.start_token,
                            session_id=durable_identity.session_id,
                            recovery_worker_identity=recovery_owner,
                            recovery_worker_generation=recovery_worker_generation,
                            termination_status=termination_status,
                            outcome=f"termination_{termination_status.lower()}",
                            error="termination was not confirmed; automatic recovery remains fenced",
                            next_retry_at=retry_at,
                            exhausted=exhausted,
                            actor="execution-reaper",
                        )
                        if not persisted:
                            raise RuntimeError(
                                "durable unconfirmed recovery outcome was not committed"
                            )
                    self._state = ObservationState(
                        last_started_at=self._state.last_started_at,
                        last_completed_at=self._state.last_completed_at,
                        last_error=self._state.last_error,
                        last_recovery_error=message,
                        last_recovered_count=reaped,
                    )
                    continue

                if durable_identity_api:
                    run_snapshot = await asyncio.wait_for(
                        asyncio.to_thread(
                            database.get_execution_run,
                            execution_id,
                            candidate["organization_id"],
                        ),
                        timeout=self.refresh_timeout_seconds,
                    )
                    closed = await self._durable_recovery_write(
                        "settle-confirmed-termination",
                        database.settle_execution_after_confirmed_termination,
                        execution_id,
                        candidate["organization_id"],
                        terminal_state=candidate["terminal_state"],
                        reason_code=candidate["reason_code"],
                        termination_status=termination_status,
                        process_id=durable_identity.pid,
                        process_group_id=(str(durable_identity.process_group_id) if durable_identity.process_group_id is not None else None),
                        process_start_token=durable_identity.start_token,
                        session_id=durable_identity.session_id,
                        worker_generation=(ownership or {}).get("worker_generation"),
                        worker_identity=(run_snapshot or {}).get("worker_identity"),
                        actor="execution-reaper",
                    )
                else:
                    closed = await self._durable_recovery_write(
                        "reap-legacy-dispatch",
                        database.reap_execution_dispatch,
                        execution_id,
                        candidate["organization_id"],
                        terminal_state=candidate["terminal_state"],
                        reason_code=candidate["reason_code"],
                        actor="execution-reaper",
                    )
                if closed:
                    reaped += 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"[:512]
                logger.warning(
                    "Execution authority recovery candidate failed: execution_id=%s error=%s",
                    execution_id, message,
                )
                self._state = ObservationState(
                    last_started_at=self._state.last_started_at,
                    last_completed_at=self._state.last_completed_at,
                    last_error=self._state.last_error,
                    last_recovery_error=message,
                    last_recovered_count=reaped,
                )
        self._state = ObservationState(
            last_started_at=self._state.last_started_at,
            last_completed_at=self._state.last_completed_at,
            last_error=self._state.last_error,
            last_recovery_error=self._state.last_recovery_error,
            last_recovered_count=reaped,
        )
        return reaped

    async def _run(self) -> None:
        try:
            while True:
                await self.refresh_once()
                await self.reap_execution_authority_once()
                await asyncio.sleep(self.interval_seconds)
        except asyncio.CancelledError:
            raise

    def start(self) -> asyncio.Task[None]:
        """Start exactly one task for the current event loop."""
        if self.running:
            return self._task  # type: ignore[return-value]
        # A completed future may have been unable to schedule its callback
        # because the previous loop closed.  Reconcile it synchronously so a
        # completed operation does not create a false same-instance restart
        # fence; only unresolved actual work remains a blocker.
        self._reconcile_completed_owned_operations()
        if self._pending_durable_writes:
            # The same service instance may not begin another observation
            # lifecycle while it still owns a database transaction from the
            # previous one.  A fresh process relies on the existing durable
            # recovery projection, but an in-memory restart must not overlap
            # or hide a pending write.
            raise RuntimeError(
                "observation service cannot restart while a durable recovery write is unresolved"
            )
        if self._pending_supervisor_cancellations:
            raise RuntimeError(
                "observation service cannot restart while a supervisor cancellation is unresolved"
            )
        if self._recovery_workers:
            # An ordinary cancellation-resistant worker has no durable-write
            # authority, but it still belongs to the prior lifecycle.  A new
            # observer must not overlap it or hide its pending state.
            raise RuntimeError(
                "observation service cannot restart while a recovery worker is unresolved"
            )
        if (
            self._stopping_lifecycle_task is not None
            and not self._stopping_lifecycle_task.done()
        ):
            raise RuntimeError(
                "observation service cannot restart while its prior lifecycle task is stopping"
            )
        self._stopping_lifecycle_task = None
        self._task = asyncio.create_task(self._run(), name="cyberassess-tool-observation")
        return self._task

    async def stop(self) -> None:
        deadline = asyncio.get_running_loop().time() + self.shutdown_timeout_seconds

        def remaining_timeout() -> float:
            return max(0.0, deadline - asyncio.get_running_loop().time())

        self._reconcile_completed_owned_operations()

        task = self._task
        if task is not None:
            task.cancel()
            try:
                await asyncio.wait_for(
                    asyncio.shield(task),
                    timeout=remaining_timeout(),
                )
            except asyncio.CancelledError:
                pass
            except asyncio.TimeoutError:
                self._record_recovery_error(
                    "observation shutdown timed out; recovery work remains visible",
                    self._state.last_recovered_count,
                )
            except Exception as exc:
                self._record_recovery_error(
                    f"observation shutdown failed: {type(exc).__name__}",
                    self._state.last_recovered_count,
                )
            if not task.done():
                # A cancellation-resistant lifecycle task must remain
                # observable and owned by the same bounded shutdown path; it
                # must not be silently abandoned or accidentally restarted.
                self._stopping_lifecycle_task = task
                self._track_recovery_worker(task)
                task.add_done_callback(self._clear_stopping_lifecycle_task)
            self._task = None

        # A thread-backed database operation is not an asyncio worker: task
        # cancellation cannot reliably stop it after it begins.  Give each
        # submitted operation only the remaining graceful-shutdown budget,
        # but never cancel its actual Future or discard its ownership.
        pending_writes = tuple(
            operation
            for operation in self._pending_durable_writes.values()
            if not operation.future.done()
        )
        if pending_writes:
            for operation in pending_writes:
                operation.shutdown_pending = True
                self._record_pending_durable_write(
                    operation,
                    condition="pending at shutdown",
                )
            await asyncio.wait(
                [self._durable_write_waiter(operation) for operation in pending_writes],
                timeout=remaining_timeout(),
            )
            # Let completion callbacks consume completed concurrent futures
            # before assessing the residual ownership set.
            await asyncio.sleep(0)
            if self._pending_durable_writes:
                self._record_recovery_error(
                    "durable recovery write shutdown timed out; reconciliation remains required",
                    self._state.last_recovered_count,
                )
        # An exact supervisor cancellation can affect a process tree after its
        # asyncio waiter times out.  It is not a generic recovery worker and
        # must never be cancelled through the task-cancellation loop below.
        pending_supervisor_cancellations = tuple(
            operation
            for operation in self._pending_supervisor_cancellations.values()
            if not operation.future.done()
        )
        if pending_supervisor_cancellations:
            for operation in pending_supervisor_cancellations:
                operation.shutdown_pending = True
                self._record_pending_supervisor_cancellation(
                    operation,
                    condition="pending at shutdown",
                )
            await asyncio.wait(
                [
                    self._supervisor_cancellation_waiter(operation)
                    for operation in pending_supervisor_cancellations
                ],
                timeout=remaining_timeout(),
            )
            await asyncio.sleep(0)
            if self._pending_supervisor_cancellations:
                self._record_recovery_error(
                    "supervisor cancellation shutdown timed out; reconciliation remains required",
                    self._state.last_recovered_count,
                )
        if self._recovery_workers:
            workers = tuple(self._recovery_workers)
            _done, pending = await asyncio.wait(
                workers,
                timeout=remaining_timeout(),
            )
            if pending:
                for worker in pending:
                    worker.cancel()
                _done_after_cancel, _still_pending = await asyncio.wait(
                    pending,
                    timeout=remaining_timeout(),
                )
                if _still_pending:
                    if not self._pending_durable_writes:
                        self._record_recovery_error(
                            "recovery worker shutdown timed out; late result remains isolated",
                            self._state.last_recovered_count,
                        )

    def _clear_stopping_lifecycle_task(self, task: asyncio.Task[Any]) -> None:
        """Clear the restart fence only when the owned lifecycle task exits."""
        if self._stopping_lifecycle_task is task:
            self._stopping_lifecycle_task = None


__all__ = ["BackendObservationService", "ObservationState"]
