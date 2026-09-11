"""Lifecycle-managed backend observation of the 26-tool fleet.

Observations are deliberately separate from authentication and execution
authorization.  The service refreshes process-local snapshots only; every
execution path retains its own live trust and version checks.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.adapters import get_cached_system_capabilities
from app.installers.manager import ToolInstallationManager

logger = logging.getLogger("cyberassess.observation")

DEFAULT_INTERVAL_SECONDS = 60.0
DEFAULT_REFRESH_TIMEOUT_SECONDS = 120.0


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


@dataclass(frozen=True)
class ObservationState:
    last_started_at: Optional[datetime] = None
    last_completed_at: Optional[datetime] = None
    last_error: Optional[str] = None
    last_recovery_error: Optional[str] = None
    last_recovered_count: int = 0


class BackendObservationService:
    """Refreshes backend-owned capability and toolbox snapshots periodically."""

    def __init__(
        self,
        *,
        interval_seconds: Optional[float] = None,
        refresh_timeout_seconds: Optional[float] = None,
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
        self._refresh_lock = asyncio.Lock()
        self._recovery_lock = asyncio.Lock()
        self._recovery_workers: set[asyncio.Task] = set()
        self._task: Optional[asyncio.Task[None]] = None
        self._state = ObservationState()

    @property
    def state(self) -> ObservationState:
        return self._state

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

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
        from app.core.db import db_manager
        from app.core.process_supervisor import process_supervisor
        from app.core.execution_service import (
            get_worker_generation,
            load_durable_process_identity,
        )

        recovery_owner = "execution-recovery-coordinator"
        recovery_worker_generation = get_worker_generation()
        max_recovery_attempts = 5
        durable_identity_api = callable(getattr(db_manager, "get_process_ownership", None))

        try:
            candidates = await asyncio.wait_for(
                asyncio.to_thread(db_manager.list_execution_recovery_candidates),
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
                try:
                    lease = await asyncio.wait_for(
                        asyncio.to_thread(
                            db_manager.claim_recovery,
                            execution_id,
                            candidate["organization_id"],
                            recovery_owner,
                            recovery_worker_generation,
                            lease_seconds=30,
                        ),
                        timeout=self.refresh_timeout_seconds,
                    )
                    if not lease:
                        continue
                    durable_identity = None
                    if durable_identity_api:
                        durable_identity = await asyncio.wait_for(
                            asyncio.to_thread(
                                load_durable_process_identity,
                                db_manager,
                                execution_id,
                                candidate["organization_id"],
                            ),
                            timeout=self.refresh_timeout_seconds,
                        )
                        if durable_identity is None:
                            attempt_number = int(lease["attempt_number"])
                            status = "EXHAUSTED" if attempt_number >= max_recovery_attempts else "DEFERRED"
                            retry_at = None if status == "EXHAUSTED" else datetime.now(timezone.utc) + timedelta(
                                seconds=min(300, 5 * (2 ** min(attempt_number - 1, 6)))
                            )
                            await asyncio.wait_for(
                                asyncio.to_thread(
                                    db_manager.complete_recovery,
                                    execution_id,
                                    candidate["organization_id"],
                                    recovery_owner,
                                    lease["lease_token"],
                                    recovery_worker_generation,
                                    status=status,
                                    outcome="durable_identity_unavailable",
                                    error="persisted process identity could not be validated; recovery remains fenced",
                                    next_retry_at=retry_at,
                                ),
                                timeout=self.refresh_timeout_seconds,
                            )
                            continue
                    cancellation_task = asyncio.create_task(
                        asyncio.to_thread(
                            process_supervisor.cancel_execution,
                            execution_id,
                            **({"process_identity": durable_identity} if durable_identity_api else {}),
                        )
                    )
                    self._recovery_workers.add(cancellation_task)
                    cancellation_task.add_done_callback(self._recovery_workers.discard)
                    cancellation = await asyncio.wait_for(
                        asyncio.shield(cancellation_task),
                        timeout=self.refresh_timeout_seconds,
                    )
                    if getattr(cancellation, "confirmed", bool(cancellation)):
                        closed = await asyncio.wait_for(
                            asyncio.to_thread(
                                db_manager.settle_recovery_execution,
                                execution_id,
                                candidate["organization_id"],
                                recovery_owner,
                                lease["lease_token"],
                                recovery_worker_generation,
                            ),
                            timeout=self.refresh_timeout_seconds,
                        )
                        if closed:
                            reaped += 1
                        continue
                    attempt_number = int(lease["attempt_number"])
                    status = "EXHAUSTED" if attempt_number >= max_recovery_attempts else "DEFERRED"
                    retry_at = None if status == "EXHAUSTED" else datetime.now(timezone.utc) + timedelta(
                        seconds=min(300, 5 * (2 ** min(attempt_number - 1, 6)))
                    )
                    await asyncio.wait_for(
                        asyncio.to_thread(
                            db_manager.complete_recovery,
                            execution_id,
                            candidate["organization_id"],
                            recovery_owner,
                            lease["lease_token"],
                            recovery_worker_generation,
                            status=status,
                            outcome=f"termination_{getattr(cancellation, 'status', 'UNKNOWN').lower()}",
                            error="termination was not confirmed; automatic recovery remains fenced",
                            next_retry_at=retry_at,
                        ),
                        timeout=self.refresh_timeout_seconds,
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
                            db_manager.get_process_ownership,
                            execution_id,
                            candidate["organization_id"],
                        ),
                        timeout=self.refresh_timeout_seconds,
                    )
                    durable_identity = await asyncio.wait_for(
                        asyncio.to_thread(
                            load_durable_process_identity,
                            db_manager,
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
                    closed = await asyncio.wait_for(
                        asyncio.to_thread(
                            db_manager.settle_execution_after_confirmed_termination,
                            execution_id,
                            candidate["organization_id"],
                            terminal_state=pre_dispatch_terminal_state,
                            reason_code=pre_dispatch_reason,
                            termination_status="PRE_DISPATCH",
                            worker_generation=(ownership or {}).get("worker_generation"),
                            actor="execution-reaper",
                        ),
                        timeout=self.refresh_timeout_seconds,
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
                        closed = await asyncio.wait_for(
                            asyncio.to_thread(
                                db_manager.settle_execution_after_confirmed_termination,
                                execution_id,
                                candidate["organization_id"],
                                terminal_state=no_process_outcome[0],
                                reason_code=no_process_outcome[1],
                                termination_status="NO_EXTERNAL_PROCESS",
                                worker_generation=(ownership or {}).get("worker_generation"),
                                actor="execution-reaper",
                            ),
                            timeout=self.refresh_timeout_seconds,
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
                        db_manager, "record_unavailable_governed_recovery", None
                    )
                    if callable(record_recovery):
                        attempt_number = int(candidate.get("attempt_number") or 0) + 1
                        exhausted = attempt_number >= max_recovery_attempts
                        retry_at = None if exhausted else datetime.now(timezone.utc) + timedelta(
                            seconds=min(300, 5 * (2 ** min(attempt_number - 1, 6)))
                        )
                        persisted = await asyncio.wait_for(
                            asyncio.to_thread(
                                record_recovery,
                                execution_id,
                                candidate["organization_id"],
                                worker_generation=(ownership or {}).get("worker_generation"),
                                recovery_worker_identity=recovery_owner,
                                recovery_worker_generation=recovery_worker_generation,
                                outcome="identity_unavailable",
                                error=message,
                                next_retry_at=retry_at,
                                exhausted=exhausted,
                                actor="execution-reaper",
                            ),
                            timeout=self.refresh_timeout_seconds,
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

                cancellation_kwargs = (
                    {"process_identity": durable_identity}
                    if durable_identity_api and durable_identity is not None
                    else {}
                )
                cancellation_task = asyncio.create_task(
                    asyncio.to_thread(
                        process_supervisor.cancel_execution,
                        execution_id,
                        **cancellation_kwargs,
                    )
                )
                self._recovery_workers.add(cancellation_task)
                cancellation_task.add_done_callback(self._recovery_workers.discard)
                cancellation = await asyncio.wait_for(
                    asyncio.shield(cancellation_task),
                    timeout=self.refresh_timeout_seconds,
                )
                confirmed = getattr(cancellation, "confirmed", bool(cancellation))
                if (
                    candidate.get("process_id") is not None
                    or candidate_run_state == "RUNNING"
                    or durable_identity_api
                ) and not confirmed:
                    message = (
                        f"unconfirmed process termination: execution_id={execution_id} "
                        f"status={getattr(cancellation, 'status', 'UNKNOWN')}"
                    )[:512]
                    logger.warning(
                        "Execution recovery deferred: termination not confirmed execution_id=%s status=%s",
                        execution_id, getattr(cancellation, "status", "UNKNOWN"),
                    )
                    if durable_identity_api and durable_identity is not None:
                        attempt_number = int(candidate.get("attempt_number") or 0) + 1
                        exhausted = attempt_number >= max_recovery_attempts
                        retry_at = None if exhausted else datetime.now(timezone.utc) + timedelta(
                            seconds=min(300, 5 * (2 ** min(attempt_number - 1, 6)))
                        )
                        termination_status = getattr(
                            getattr(cancellation, "status", None),
                            "value",
                            str(getattr(cancellation, "status", "UNKNOWN")),
                        )
                        persisted = await asyncio.wait_for(
                            asyncio.to_thread(
                                db_manager.record_unconfirmed_governed_recovery,
                                execution_id,
                                candidate["organization_id"],
                                process_id=durable_identity.pid,
                                process_group_id=str(durable_identity.process_group_id),
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
                            ),
                            timeout=self.refresh_timeout_seconds,
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
                            db_manager.get_execution_run,
                            execution_id,
                            candidate["organization_id"],
                        ),
                        timeout=self.refresh_timeout_seconds,
                    )
                    termination_status = getattr(
                        getattr(cancellation, "status", None),
                        "value",
                        str(getattr(cancellation, "status", "UNKNOWN")),
                    )
                    closed = await asyncio.wait_for(
                        asyncio.to_thread(
                            db_manager.settle_execution_after_confirmed_termination,
                            execution_id,
                            candidate["organization_id"],
                            terminal_state=candidate["terminal_state"],
                            reason_code=candidate["reason_code"],
                            termination_status=termination_status,
                            process_id=durable_identity.pid,
                            process_group_id=str(durable_identity.process_group_id),
                            process_start_token=durable_identity.start_token,
                            session_id=durable_identity.session_id,
                            worker_generation=(ownership or {}).get("worker_generation"),
                            worker_identity=(run_snapshot or {}).get("worker_identity"),
                            actor="execution-reaper",
                        ),
                        timeout=self.refresh_timeout_seconds,
                    )
                else:
                    closed = await asyncio.wait_for(
                        asyncio.to_thread(
                            db_manager.reap_execution_dispatch,
                            execution_id,
                            candidate["organization_id"],
                            terminal_state=candidate["terminal_state"],
                            reason_code=candidate["reason_code"],
                            actor="execution-reaper",
                        ),
                        timeout=self.refresh_timeout_seconds,
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
        self._task = asyncio.create_task(self._run(), name="cyberassess-tool-observation")
        return self._task

    async def stop(self) -> None:
        task = self._task
        self._task = None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        if self._recovery_workers:
            await asyncio.gather(*tuple(self._recovery_workers), return_exceptions=True)


__all__ = ["BackendObservationService", "ObservationState"]
