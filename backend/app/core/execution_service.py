"""Single execution-service boundary for durable launch and terminal settlement."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.core.execution_context import (
    PosixProcessAttestation,
    _ISSUER_TOKEN,
    _issue_non_scan_execution_context,
    canonical_binding_digest,
)
from app.core.db import _ACTIVE_DATABASE_CONNECTION
from app.core.models import (
    ExecutionProcessOwnershipRecord,
    EXECUTION_REASON_CODES,
    ProcessContainerType,
    ProcessOwnershipState,
    LaunchCommitState,
    utc_now,
)


_PROCESS_WORKER_GENERATION = os.environ.get("CYBERASSESS_WORKER_GENERATION", "").strip() or f"process-{uuid.uuid4().hex}"


def get_worker_identity() -> str:
    """Return the deployment-configured worker identity used by the execution plane."""
    return os.environ.get("CYBERASSESS_WORKER_IDENTITY", "local-worker").strip()


def get_worker_generation() -> str:
    """Return the process/deployment generation bound to durable execution evidence."""
    return _PROCESS_WORKER_GENERATION


@dataclass(frozen=True)
class ExecutionCancellationOutcome:
    """Evidence returned by the single execution cancellation coordinator."""

    execution_id: Optional[str]
    request_id: str
    authority_revoked: bool
    process_status: str
    process_confirmed: bool
    durable_terminal: bool
    task_stopped: bool
    recovery_required: bool
    reason_code: Optional[str] = None
    error_code: Optional[str] = None

    @property
    def confirmed(self) -> bool:
        """Return true only when no process or a durable terminal run is proven."""
        return self.task_stopped and self.durable_terminal and (
            self.process_confirmed
            or self.reason_code == "EXECUTION_CANCELLED_BEFORE_DISPATCH"
            or self.execution_id is None
        )


class ExecutionCancellationCoordinator:
    """Own revocation, exact process cancellation, task shutdown, and settlement checks.

    All callers use this boundary instead of independently revoking a request,
    signalling a PID, or publishing a terminal result.  A missing in-memory
    process mapping is deliberately surfaced as ``NOT_FOUND`` and remains
    recoverable unless the durable database transition proves that the run was
    cancelled before any dispatch claim could occur.
    """

    _TERMINAL_RUN_STATES = frozenset({
        "SUCCEEDED",
        "PARTIAL_RESULTS_WITH_WARNING",
        "FAILED",
        "TIMED_OUT",
        "CANCELLED",
        "EXECUTION_BLOCKED",
    })

    def __init__(self, database: Any, supervisor: Any = None) -> None:
        self._database = database
        self._supervisor = supervisor

    @property
    def supervisor(self) -> Any:
        if self._supervisor is None:
            from app.core.process_supervisor import process_supervisor

            self._supervisor = process_supervisor
        return self._supervisor

    @staticmethod
    async def stop_task(task: Optional[asyncio.Task], *, timeout_seconds: float = 5.0) -> bool:
        """Stop one owning task and wait for its cancellation acknowledgement."""
        if task is None or task.done():
            return True
        task.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=timeout_seconds)
        except asyncio.CancelledError:
            return True
        except asyncio.TimeoutError:
            return False
        except Exception:
            return False
        return task.done()

    @staticmethod
    def _outcome(
        *,
        execution_id: Optional[str],
        request_id: str,
        authority_revoked: bool,
        process_status: str,
        process_confirmed: bool,
        durable_terminal: bool,
        task_stopped: bool,
        reason_code: Optional[str] = None,
        error_code: Optional[str] = None,
    ) -> ExecutionCancellationOutcome:
        outcome = ExecutionCancellationOutcome(
            execution_id=execution_id,
            request_id=request_id,
            authority_revoked=authority_revoked,
            process_status=process_status,
            process_confirmed=process_confirmed,
            durable_terminal=durable_terminal,
            task_stopped=task_stopped,
            recovery_required=not (
                task_stopped
                and durable_terminal
                and (process_confirmed or reason_code == "EXECUTION_CANCELLED_BEFORE_DISPATCH" or execution_id is None)
            ),
            reason_code=reason_code,
            error_code=error_code,
        )
        return outcome

    async def cancel_request(
        self,
        request_id: str,
        organization_id: str,
        *,
        actor: str,
        owning_task: Optional[asyncio.Task] = None,
    ) -> ExecutionCancellationOutcome:
        """Cancel one exact tenant-bound execution request.

        Revocation is committed before process cancellation, preventing a
        concurrent worker from creating a new governed process.  The process
        supervisor is then called by exact execution identity.  Only a durable
        terminal run plus a confirmed process outcome (or an atomic
        pre-dispatch cancellation) is reported as confirmed.
        """
        if not isinstance(request_id, str) or not request_id.strip() or not isinstance(organization_id, str) or not organization_id.strip() or not isinstance(actor, str) or not actor.strip():
            return self._outcome(
                execution_id=None,
                request_id=str(request_id or ""),
                authority_revoked=False,
                process_status="INVALID_REQUEST",
                process_confirmed=False,
                durable_terminal=False,
                task_stopped=False,
                error_code="INVALID_CANCELLATION_REQUEST",
            )

        try:
            run = await asyncio.to_thread(
                self._database.get_execution_run_for_request,
                request_id,
                organization_id,
            )
        except Exception as exc:
            return self._outcome(
                execution_id=None,
                request_id=request_id,
                authority_revoked=False,
                process_status="FAILED",
                process_confirmed=False,
                durable_terminal=False,
                task_stopped=False,
                error_code=type(exc).__name__,
            )

        if run is None:
            try:
                revoked = await asyncio.to_thread(
                    self._database.revoke_execution_request,
                    request_id,
                    organization_id,
                    actor,
                )
            except Exception as exc:
                return self._outcome(
                    execution_id=None,
                    request_id=request_id,
                    authority_revoked=False,
                    process_status="FAILED",
                    process_confirmed=False,
                    durable_terminal=False,
                    task_stopped=False,
                    error_code=type(exc).__name__,
                )
            task_stopped = await self.stop_task(owning_task)
            return self._outcome(
                execution_id=None,
                request_id=request_id,
                authority_revoked=bool(revoked),
                process_status="NOT_FOUND" if revoked else "FAILED",
                process_confirmed=False,
                durable_terminal=bool(revoked),
                task_stopped=task_stopped,
                reason_code="EXECUTION_CANCELLED_BEFORE_DISPATCH" if revoked else None,
                error_code=None if revoked else "EXECUTION_REQUEST_NOT_FOUND",
            )

        execution_id = str(run.get("execution_id") or "")
        if not execution_id:
            return self._outcome(
                execution_id=None,
                request_id=request_id,
                authority_revoked=False,
                process_status="FAILED",
                process_confirmed=False,
                durable_terminal=False,
                task_stopped=False,
                error_code="EXECUTION_IDENTITY_MISSING",
            )
        if run.get("state") in self._TERMINAL_RUN_STATES:
            try:
                revoked = await asyncio.to_thread(
                    self._database.revoke_execution_request,
                    request_id,
                    organization_id,
                    actor,
                )
            except Exception as exc:
                return self._outcome(
                    execution_id=execution_id,
                    request_id=request_id,
                    authority_revoked=False,
                    process_status="FAILED",
                    process_confirmed=False,
                    durable_terminal=True,
                    task_stopped=False,
                    reason_code=run.get("reason_code"),
                    error_code=type(exc).__name__,
                )
            task_stopped = await self.stop_task(owning_task)
            return self._outcome(
                execution_id=execution_id,
                request_id=request_id,
                authority_revoked=bool(revoked),
                process_status="ALREADY_EXITED" if revoked else "FAILED",
                process_confirmed=bool(revoked),
                durable_terminal=True,
                task_stopped=task_stopped,
                reason_code=run.get("reason_code"),
                error_code=None if revoked else "EXECUTION_AUTHORITY_NOT_REVOKED",
            )

        try:
            revoked = await asyncio.to_thread(
                self._database.revoke_execution_request,
                request_id,
                organization_id,
                actor,
            )
        except Exception as exc:
            return self._outcome(
                execution_id=execution_id,
                request_id=request_id,
                authority_revoked=False,
                process_status="FAILED",
                process_confirmed=False,
                durable_terminal=False,
                task_stopped=False,
                error_code=type(exc).__name__,
            )
        if not revoked:
            return self._outcome(
                execution_id=execution_id,
                request_id=request_id,
                authority_revoked=False,
                process_status="FAILED",
                process_confirmed=False,
                durable_terminal=False,
                task_stopped=False,
                error_code="EXECUTION_AUTHORITY_NOT_REVOKED",
            )

        try:
            after_revoke = await asyncio.to_thread(
                self._database.get_execution_run,
                execution_id,
                organization_id,
            )
        except Exception as exc:
            return self._outcome(
                execution_id=execution_id,
                request_id=request_id,
                authority_revoked=True,
                process_status="FAILED",
                process_confirmed=False,
                durable_terminal=False,
                task_stopped=False,
                error_code=type(exc).__name__,
            )

        # revoke_execution_request atomically closes a REQUESTED/PENDING child
        # before any dispatch claim.  That database transition is the only
        # accepted no-process proof for a missing supervisor mapping.
        if (
            after_revoke
            and after_revoke.get("state") == "CANCELLED"
            and after_revoke.get("reason_code") == "EXECUTION_CANCELLED_BEFORE_DISPATCH"
        ):
            task_stopped = await self.stop_task(owning_task)
            return self._outcome(
                execution_id=execution_id,
                request_id=request_id,
                authority_revoked=True,
                process_status="NOT_FOUND",
                process_confirmed=False,
                durable_terminal=True,
                task_stopped=task_stopped,
                reason_code="EXECUTION_CANCELLED_BEFORE_DISPATCH",
            )

        try:
            cancellation = await asyncio.to_thread(
                self.supervisor.cancel_execution,
                execution_id,
            )
            process_status = getattr(getattr(cancellation, "status", None), "value", str(getattr(cancellation, "status", "UNKNOWN")))
            process_confirmed = bool(getattr(cancellation, "confirmed", False))
        except Exception as exc:
            process_status = "FAILED"
            process_confirmed = False
            error_code = type(exc).__name__
        else:
            error_code = None

        task_stopped = await self.stop_task(owning_task)
        try:
            final_run = await asyncio.to_thread(
                self._database.get_execution_run,
                execution_id,
                organization_id,
            )
        except Exception as exc:
            final_run = None
            error_code = error_code or type(exc).__name__
        durable_terminal = bool(final_run and final_run.get("state") in self._TERMINAL_RUN_STATES)
        return self._outcome(
            execution_id=execution_id,
            request_id=request_id,
            authority_revoked=True,
            process_status=process_status,
            process_confirmed=process_confirmed,
            durable_terminal=durable_terminal,
            task_stopped=task_stopped,
            reason_code=final_run.get("reason_code") if final_run else None,
            error_code=error_code,
        )


def issue_non_scan_execution_context(purpose: str, *, ttl_seconds: int = 300):
    """Issue an installer/observation capability from the execution service.

    Worker identity and generation are process-owned values; callers may select
    only a registered purpose and bounded lifetime.  This capability is never
    eligible for scan authorization or scan terminalization.
    """
    worker_identity = get_worker_identity()
    return _issue_non_scan_execution_context(
        purpose,
        ttl_seconds=ttl_seconds,
        issuer=_ISSUER_TOKEN,
        worker_identity=worker_identity,
        worker_generation=_PROCESS_WORKER_GENERATION,
    )


def record_no_process(capability: Any, *, proof_code: str, reason_code: str) -> bool:
    """Persist an explicit no-process result before terminal settlement."""
    if reason_code not in EXECUTION_REASON_CODES or not capability.execution_id:
        return False
    proof_material = {
        "schema_version": "no-process-proof-v1",
        "execution_id": capability.execution_id,
        "decision_id": capability.decision.id,
        "claim_token": capability.claim_token,
        "dispatch_claim_token": capability.dispatch_claim_token,
        "worker_identity": capability.worker_identity,
        "worker_generation": capability.worker_generation,
        "proof_code": proof_code,
        "reason_code": reason_code,
        "observed_at": utc_now().isoformat(),
    }
    proof_digest = canonical_binding_digest(proof_material)
    record = ExecutionProcessOwnershipRecord(
        execution_id=capability.execution_id,
        organization_id=capability.decision.organization_id,
        ownership_state=ProcessOwnershipState.NO_EXTERNAL_PROCESS,
        container_type=ProcessContainerType.NONE,
        launch_commit_state=LaunchCommitState.NOT_ATTEMPTED,
        no_process_proof=f"NO_EXTERNAL_PROCESS:v1:{proof_digest}",
        correlation_id=f"corr-execution-{capability.execution_id}",
    )
    return capability.database.transition_process_ownership(
        record, ProcessOwnershipState.UNKNOWN, reason_code=reason_code,
    )


def record_posix_launch(capability: Any, *, pid: int, process_group_id: Optional[int], session_id: int, start_token: str) -> str:
    """Create and persist a canonical POSIX identity attestation and ownership."""
    if not capability.execution_id or not start_token.startswith("posix:"):
        raise ValueError("canonical POSIX process identity is required")
    parts = start_token.split(":", 2)
    if len(parts) != 3 or not parts[1] or not parts[2].isdigit() or pid <= 0 or session_id < 0:
        raise ValueError("POSIX process identity is malformed")
    captured = utc_now()
    expires = captured + timedelta(seconds=30)
    values = {
        "schema_version": "posix-process-attestation-v1",
        "proof_type": "PROC_START_TICKS_SESSION_GROUP",
        "boot_id": parts[1],
        "root_start_ticks": int(parts[2]),
        "session_id": session_id,
        "process_group_id": process_group_id if process_group_id is not None else pid,
        "pidfd_supported": False,
        "pidfd_verified": False,
        "worker_generation": getattr(capability, "worker_generation", "unknown-worker-generation"),
        "captured_at": captured,
        "expires_at": expires,
        "verification_result": "VERIFIED",
    }
    digest = canonical_binding_digest(values)
    attestation = PosixProcessAttestation(**values, digest=digest)
    record = ExecutionProcessOwnershipRecord(
        execution_id=capability.execution_id,
        organization_id=capability.decision.organization_id,
        ownership_state=ProcessOwnershipState.EXTERNAL_PROCESS_GOVERNED,
        container_type=ProcessContainerType.POSIX_SESSION,
        container_identity=f"posix-session:{session_id}:group:{process_group_id or pid}",
        root_process_id=pid,
        root_process_start_token=start_token,
        process_group_id=str(process_group_id or pid),
        session_id=str(session_id),
        worker_generation=attestation.worker_generation,
        launch_commit_state=LaunchCommitState.COMMITTED,
        identity_attestation=attestation.model_dump_json(exclude_none=True),
        correlation_id=f"corr-execution-{capability.execution_id}",
        launched_at=captured,
        last_verified_at=captured,
    )
    if not capability.database.transition_process_ownership(
        record, ProcessOwnershipState.UNKNOWN, reason_code="PROCESS_LAUNCH_COMMITTED",
    ):
        raise RuntimeError("durable process ownership commit failed")
    return attestation.model_dump_json(exclude_none=True)


def record_launch_uncertain(
    capability: Any,
    *,
    pid: Optional[int],
    process_group_id: Optional[int],
    start_token: Optional[str] = None,
) -> bool:
    """Persist post-creation uncertainty before any recovery decision."""
    if not capability.execution_id:
        return False
    record = ExecutionProcessOwnershipRecord(
        execution_id=capability.execution_id,
        organization_id=capability.decision.organization_id,
        ownership_state=ProcessOwnershipState.LAUNCH_UNCERTAIN,
        container_type=ProcessContainerType.POSIX_SESSION if process_group_id else ProcessContainerType.PROCESS_SET,
        container_identity=(f"posix-session:group:{process_group_id}" if process_group_id else None),
        root_process_id=pid,
        root_process_start_token=start_token,
        process_group_id=str(process_group_id) if process_group_id else None,
        worker_generation=capability.worker_generation,
        launch_commit_state=LaunchCommitState.UNCERTAIN,
        correlation_id=f"corr-execution-{capability.execution_id}",
        last_verified_at=utc_now(),
    )
    return capability.database.transition_process_ownership(
        record, ProcessOwnershipState.UNKNOWN, reason_code="PROCESS_LAUNCH_UNCERTAIN",
    )


def record_terminal(capability: Any, *, reason_code: str) -> bool:
    """Transition process ownership to terminal only after platform cleanup."""
    if not capability.execution_id:
        return False
    existing = capability.database.get_process_ownership(
        capability.execution_id, capability.decision.organization_id,
    )
    if not existing:
        return False
    current = ProcessOwnershipState(existing["ownership_state"])
    if current == ProcessOwnershipState.TERMINAL:
        return True
    record = ExecutionProcessOwnershipRecord(**{
        **existing,
        "ownership_state": ProcessOwnershipState.TERMINAL,
        "container_type": ProcessContainerType(existing["container_type"]),
        "launch_commit_state": LaunchCommitState(existing["launch_commit_state"]),
        "updated_at": utc_now(),
        "terminalized_at": utc_now(),
    })
    return capability.database.transition_process_ownership(record, current, reason_code=reason_code)


def settle_execution(
    capability: Any,
    *,
    terminal_state: str,
    reason_code: str,
    process_id: Optional[int] = None,
    process_group_id: Optional[str] = None,
) -> bool:
    """Coordinate durable ownership evidence and canonical run settlement."""
    if not capability.execution_id or not capability.dispatch_claim_token:
        return False
    class _SettlementRejected(Exception):
        """Internal rollback marker for a rejected multi-table settlement."""

    try:
        with capability.database._connection_scope() as conn:
            token = _ACTIVE_DATABASE_CONNECTION.set(conn)
            try:
                if process_id is None:
                    if not record_no_process(capability, proof_code=reason_code, reason_code=reason_code):
                        raise _SettlementRejected
                    settled = capability.database.abort_execution_start(
                        capability.decision.id, capability.decision.organization_id,
                        capability.worker_identity, capability.claim_token,
                        capability.dispatch_claim_token, terminal_state=terminal_state,
                        reason_code=reason_code,
                    )
                else:
                    if not record_terminal(capability, reason_code=reason_code):
                        raise _SettlementRejected
                    settled = capability.database.finish_execution(
                        capability.execution_id, capability.decision.organization_id,
                        capability.worker_identity, capability.dispatch_claim_token,
                        terminal_state=terminal_state, reason_code=reason_code,
                        process_id=process_id, process_group_id=process_group_id,
                    )
                if not settled:
                    raise _SettlementRejected
            finally:
                _ACTIVE_DATABASE_CONNECTION.reset(token)
    except _SettlementRejected:
        return False
    return True


__all__ = [
    "ExecutionCancellationCoordinator",
    "ExecutionCancellationOutcome",
    "record_no_process",
    "record_posix_launch",
    "record_launch_uncertain",
    "record_terminal",
    "settle_execution",
]
