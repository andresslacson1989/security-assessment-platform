"""Single execution-service boundary for durable launch and terminal settlement."""

from __future__ import annotations

import asyncio
import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.core.execution_context import (
    EXECUTION_PROOF_TERMINATION_KEYS,
    PosixProcessAttestation,
    _ISSUER_TOKEN,
    decode_execution_proof,
    _issue_non_scan_execution_context,
    canonical_binding_digest,
    encode_execution_proof,
    execution_claim_digest,
)
from app.core.db import _ACTIVE_DATABASE_CONNECTION
from app.core.models import (
    ExecutionProcessOwnershipRecord,
    EXECUTION_REASON_CODES,
    ProcessContainerType,
    ProcessOwnershipState,
    LaunchCommitState,
    is_valid_execution_terminal_outcome,
    utc_now,
)


_PROCESS_WORKER_GENERATION = os.environ.get("CYBERASSESS_WORKER_GENERATION", "").strip() or f"process-{uuid.uuid4().hex}"


def get_worker_identity() -> str:
    """Return the deployment-configured worker identity used by the execution plane."""
    return os.environ.get("CYBERASSESS_WORKER_IDENTITY", "local-worker").strip()


def get_worker_generation() -> str:
    """Return the process/deployment generation bound to durable execution evidence."""
    return _PROCESS_WORKER_GENERATION


def load_durable_process_identity(
    database: Any,
    execution_id: str,
    organization_id: str,
):
    """Reload the exact persisted POSIX identity for one active execution.

    The returned identity is suitable for the supervisor only after the
    tenant-bound run and ownership rows agree on every persisted field.  A
    current worker generation is deliberately *not* required: recovery after a
    worker restart must be able to use the previous worker's durable identity.
    The old generation is still checked for internal consistency, and malformed
    or Windows records fail closed.
    """
    from app.core.process_supervisor import ProcessIdentity

    if (
        not isinstance(execution_id, str)
        or not execution_id.strip()
        or not isinstance(organization_id, str)
        or not organization_id.strip()
    ):
        return None
    try:
        run = database.get_execution_run(execution_id, organization_id)
        ownership = database.get_process_ownership(execution_id, organization_id)
    except Exception:
        return None
    if not run or not ownership:
        return None
    if run.get("organization_id") != organization_id or ownership.get("organization_id") != organization_id:
        return None
    if run.get("execution_id") != execution_id or ownership.get("execution_id") != execution_id:
        return None
    if run.get("state") not in {"REQUESTED", "STARTING", "RUNNING"}:
        return None
    if ownership.get("ownership_state") in {"TERMINAL", "UNKNOWN", "NO_EXTERNAL_PROCESS"}:
        return None

    # Governed Windows execution is intentionally unsupported until the
    # supervisor has a verified Job Object implementation.  Do not turn a
    # legacy Windows-shaped row into an unbound PID operation.
    if ownership.get("container_type") != ProcessContainerType.POSIX_SESSION.value:
        return None
    if ownership.get("launch_commit_state") not in {
        LaunchCommitState.COMMITTED.value,
        LaunchCommitState.UNCERTAIN.value,
    }:
        return None
    try:
        pid = int(ownership.get("root_process_id"))
        group_id = int(str(ownership.get("process_group_id")))
        session_id = int(str(ownership.get("session_id")))
    except (TypeError, ValueError):
        return None
    if pid <= 1 or group_id <= 1 or session_id < 0:
        return None
    if ownership.get("container_identity") != f"posix-session:{session_id}:group:{group_id}":
        return None
    if run.get("process_id") is not None and int(run["process_id"]) != pid:
        return None
    if run.get("process_group_id") is not None and str(run["process_group_id"]) != str(group_id):
        return None

    start_token = ownership.get("root_process_start_token")
    if not isinstance(start_token, str):
        return None
    token_parts = start_token.split(":")
    if (
        len(token_parts) != 3
        or token_parts[0] != "posix"
        or not re.fullmatch(r"[0-9a-fA-F-]{8,128}", token_parts[1] or "")
        or not token_parts[2].isdigit()
    ):
        return None

    ownership_generation = str(ownership.get("worker_generation") or "")
    run_generation = str(run.get("worker_generation") or "")
    if not ownership_generation or not run_generation or ownership_generation != run_generation:
        return None

    attestation_json = ownership.get("identity_attestation")
    if ownership.get("ownership_state") == ProcessOwnershipState.EXTERNAL_PROCESS_GOVERNED.value:
        if not isinstance(attestation_json, str) or not attestation_json.strip():
            return None
        try:
            attestation = PosixProcessAttestation.model_validate_json(attestation_json)
        except Exception:
            return None
        if (
            attestation.verification_result != "VERIFIED"
            or attestation.worker_generation != ownership_generation
            or attestation.boot_id != token_parts[1]
            or attestation.root_start_ticks != int(token_parts[2])
            or attestation.session_id != session_id
            or attestation.process_group_id != group_id
        ):
            return None
    elif ownership.get("ownership_state") not in {
        ProcessOwnershipState.LAUNCH_UNCERTAIN.value,
        ProcessOwnershipState.RECOVERY_BLOCKED.value,
    }:
        return None

    return ProcessIdentity(
        pid=pid,
        process_group_id=group_id,
        start_token=start_token,
        session_id=session_id,
    )


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
            or self.reason_code == "EXECUTION_CANCELLED_BEFORE_PROCESS_CREATION"
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
                and (
                    process_confirmed
                    or reason_code in {
                        "EXECUTION_CANCELLED_BEFORE_DISPATCH",
                        "EXECUTION_CANCELLED_BEFORE_PROCESS_CREATION",
                    }
                    or execution_id is None
                )
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
            settlement = getattr(
                self._database,
                "settle_execution_after_confirmed_termination",
                None,
            )
            durable_terminal = True
            if callable(settlement):
                durable_terminal = bool(await asyncio.to_thread(
                    settlement,
                    execution_id,
                    organization_id,
                    terminal_state="CANCELLED",
                    reason_code="EXECUTION_CANCELLED_BEFORE_DISPATCH",
                    termination_status="PRE_DISPATCH",
                    worker_generation=after_revoke.get("worker_generation"),
                    actor="execution-cancellation-coordinator",
                ))
            return self._outcome(
                execution_id=execution_id,
                request_id=request_id,
                authority_revoked=True,
                process_status="NOT_FOUND",
                process_confirmed=False,
                durable_terminal=durable_terminal,
                task_stopped=task_stopped,
                reason_code="EXECUTION_CANCELLED_BEFORE_DISPATCH",
            )

        try:
            ownership = await asyncio.to_thread(
                self._database.get_process_ownership,
                execution_id,
                organization_id,
            )
        except (AttributeError, NotImplementedError):
            # Minimal fakes and legacy non-durable stores have no ownership
            # projection.  They retain the old supervisor-only test seam, but
            # the real database always exposes this method and therefore cannot
            # silently bypass durable identity reattachment.
            ownership = None
        except Exception as exc:
            ownership = None
            identity_error = type(exc).__name__
        else:
            identity_error = None

        durable_ownership_api = callable(getattr(self._database, "get_process_ownership", None))
        durable_identity = None
        if ownership is not None:
            durable_identity = await asyncio.to_thread(
                load_durable_process_identity,
                self._database,
                execution_id,
                organization_id,
            )

        settlement = getattr(
            self._database,
            "settle_execution_after_confirmed_termination",
            None,
        )
        ownership_state = str(ownership.get("ownership_state")) if ownership else None

        # A durable NO_EXTERNAL_PROCESS state is a positive no-process fact,
        # not permission to ask the supervisor to infer safety from a missing
        # PID mapping.  It is only safe to close an active run before process
        # creation, and only through the atomic DAL settlement.
        if (
            ownership_state == ProcessOwnershipState.NO_EXTERNAL_PROCESS.value
            and after_revoke
            and after_revoke.get("state") == "STARTING"
            and callable(settlement)
        ):
            durable_terminal = bool(await asyncio.to_thread(
                settlement,
                execution_id,
                organization_id,
                terminal_state="CANCELLED",
                reason_code="EXECUTION_CANCELLED_BEFORE_PROCESS_CREATION",
                termination_status="NO_EXTERNAL_PROCESS",
                worker_generation=ownership.get("worker_generation"),
                actor="execution-cancellation-coordinator",
            ))
            task_stopped = await self.stop_task(owning_task)
            return self._outcome(
                execution_id=execution_id,
                request_id=request_id,
                authority_revoked=True,
                process_status="NO_EXTERNAL_PROCESS" if durable_terminal else "FAILED",
                process_confirmed=False,
                durable_terminal=durable_terminal,
                task_stopped=task_stopped,
                reason_code=("EXECUTION_CANCELLED_BEFORE_PROCESS_CREATION" if durable_terminal else None),
                error_code=None if durable_terminal else "EXECUTION_NO_PROCESS_SETTLEMENT_FAILED",
            )

        # A live/uncertain durable ownership row without a valid persisted
        # identity is an escalation condition.  Never fall back to a raw PID or
        # to an in-memory mapping that has not been reconciled with the tenant
        # record after a restart.
        durable_identity_required = (
            durable_ownership_api
            and after_revoke
            and after_revoke.get("state") in {"STARTING", "RUNNING"}
        ) or ownership_state in {
            ProcessOwnershipState.EXTERNAL_PROCESS_GOVERNED.value,
            ProcessOwnershipState.LAUNCH_UNCERTAIN.value,
            ProcessOwnershipState.RECOVERY_BLOCKED.value,
        }
        if durable_identity_required and durable_identity is None:
            task_stopped = await self.stop_task(owning_task)
            return self._outcome(
                execution_id=execution_id,
                request_id=request_id,
                authority_revoked=True,
                process_status="IDENTITY_UNAVAILABLE",
                process_confirmed=False,
                durable_terminal=False,
                task_stopped=task_stopped,
                error_code=identity_error or "DURABLE_PROCESS_IDENTITY_UNAVAILABLE",
            )

        try:
            if durable_identity is not None:
                cancellation = await asyncio.to_thread(
                    self.supervisor.cancel_execution,
                    execution_id,
                    process_identity=durable_identity,
                )
            else:
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

        durable_settlement = False
        if process_confirmed and callable(settlement):
            if durable_identity is None:
                error_code = error_code or "DURABLE_PROCESS_IDENTITY_REQUIRED_FOR_SETTLEMENT"
            else:
                durable_settlement = bool(await asyncio.to_thread(
                    settlement,
                    execution_id,
                    organization_id,
                    terminal_state="CANCELLED",
                    reason_code="EXECUTION_CANCELLED",
                    termination_status=process_status,
                    process_id=durable_identity.pid,
                    process_group_id=str(durable_identity.process_group_id),
                    process_start_token=durable_identity.start_token,
                    session_id=durable_identity.session_id,
                    worker_generation=ownership.get("worker_generation") if ownership else None,
                    actor="execution-cancellation-coordinator",
                ))
                if not durable_settlement:
                    error_code = error_code or "CONFIRMED_TERMINATION_SETTLEMENT_FAILED"

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
        if callable(settlement):
            durable_terminal = durable_settlement
        else:
            durable_terminal = bool(final_run and final_run.get("state") in self._TERMINAL_RUN_STATES)
        return self._outcome(
            execution_id=execution_id,
            request_id=request_id,
            authority_revoked=True,
            process_status=process_status,
            process_confirmed=process_confirmed,
            durable_terminal=durable_terminal,
            task_stopped=task_stopped,
            reason_code=(
                final_run.get("reason_code")
                if final_run and final_run.get("reason_code")
                else ("EXECUTION_CANCELLED" if durable_settlement else None)
            ),
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


def _expected_terminal_dispatch(terminal_state: str) -> str:
    if terminal_state in {"SUCCEEDED", "PARTIAL_RESULTS_WITH_WARNING"}:
        return "COMPLETED"
    if terminal_state in {"CANCELLED", "EXECUTION_BLOCKED"}:
        return "BLOCKED"
    return "FAILED"


def _durable_execution_evidence(capability: Any) -> Optional[dict[str, Any]]:
    if not capability.execution_id:
        return None
    reader = getattr(capability.database, "get_execution_replay_evidence", None)
    if not callable(reader):
        return None
    evidence = reader(capability.execution_id, capability.decision.organization_id)
    if not isinstance(evidence, dict):
        return None
    run = evidence.get("run")
    if not isinstance(run, dict):
        return None
    if run.get("execution_id") != capability.execution_id or run.get("organization_id") != capability.decision.organization_id:
        return None
    if run.get("worker_identity") != capability.worker_identity or run.get("worker_generation") != capability.worker_generation:
        return None
    if run.get("approved_decision_id") != capability.decision.id:
        return None
    return evidence


def _claim_digests(capability: Any) -> tuple[str, str]:
    if not isinstance(capability.claim_token, str) or not isinstance(capability.dispatch_claim_token, str):
        raise ValueError("execution claims are incomplete")
    return (
        execution_claim_digest(capability.claim_token),
        execution_claim_digest(capability.dispatch_claim_token),
    )


def _parse_aware_timestamp(value: Any, field_name: str) -> datetime:
    """Parse a durable lifecycle timestamp without accepting local-time input."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} is missing")
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _proof_recovery_fields(evidence: dict[str, Any]) -> tuple[str, int, Optional[str]]:
    recovery = evidence.get("recovery")
    if not isinstance(recovery, dict) or recovery.get("status") not in {
        "REQUESTED", "CONFIRMED_TERMINATED",
    }:
        raise ValueError("execution recovery projection is not replayable")
    try:
        attempt_number = int(recovery.get("attempt_number") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("execution recovery attempt number is invalid") from exc
    if attempt_number < 0:
        raise ValueError("execution recovery attempt number is invalid")
    if (
        type(recovery.get("escalation_level")) is not int
        or recovery["escalation_level"] < 0
    ):
        raise ValueError("execution recovery escalation level is invalid")
    if recovery.get("last_error") is not None:
        raise ValueError("execution recovery projection retains an unresolved error")
    if any(
        recovery.get(field_name) is not None
        for field_name in ("owner", "lease_token", "lease_expires_at", "next_retry_at")
    ):
        raise ValueError("execution recovery projection retains an active lease")
    attempt = evidence.get("latest_confirmed_recovery")
    attempt_id = attempt.get("attempt_id") if isinstance(attempt, dict) else None
    if recovery.get("status") == "REQUESTED":
        if (
            attempt is not None
            or attempt_id is not None
            or attempt_number != 0
            or recovery.get("last_outcome") is not None
            or recovery.get("escalation_level") != 0
        ):
            raise ValueError("requested recovery projection has terminal evidence")
    else:
        if not isinstance(attempt, dict) or not isinstance(attempt_id, str) or not attempt_id.strip() or attempt_number < 1:
            raise ValueError("confirmed recovery projection has no attempt evidence")
        run = evidence.get("run")
        if not isinstance(run, dict) or not isinstance(recovery.get("last_outcome"), str) or not recovery["last_outcome"].strip():
            raise ValueError("confirmed recovery projection has no outcome evidence")
        required_text = (
            "attempt_id", "worker_identity", "reason_code", "correlation_id",
            "requested_at", "started_at", "completed_at", "health_reference",
        )
        if any(
            not isinstance(attempt.get(field_name), str) or not attempt[field_name].strip()
            for field_name in required_text
        ):
            raise ValueError("confirmed recovery attempt evidence is incomplete")
        try:
            recovery_timestamps = tuple(
                _parse_aware_timestamp(attempt[field_name], field_name)
                for field_name in ("requested_at", "started_at", "completed_at")
            )
        except ValueError:
            raise ValueError("confirmed recovery attempt timestamps are invalid") from None
        if not recovery_timestamps[0] <= recovery_timestamps[1] <= recovery_timestamps[2]:
            raise ValueError("confirmed recovery attempt timestamps are invalid")
        if (
            type(attempt.get("attempt_number")) is not int
            or type(attempt.get("escalation_level")) is not int
            or attempt.get("escalation_level") < 0
        ):
            raise ValueError("confirmed recovery attempt counters are invalid")
        if (
            attempt.get("execution_id") != run.get("execution_id")
            or attempt.get("organization_id") != run.get("organization_id")
            or attempt.get("worker_identity") != run.get("worker_identity")
            or attempt.get("worker_generation") != run.get("worker_generation")
            or attempt.get("attempt_number") != attempt_number
            or attempt.get("status") != "CONFIRMED_TERMINATED"
            or attempt.get("correlation_id") != run.get("correlation_id")
            or attempt.get("reason_code") != run.get("reason_code")
            or attempt.get("cancellation_status") not in {
                "CONFIRMED", "KILLED", "ALREADY_EXITED", "NO_EXTERNAL_PROCESS", "PRE_DISPATCH",
            }
            or attempt.get("error_code") is not None
            or attempt.get("next_retry_at") is not None
            or attempt.get("escalation_level") != recovery.get("escalation_level")
        ):
            raise ValueError("confirmed recovery attempt evidence is inconsistent")
    return str(recovery["status"]), attempt_number, attempt_id


def record_no_process(
    capability: Any,
    *,
    proof_code: str,
    reason_code: str,
    terminal_state: Optional[str] = None,
    dispatch_state: Optional[str] = None,
) -> bool:
    """Persist an exact, digest-bound no-process result before run settlement."""
    if (
        reason_code not in EXECUTION_REASON_CODES
        or proof_code != reason_code
        or not capability.execution_id
    ):
        return False
    terminal_state = terminal_state or (
        "CANCELLED"
        if reason_code.startswith("EXECUTION_CANCELLED")
        else "EXECUTION_BLOCKED"
    )
    expected_dispatch = _expected_terminal_dispatch(terminal_state)
    if dispatch_state is None:
        dispatch_state = expected_dispatch
    if terminal_state not in {"CANCELLED", "EXECUTION_BLOCKED", "FAILED", "TIMED_OUT"} or dispatch_state != expected_dispatch:
        return False
    try:
        evidence = _durable_execution_evidence(capability)
        if evidence is None:
            return False
        run = evidence["run"]
        dispatch = evidence.get("dispatch")
        if not isinstance(dispatch, dict) or dispatch.get("state") not in {"CLAIMED", "PENDING", "BLOCKED"}:
            return False
        decision_digest, dispatch_digest = _claim_digests(capability)
        recovery_status, recovery_attempt_number, recovery_attempt_id = _proof_recovery_fields(evidence)
        observed_at = utc_now()
        correlation_id = run.get("correlation_id")
        if not isinstance(correlation_id, str) or not correlation_id.strip():
            return False
        payload = {
            "schema_version": "execution-proof-v2",
            "proof_type": "NO_EXTERNAL_PROCESS",
            "execution_id": capability.execution_id,
            "organization_id": capability.decision.organization_id,
            "request_id": run["request_id"],
            "decision_id": capability.decision.id,
            "terminal_state": terminal_state,
            "dispatch_state": dispatch_state,
            "ownership_state": ProcessOwnershipState.NO_EXTERNAL_PROCESS.value,
            "container_type": ProcessContainerType.NONE.value,
            "launch_commit_state": LaunchCommitState.NOT_ATTEMPTED.value,
            "worker_identity": capability.worker_identity,
            "worker_generation": capability.worker_generation,
            "correlation_id": correlation_id,
            "claim_identity_digest": decision_digest,
            "dispatch_identity_digest": dispatch_digest,
            "proof_code": proof_code,
            "reason_code": reason_code,
            "observed_at": observed_at.isoformat(),
            "recovery_status": recovery_status,
            "recovery_attempt_number": recovery_attempt_number,
            "recovery_attempt_id": recovery_attempt_id,
        }
        proof = encode_execution_proof("NO_EXTERNAL_PROCESS", payload)
        record = ExecutionProcessOwnershipRecord(
            execution_id=capability.execution_id,
            organization_id=capability.decision.organization_id,
            ownership_state=ProcessOwnershipState.NO_EXTERNAL_PROCESS,
            container_type=ProcessContainerType.NONE,
            launch_commit_state=LaunchCommitState.NOT_ATTEMPTED,
            no_process_proof=proof,
            correlation_id=correlation_id,
            worker_generation=capability.worker_generation,
            last_verified_at=observed_at,
            updated_at=observed_at,
        )
        return capability.database.transition_process_ownership(
            record,
            ProcessOwnershipState.UNKNOWN,
            reason_code=reason_code,
            worker_identity=capability.worker_identity,
        )
    except (KeyError, TypeError, ValueError):
        return False


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
    evidence = _durable_execution_evidence(capability)
    if evidence is None or not isinstance(evidence["run"].get("correlation_id"), str):
        raise RuntimeError("durable execution correlation is unavailable")
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
        correlation_id=evidence["run"]["correlation_id"],
        launched_at=captured,
        last_verified_at=captured,
    )
    if not capability.database.transition_process_ownership(
        record,
        ProcessOwnershipState.UNKNOWN,
        reason_code="PROCESS_LAUNCH_COMMITTED",
        worker_identity=capability.worker_identity,
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
    evidence = _durable_execution_evidence(capability)
    if evidence is None or not isinstance(evidence["run"].get("correlation_id"), str):
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
        correlation_id=evidence["run"]["correlation_id"],
        last_verified_at=utc_now(),
    )
    return capability.database.transition_process_ownership(
        record,
        ProcessOwnershipState.UNKNOWN,
        reason_code="PROCESS_LAUNCH_UNCERTAIN",
        worker_identity=capability.worker_identity,
    )


def record_terminal(
    capability: Any,
    *,
    terminal_state: str,
    reason_code: str,
    process_id: Optional[int] = None,
    process_group_id: Optional[str] = None,
    process_start_token: Optional[str] = None,
    session_id: Optional[int] = None,
    termination_status: Optional[str] = None,
) -> bool:
    """Transition governed process ownership with a complete terminal proof."""
    if not capability.execution_id:
        return False
    existing = capability.database.get_process_ownership(
        capability.execution_id, capability.decision.organization_id,
    )
    if not existing:
        return False
    current = ProcessOwnershipState(existing["ownership_state"])
    if current == ProcessOwnershipState.TERMINAL:
        if (
            terminal_state not in {"FAILED", "TIMED_OUT", "CANCELLED"}
            or not is_valid_execution_terminal_outcome(terminal_state, reason_code)
        ):
            return False
        # A terminal replay is idempotent only when the caller presents the
        # complete persisted process proof.  Do not allow a caller to omit an
        # identity field and have the replay validator silently substitute the
        # durable value from the database.
        if (
            type(process_id) is not int
            or process_id <= 1
            or not isinstance(process_group_id, str)
            or not process_group_id.isdigit()
            or int(process_group_id) <= 1
            or not isinstance(process_start_token, str)
            or not process_start_token.strip()
            or type(session_id) is not int
            or session_id < 0
            or termination_status not in {"KILLED", "ALREADY_EXITED"}
        ):
            return False
        proof = existing.get("no_process_proof")
        if not isinstance(proof, str) or not proof.strip():
            return False
        try:
            payload = decode_execution_proof(
                proof,
                expected_proof_type="TERMINATION_CONFIRMED",
            )
        except (TypeError, ValueError):
            return False
        if set(payload) != set(EXECUTION_PROOF_TERMINATION_KEYS):
            return False
        if payload.get("terminal_state") != terminal_state or payload.get("reason_code") != reason_code:
            return False
        if payload.get("termination_status") != termination_status:
            return False
        if payload.get("termination_status") not in {"KILLED", "ALREADY_EXITED"}:
            return False
        for supplied, stored, field_name in (
            (process_id, payload.get("process_id"), "process_id"),
            (process_group_id, payload.get("process_group_id"), "process_group_id"),
            (process_start_token, payload.get("process_start_token"), "process_start_token"),
            (session_id, payload.get("session_id"), "session_id"),
        ):
            if field_name in {"process_group_id", "process_start_token"}:
                if str(supplied) != str(stored):
                    return False
            elif supplied != stored:
                return False
        for field_name, stored_field in (
            ("process_id", "root_process_id"),
            ("process_group_id", "process_group_id"),
            ("process_start_token", "root_process_start_token"),
            ("session_id", "session_id"),
            ("identity_attestation", "identity_attestation"),
        ):
            payload_value = payload.get(field_name)
            stored_value = existing.get(stored_field)
            if field_name in {"process_group_id", "session_id"}:
                matches = str(payload_value) == str(stored_value)
            else:
                matches = payload_value == stored_value
            if not matches:
                return False
        evidence = _durable_execution_evidence(capability)
        if evidence is None:
            return False
        run = evidence["run"]
        if (
            not isinstance(existing.get("correlation_id"), str)
            or not existing["correlation_id"].strip()
            or existing["correlation_id"] != run.get("correlation_id")
        ):
            return False
        try:
            decision_digest, dispatch_digest = _claim_digests(capability)
            recovery_status, recovery_attempt_number, recovery_attempt_id = _proof_recovery_fields(evidence)
        except (KeyError, TypeError, ValueError):
            return False
        for field_name, expected in (
            ("execution_id", capability.execution_id),
            ("organization_id", capability.decision.organization_id),
            ("request_id", run.get("request_id")),
            ("decision_id", capability.decision.id),
            ("dispatch_state", _expected_terminal_dispatch(terminal_state)),
            ("ownership_state", ProcessOwnershipState.TERMINAL.value),
            ("container_type", existing.get("container_type")),
            ("launch_commit_state", existing.get("launch_commit_state")),
            ("worker_identity", capability.worker_identity),
            ("worker_generation", capability.worker_generation),
            ("correlation_id", run.get("correlation_id")),
            ("claim_identity_digest", decision_digest),
            ("dispatch_identity_digest", dispatch_digest),
            ("recovery_status", recovery_status),
            ("recovery_attempt_number", recovery_attempt_number),
            ("recovery_attempt_id", recovery_attempt_id),
            ("identity_attestation_digest", canonical_binding_digest(existing["identity_attestation"])),
        ):
            if payload.get(field_name) != expected:
                return False
        try:
            attestation = PosixProcessAttestation.model_validate_json(existing["identity_attestation"])
            expected_pid = int(str(existing.get("root_process_id")))
            expected_group = int(str(existing.get("process_group_id")))
            expected_session = int(str(existing.get("session_id")))
        except Exception:
            return False
        token_parts = str(existing.get("root_process_start_token") or "").split(":", 2)
        if (
            expected_pid <= 1
            or expected_group <= 1
            or expected_session < 0
            or attestation.verification_result != "VERIFIED"
            or attestation.worker_generation != str(existing.get("worker_generation") or "")
            or len(token_parts) != 3
            or token_parts[0] != "posix"
            or not re.fullmatch(r"[0-9a-fA-F-]{8,128}", token_parts[1] or "")
            or not token_parts[2].isdigit()
            or int(token_parts[2]) <= 0
            or attestation.boot_id != token_parts[1]
            or attestation.root_start_ticks != int(token_parts[2])
            or attestation.root_start_ticks <= 0
            or attestation.session_id != expected_session
            or attestation.process_group_id != expected_group
            or attestation.process_group_id <= 1
            or existing.get("container_identity")
            != f"posix-session:{expected_session}:group:{expected_group}"
        ):
            return False
        try:
            observed_at = datetime.fromisoformat(str(payload.get("observed_at")))
            terminalized_at = datetime.fromisoformat(str(existing.get("terminalized_at")))
        except (TypeError, ValueError):
            return False
        if (
            observed_at.tzinfo is None
            or observed_at.utcoffset() is None
            or terminalized_at.tzinfo is None
            or terminalized_at.utcoffset() is None
            or payload.get("observed_at") != existing.get("terminalized_at")
        ):
            return False
        recovery = evidence.get("recovery")
        latest_recovery = evidence.get("latest_confirmed_recovery")
        if recovery_status == "CONFIRMED_TERMINATED" and (
            not isinstance(recovery, dict)
            or not isinstance(latest_recovery, dict)
            or recovery.get("last_outcome") != proof
            or latest_recovery.get("cancellation_status") != payload.get("termination_status")
        ):
            return False
        return True
    if current != ProcessOwnershipState.EXTERNAL_PROCESS_GOVERNED:
        return False
    if (
        terminal_state not in {"SUCCEEDED", "PARTIAL_RESULTS_WITH_WARNING", "FAILED", "TIMED_OUT", "CANCELLED"}
        or not is_valid_execution_terminal_outcome(terminal_state, reason_code)
    ):
        return False
    if termination_status is None:
        termination_status = "ALREADY_EXITED"
    if termination_status not in {"KILLED", "ALREADY_EXITED"}:
        return False
    try:
        expected_pid = int(existing["root_process_id"])
        expected_group = str(existing["process_group_id"])
        expected_session = int(str(existing["session_id"]))
    except (TypeError, ValueError):
        return False
    if (
        expected_pid <= 1
        or not expected_group.isdigit()
        or int(expected_group) <= 1
        or expected_session < 0
    ):
        return False
    if (
        type(process_id) is not int
        or process_id <= 1
        or not isinstance(process_group_id, str)
        or not process_group_id.isdigit()
        or int(process_group_id) <= 1
        or not isinstance(process_start_token, str)
        or not process_start_token.strip()
        or type(session_id) is not int
        or session_id < 0
        or termination_status not in {"KILLED", "ALREADY_EXITED"}
    ):
        return False
    if process_id != expected_pid:
        return False
    if str(process_group_id) != expected_group:
        return False
    if session_id != expected_session:
        return False
    if process_start_token != existing.get("root_process_start_token"):
        return False
    attestation_json = existing.get("identity_attestation")
    if not isinstance(attestation_json, str) or not attestation_json.strip():
        return False
    try:
        attestation = PosixProcessAttestation.model_validate_json(attestation_json)
    except Exception:
        return False
    start_parts = str(existing.get("root_process_start_token") or "").split(":", 2)
    if (
        attestation.verification_result != "VERIFIED"
        or attestation.worker_generation != str(existing.get("worker_generation") or "")
        or len(start_parts) != 3
        or start_parts[0] != "posix"
        or not re.fullmatch(r"[0-9a-fA-F-]{8,128}", start_parts[1] or "")
        or not start_parts[2].isdigit()
        or int(start_parts[2]) <= 0
        or int(expected_group) <= 1
        or attestation.boot_id != start_parts[1]
        or attestation.root_start_ticks != int(start_parts[2])
        or attestation.root_start_ticks <= 0
        or attestation.session_id != int(str(existing.get("session_id")))
        or attestation.process_group_id != int(str(existing.get("process_group_id")))
        or attestation.process_group_id <= 1
        or existing.get("container_identity")
        != f"posix-session:{existing.get('session_id')}:group:{existing.get('process_group_id')}"
    ):
        return False
    evidence = _durable_execution_evidence(capability)
    if evidence is None:
        return False
    run = evidence["run"]
    correlation_id = run.get("correlation_id")
    if not isinstance(correlation_id, str) or not correlation_id.strip():
        return False
    try:
        decision_digest, dispatch_digest = _claim_digests(capability)
        recovery_status, recovery_attempt_number, recovery_attempt_id = _proof_recovery_fields(evidence)
        observed_at = utc_now()
        payload = {
            "schema_version": "execution-proof-v2",
            "proof_type": "TERMINATION_CONFIRMED",
            "execution_id": capability.execution_id,
            "organization_id": capability.decision.organization_id,
            "request_id": run["request_id"],
            "decision_id": capability.decision.id,
            "terminal_state": terminal_state,
            "dispatch_state": _expected_terminal_dispatch(terminal_state),
            "ownership_state": ProcessOwnershipState.TERMINAL.value,
            "container_type": existing["container_type"],
            "launch_commit_state": existing["launch_commit_state"],
            "worker_identity": capability.worker_identity,
            "worker_generation": capability.worker_generation,
            "correlation_id": correlation_id,
            "claim_identity_digest": decision_digest,
            "dispatch_identity_digest": dispatch_digest,
            "reason_code": reason_code,
            "observed_at": observed_at.isoformat(),
            "recovery_status": recovery_status,
            "recovery_attempt_number": recovery_attempt_number,
            "recovery_attempt_id": recovery_attempt_id,
            "termination_status": termination_status,
            "process_id": expected_pid,
            "process_group_id": expected_group,
            "process_start_token": existing["root_process_start_token"],
            "session_id": expected_session,
            "identity_attestation": attestation_json,
            "identity_attestation_digest": canonical_binding_digest(attestation_json),
        }
        proof = encode_execution_proof("TERMINATION_CONFIRMED", payload)
    except (KeyError, TypeError, ValueError):
        return False
    record = ExecutionProcessOwnershipRecord(**{
        **existing,
        "ownership_state": ProcessOwnershipState.TERMINAL,
        "container_type": ProcessContainerType(existing["container_type"]),
        "launch_commit_state": LaunchCommitState(existing["launch_commit_state"]),
        "no_process_proof": proof,
        "correlation_id": correlation_id,
        "updated_at": observed_at,
        "terminalized_at": observed_at,
    })
    return capability.database.transition_process_ownership(
        record,
        current,
        reason_code=reason_code,
        worker_identity=capability.worker_identity,
    )


def settle_execution(
    capability: Any,
    *,
    terminal_state: str,
    reason_code: str,
    process_id: Optional[int] = None,
    process_group_id: Optional[str] = None,
    process_start_token: Optional[str] = None,
    session_id: Optional[int] = None,
    termination_status: Optional[str] = None,
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
                    if not record_no_process(
                        capability,
                        proof_code=reason_code,
                        reason_code=reason_code,
                        terminal_state=terminal_state,
                        dispatch_state=_expected_terminal_dispatch(terminal_state),
                    ):
                        raise _SettlementRejected
                    settled = capability.database.abort_execution_start(
                        capability.decision.id, capability.decision.organization_id,
                        capability.worker_identity, capability.claim_token,
                        capability.dispatch_claim_token, terminal_state=terminal_state,
                        reason_code=reason_code,
                    )
                else:
                    if termination_status is None:
                        # Ordinary process completion has an explicit
                        # persisted outcome even though no kill was needed.
                        termination_status = "ALREADY_EXITED"
                    if not record_terminal(
                        capability,
                        terminal_state=terminal_state,
                        reason_code=reason_code,
                        process_id=process_id,
                        process_group_id=process_group_id,
                        process_start_token=process_start_token,
                        session_id=session_id,
                        termination_status=termination_status,
                    ):
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
        # A cancellation coordinator revokes authority before it asks the
        # supervisor to terminate the process.  The normal authority-held
        # transition above must reject that stale capability; the exact
        # persisted identity then uses the dedicated post-revocation DAL
        # settlement instead.  This fallback is deliberately restricted to
        # cancellation outcomes and complete identity/no-process evidence.
        fallback = getattr(
            capability.database,
            "settle_execution_after_confirmed_termination",
            None,
        )
        if not callable(fallback):
            return False
        if reason_code == "EXECUTION_CANCELLED" and process_id is not None:
            if termination_status not in {"KILLED", "ALREADY_EXITED"}:
                return False
            existing = capability.database.get_process_ownership(
                capability.execution_id, capability.decision.organization_id,
            )
            if not isinstance(existing, dict):
                return False
            return bool(fallback(
                capability.execution_id,
                capability.decision.organization_id,
                terminal_state=terminal_state,
                reason_code=reason_code,
                termination_status=termination_status,
                process_id=process_id,
                process_group_id=process_group_id,
                process_start_token=process_start_token,
                session_id=session_id,
                identity_attestation=existing.get("identity_attestation"),
                worker_generation=capability.worker_generation,
                worker_identity=capability.worker_identity,
                actor="process-supervisor",
            ))
        if reason_code == "EXECUTION_CANCELLED_BEFORE_PROCESS_CREATION" and process_id is None:
            return bool(fallback(
                capability.execution_id,
                capability.decision.organization_id,
                terminal_state=terminal_state,
                reason_code=reason_code,
                termination_status="NO_EXTERNAL_PROCESS",
                worker_generation=capability.worker_generation,
                worker_identity=capability.worker_identity,
                actor="process-supervisor",
            ))
        return False
    return True


__all__ = [
    "ExecutionCancellationCoordinator",
    "ExecutionCancellationOutcome",
    "load_durable_process_identity",
    "record_no_process",
    "record_posix_launch",
    "record_launch_uncertain",
    "record_terminal",
    "settle_execution",
]
