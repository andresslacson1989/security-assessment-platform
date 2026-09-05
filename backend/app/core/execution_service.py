"""Single execution-service boundary for durable launch and terminal settlement."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.core.execution_context import PosixProcessAttestation, canonical_binding_digest
from app.core.models import (
    ExecutionProcessOwnershipRecord,
    EXECUTION_REASON_CODES,
    ProcessContainerType,
    ProcessOwnershipState,
    LaunchCommitState,
    utc_now,
)


def record_no_process(capability: Any, *, proof_code: str, reason_code: str) -> bool:
    """Persist an explicit no-process result before terminal settlement."""
    if reason_code not in EXECUTION_REASON_CODES or not capability.execution_id:
        return False
    record = ExecutionProcessOwnershipRecord(
        execution_id=capability.execution_id,
        organization_id=capability.decision.organization_id,
        ownership_state=ProcessOwnershipState.NO_EXTERNAL_PROCESS,
        container_type=ProcessContainerType.NONE,
        launch_commit_state=LaunchCommitState.NOT_ATTEMPTED,
        no_process_proof=f"NO_EXTERNAL_PROCESS:{proof_code}",
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
    if process_id is None:
        if not record_no_process(capability, proof_code=reason_code, reason_code=reason_code):
            return False
        return bool(capability.database.abort_execution_start(
            capability.decision.id, capability.decision.organization_id,
            capability.worker_identity, capability.claim_token,
            capability.dispatch_claim_token, terminal_state=terminal_state,
            reason_code=reason_code,
        ))
    if not record_terminal(capability, reason_code=reason_code):
        return False
    return bool(capability.database.finish_execution(
        capability.execution_id, capability.decision.organization_id,
        capability.worker_identity, capability.dispatch_claim_token,
        terminal_state=terminal_state, reason_code=reason_code,
        process_id=process_id, process_group_id=process_group_id,
    ))


__all__ = ["record_no_process", "record_posix_launch", "record_terminal", "settle_execution"]
