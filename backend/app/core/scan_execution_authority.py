"""Explicit authority provider for approved scan-manifest operations.

The provider is intentionally a resolver, not a capability cache. A caller
must supply the server-generated operation identity for every external launch;
the provider then reloads the complete parent/operation/child tuple from the
authoritative database and asks the existing decision verifier to issue one
opaque launch capability. No ambient or task-local authority is used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from types import MappingProxyType
from typing import Any, Mapping, Optional

from app.core.db import db_manager
from app.core.execution_decision import (
    ExecutionDecisionCapability,
    ExecutionDecisionError,
    issue_execution_capability,
)
from app.core.execution_context import (
    EXECUTION_PROOF_NO_PROCESS_KEYS,
    EXECUTION_PROOF_TERMINATION_KEYS,
    PosixProcessAttestation,
    canonical_binding_digest,
    decode_execution_proof,
)
from app.core.models import (
    EXECUTION_REASON_CODES,
    EXECUTION_RUN_TERMINAL_STATES,
    LaunchCommitState,
    ProcessContainerType,
    ProcessOwnershipState,
    ValidatedTarget,
    is_valid_execution_terminal_outcome,
)
from app.core.ssrf_protector import validate_validated_target
from app.core.tool_operation_policy import (
    OPERATION_POLICY_REVISION,
    get_operation_policy,
    is_canonical_operation_policy_revision,
)


class ScanExecutionAuthorityError(ExecutionDecisionError):
    """Raised when an approved scan child operation cannot be resolved."""


@dataclass(frozen=True)
class ScanExecutionLaunchBinding:
    """Typed snapshot of one complete, tenant-bound launch relation."""

    scan_request_id: str
    scan_id: str
    organization_id: str
    parent_state: str
    parent_manifest_hash: str
    parent_project_id: Optional[str]
    parent_asset_id: Optional[str]
    parent_target_id: str
    parent_target_integrity_seal: str
    parent_target_policy_version: str

    operation_id: str
    operation_tool_id: str
    operation_engine_id: str
    operation_family: str
    operation_options: Mapping[str, Any] = field(default_factory=dict)
    operation_policy_revision: str = ""
    operation_target_id: str = ""
    operation_authorization_decision_id: str = ""
    operation_resource_budget: Mapping[str, Any] = field(default_factory=dict)
    operation_account_impact_budget: Mapping[str, Any] = field(default_factory=dict)
    operation_credential_scope: Mapping[str, Any] = field(default_factory=dict)
    operation_capability_state: str = ""
    operation_selection_state: str = ""

    child_request_id: str = ""
    child_request_organization_id: str = ""
    child_request_state: str = ""
    child_request_project_id: Optional[str] = None
    child_request_asset_id: Optional[str] = None
    child_request_target_id: str = ""
    child_request_authorization_decision_id: str = ""
    child_request_target_policy_version: str = ""
    child_request_tool_id: str = ""
    child_request_operation_family: str = ""
    child_request_operation_options: Mapping[str, Any] = field(default_factory=dict)
    child_request_operation_policy_revision: str = ""
    child_request_resource_budget: Mapping[str, Any] = field(default_factory=dict)
    child_request_account_impact_budget: Mapping[str, Any] = field(default_factory=dict)
    child_request_credential_scope: Mapping[str, Any] = field(default_factory=dict)
    child_request_fingerprint: str = ""
    child_request_expires_at: str = ""

    child_decision_id: str = ""
    child_decision_organization_id: str = ""
    child_decision_project_id: Optional[str] = None
    child_decision_asset_id: Optional[str] = None
    child_decision_target_id: str = ""
    child_decision_authorization_decision_id: str = ""
    child_decision_target_policy_version: str = ""
    child_decision_tool_id: str = ""
    child_decision_operation_family: str = ""
    child_decision_operation_options: Mapping[str, Any] = field(default_factory=dict)
    child_decision_operation_policy_revision: str = ""
    child_decision_approval_state: str = ""
    child_decision_session_jti: str = ""
    child_decision_worker_identity: str = ""
    child_decision_resource_budget: Mapping[str, Any] = field(default_factory=dict)
    child_decision_account_impact_budget: Mapping[str, Any] = field(default_factory=dict)
    child_decision_credential_scope: Mapping[str, Any] = field(default_factory=dict)
    child_decision_expires_at: str = ""
    child_decision_revoked_at: Optional[str] = None
    child_decision_consumed_at: Optional[str] = None

    child_execution_id: str = ""
    child_run_request_id: str = ""
    child_run_organization_id: str = ""
    child_run_approved_decision_id: str = ""
    child_run_target_policy_version: str = ""
    child_run_operation_policy_revision: str = ""
    child_run_request_fingerprint: str = ""
    child_run_operation_options: Mapping[str, Any] = field(default_factory=dict)
    child_run_resource_budget: Mapping[str, Any] = field(default_factory=dict)
    child_run_account_impact_budget: Mapping[str, Any] = field(default_factory=dict)
    child_run_credential_scope: Mapping[str, Any] = field(default_factory=dict)
    child_run_snapshot_completeness: str = ""
    child_run_state: str = ""
    child_run_worker_identity: str = ""
    child_run_worker_generation: str = ""
    child_run_correlation_id: Optional[str] = None
    dispatch_state: str = ""
    dispatch_attempt_count: int = 0

    def __post_init__(self) -> None:
        for field_name in (
            "operation_options",
            "operation_resource_budget",
            "operation_account_impact_budget",
            "operation_credential_scope",
            "child_request_operation_options",
            "child_request_resource_budget",
            "child_request_account_impact_budget",
            "child_request_credential_scope",
            "child_decision_operation_options",
            "child_decision_resource_budget",
            "child_decision_account_impact_budget",
            "child_decision_credential_scope",
            "child_run_operation_options",
            "child_run_resource_budget",
            "child_run_account_impact_budget",
            "child_run_credential_scope",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, Mapping):
                raise ScanExecutionAuthorityError(f"launch binding field {field_name} is not an object")
            object.__setattr__(self, field_name, MappingProxyType(dict(value)))


def _parse_timestamp(value: str, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ScanExecutionAuthorityError(f"launch binding timestamp {field_name} is missing")
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ScanExecutionAuthorityError(f"launch binding timestamp {field_name} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ScanExecutionAuthorityError(f"launch binding timestamp {field_name} is timezone-naive")
    return parsed.astimezone(timezone.utc)


def _same_mapping(*values: Mapping[str, Any]) -> bool:
    first = dict(values[0])
    return all(dict(value) == first for value in values[1:])


TERMINAL_REPLAY_PARENT_STATES = frozenset({
    "DISPATCHABLE", "CONSUMED", "EXPIRED", "REVOKED",
})
_TERMINAL_REPLAY_REQUEST_STATES = frozenset({"AUTHORIZED", "REVOKED"})
_CLAIM_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _binding_value(binding: Any, field_name: str) -> Any:
    if isinstance(binding, Mapping):
        return binding.get(field_name)
    return getattr(binding, field_name, None)


def _nonblank(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _expected_terminal_dispatch(run_state: str) -> str:
    if run_state in {"SUCCEEDED", "PARTIAL_RESULTS_WITH_WARNING"}:
        return "COMPLETED"
    if run_state in {"CANCELLED", "EXECUTION_BLOCKED"}:
        return "BLOCKED"
    if run_state in {"FAILED", "TIMED_OUT"}:
        return "FAILED"
    raise ScanExecutionAuthorityError("terminal replay run outcome is not supported")


def _require_proof_fields(payload: Mapping[str, Any], expected: frozenset[str]) -> None:
    if set(payload) != set(expected):
        raise ScanExecutionAuthorityError("terminal replay proof payload fields are not exact")


def _require_proof_timestamp(value: Any, expected: Any, field_name: str) -> None:
    if not _nonblank(value) or not _nonblank(expected) or value != expected:
        raise ScanExecutionAuthorityError(
            f"terminal replay proof {field_name} is not bound to durable evidence"
        )
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ScanExecutionAuthorityError(
            f"terminal replay proof {field_name} is invalid"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ScanExecutionAuthorityError(
            f"terminal replay proof {field_name} must be timezone-aware"
        )


def _require_recovery_timestamp(value: Any, field_name: str) -> datetime:
    """Require one durable recovery timestamp with an explicit timezone."""
    if not _nonblank(value):
        raise ScanExecutionAuthorityError(
            f"terminal replay recovery timestamp {field_name} is missing"
        )
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ScanExecutionAuthorityError(
            f"terminal replay recovery timestamp {field_name} is invalid"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ScanExecutionAuthorityError(
            f"terminal replay recovery timestamp {field_name} must be timezone-aware"
        )
    return parsed.astimezone(timezone.utc)


def _require_digest(value: Any, field_name: str) -> None:
    if value is not None and (
        not isinstance(value, str) or _CLAIM_DIGEST_RE.fullmatch(value) is None
    ):
        raise ScanExecutionAuthorityError(
            f"terminal replay proof {field_name} is malformed"
        )


def validate_terminal_replay_proof(binding: Any, *, database: Any) -> None:
    """Validate an exact terminal replay without mutating durable state.

    This is deliberately a read-only fence.  It loads one tenant-scoped
    evidence snapshot, validates the versioned proof envelope and then binds
    every proof field to the live run, dispatch, ownership, recovery, and
    worker-handoff identities.  A terminal state alone is never sufficient.
    """
    execution_id = _binding_value(binding, "child_execution_id")
    organization_id = _binding_value(binding, "organization_id")
    run_state = _binding_value(binding, "child_run_state")
    dispatch_state = _binding_value(binding, "dispatch_state")
    if not _nonblank(execution_id) or not _nonblank(organization_id):
        raise ScanExecutionAuthorityError("terminal replay proof identity is incomplete")
    if _binding_value(binding, "parent_state") not in TERMINAL_REPLAY_PARENT_STATES:
        raise ScanExecutionAuthorityError("terminal replay parent state is not eligible")
    if run_state not in EXECUTION_RUN_TERMINAL_STATES:
        raise ScanExecutionAuthorityError("terminal replay proof run is not terminal")
    expected_dispatch = _expected_terminal_dispatch(run_state)
    if dispatch_state != expected_dispatch:
        raise ScanExecutionAuthorityError("terminal replay proof dispatch mapping is invalid")
    if _binding_value(binding, "child_run_snapshot_completeness") != "COMPLETE":
        raise ScanExecutionAuthorityError("terminal replay proof run snapshot is incomplete")
    if _binding_value(binding, "child_request_state") not in _TERMINAL_REPLAY_REQUEST_STATES:
        raise ScanExecutionAuthorityError("terminal replay proof request state is invalid")
    if _binding_value(binding, "child_decision_approval_state") != "APPROVED":
        raise ScanExecutionAuthorityError("terminal replay proof decision is not approved")

    required_binding_fields = (
        "scan_request_id", "scan_id", "parent_manifest_hash", "parent_target_id",
        "parent_target_integrity_seal", "parent_target_policy_version",
        "operation_id", "operation_tool_id", "operation_engine_id",
        "operation_family", "child_request_id", "child_decision_id",
        "child_request_fingerprint", "child_decision_session_jti",
        "child_decision_worker_identity", "child_run_request_id",
        "child_run_organization_id", "child_run_approved_decision_id",
        "child_run_target_policy_version", "child_run_operation_policy_revision",
        "child_run_request_fingerprint", "child_run_worker_identity",
        "child_run_worker_generation", "child_run_correlation_id",
        "child_request_expires_at", "child_decision_expires_at",
    )
    for field_name in required_binding_fields:
        if not _nonblank(_binding_value(binding, field_name)):
            raise ScanExecutionAuthorityError(
                f"terminal replay proof binding field {field_name} is incomplete"
            )
    if _binding_value(binding, "child_request_state") == "REVOKED" and not (
        _binding_value(binding, "child_decision_revoked_at")
        or _binding_value(binding, "child_decision_consumed_at")
    ):
        raise ScanExecutionAuthorityError(
            "terminal replay proof revoked request lacks durable terminal history"
        )

    binding_pairs = (
        ("child_run_request_id", _binding_value(binding, "child_request_id")),
        ("child_run_organization_id", organization_id),
        ("child_run_approved_decision_id", _binding_value(binding, "child_decision_id")),
        ("child_run_worker_identity", _binding_value(binding, "child_decision_worker_identity")),
    )
    for field_name, expected in binding_pairs:
        if _binding_value(binding, field_name) != expected:
            raise ScanExecutionAuthorityError(
                f"terminal replay binding {field_name} is inconsistent"
            )

    # The terminal replay path does not reconstruct a ValidatedTarget, so it
    # must perform the same identity-chain comparison directly on the loaded
    # authority snapshot.  A terminal row with a changed parent target,
    # operation target, or child decision is not an observation of the same
    # execution and must not be accepted as one.
    binding_consistency_groups = (
        (
            "parent_project_id", "child_request_project_id", "child_decision_project_id",
            "project binding",
        ),
        (
            "parent_asset_id", "child_request_asset_id", "child_decision_asset_id",
            "asset binding",
        ),
        (
            "parent_target_id", "operation_target_id", "child_request_target_id",
            "child_decision_target_id", "target binding",
        ),
        (
            "parent_target_policy_version", "child_request_target_policy_version",
            "child_decision_target_policy_version", "child_run_target_policy_version",
            "target-policy binding",
        ),
        (
            "operation_authorization_decision_id", "child_request_authorization_decision_id",
            "child_decision_authorization_decision_id", "authorization-decision binding",
        ),
        (
            "operation_tool_id", "child_request_tool_id", "child_decision_tool_id",
            "tool binding",
        ),
        (
            "operation_family", "child_request_operation_family", "child_decision_operation_family",
            "operation-family binding",
        ),
        (
            "operation_policy_revision", "child_request_operation_policy_revision",
            "child_decision_operation_policy_revision", "child_run_operation_policy_revision",
            "operation-policy binding",
        ),
    )
    for *field_names, label in binding_consistency_groups:
        values = [_binding_value(binding, field_name) for field_name in field_names]
        if any(value != values[0] for value in values[1:]):
            raise ScanExecutionAuthorityError(f"terminal replay {label} is inconsistent")
    for field_names, label in (
        (
            (
                "operation_options", "child_request_operation_options",
                "child_decision_operation_options", "child_run_operation_options",
            ),
            "operation-options binding",
        ),
        (
            (
                "operation_resource_budget", "child_request_resource_budget",
                "child_decision_resource_budget", "child_run_resource_budget",
            ),
            "resource-budget binding",
        ),
        (
            (
                "operation_account_impact_budget", "child_request_account_impact_budget",
                "child_decision_account_impact_budget", "child_run_account_impact_budget",
            ),
            "account-budget binding",
        ),
        (
            (
                "operation_credential_scope", "child_request_credential_scope",
                "child_decision_credential_scope", "child_run_credential_scope",
            ),
            "credential-scope binding",
        ),
    ):
        values = [_binding_value(binding, field_name) or {} for field_name in field_names]
        if any(not isinstance(value, Mapping) for value in values) or not _same_mapping(*values):
            raise ScanExecutionAuthorityError(f"terminal replay {label} is inconsistent")

    reader = getattr(database, "get_execution_replay_evidence", None)
    if not callable(reader):
        raise ScanExecutionAuthorityError("terminal replay evidence reader is unavailable")
    try:
        evidence = reader(execution_id, organization_id)
    except Exception as exc:
        raise ScanExecutionAuthorityError("terminal replay evidence could not be read") from exc
    if not isinstance(evidence, Mapping):
        raise ScanExecutionAuthorityError("terminal replay evidence is missing")
    run = evidence.get("run")
    ownership = evidence.get("ownership")
    dispatch = evidence.get("dispatch")
    recovery = evidence.get("recovery")
    latest_attempt = evidence.get("latest_confirmed_recovery")
    claim_digests = evidence.get("claim_digests")
    if not all(isinstance(value, Mapping) for value in (run, ownership, dispatch, recovery)):
        raise ScanExecutionAuthorityError("terminal replay evidence is incomplete")
    if not isinstance(claim_digests, Mapping):
        raise ScanExecutionAuthorityError("terminal replay claim evidence is missing")

    run_pairs = (
        ("execution_id", execution_id),
        ("request_id", _binding_value(binding, "child_request_id")),
        ("organization_id", organization_id),
        ("state", run_state),
        ("worker_identity", _binding_value(binding, "child_run_worker_identity")),
        ("approved_decision_id", _binding_value(binding, "child_decision_id")),
        ("target_policy_version", _binding_value(binding, "child_run_target_policy_version")),
        ("operation_policy_revision", _binding_value(binding, "child_run_operation_policy_revision")),
        ("request_fingerprint", _binding_value(binding, "child_run_request_fingerprint")),
        ("worker_generation", _binding_value(binding, "child_run_worker_generation")),
        ("correlation_id", _binding_value(binding, "child_run_correlation_id")),
        ("snapshot_completeness", "COMPLETE"),
    )
    for field_name, expected in run_pairs:
        if run.get(field_name) != expected:
            raise ScanExecutionAuthorityError(
                f"terminal replay run field {field_name} is inconsistent"
            )
    if not is_valid_execution_terminal_outcome(run_state, run.get("reason_code")):
        raise ScanExecutionAuthorityError(
            "terminal replay run outcome and reason are not a canonical pair"
        )
    for field_name in (
        "operation_options", "resource_budget", "account_impact_budget", "credential_scope",
    ):
        if not _same_mapping(
            run.get(field_name) or {},
            _binding_value(binding, f"child_run_{field_name}") or {},
        ):
            raise ScanExecutionAuthorityError(
                f"terminal replay run snapshot {field_name} is inconsistent"
            )

    dispatch_pairs = (
        ("execution_id", execution_id),
        ("organization_id", organization_id),
        ("state", expected_dispatch),
        ("correlation_id", _binding_value(binding, "child_run_correlation_id")),
    )
    for field_name, expected in dispatch_pairs:
        if dispatch.get(field_name) != expected:
            raise ScanExecutionAuthorityError(
                f"terminal replay dispatch field {field_name} is inconsistent"
            )
    if type(dispatch.get("attempt_count")) is not int or dispatch["attempt_count"] < 0:
        raise ScanExecutionAuthorityError("terminal replay dispatch attempt count is invalid")
    if dispatch["attempt_count"] != _binding_value(binding, "dispatch_attempt_count"):
        raise ScanExecutionAuthorityError("terminal replay dispatch attempt evidence is inconsistent")
    if any(
        dispatch.get(field_name) is not None
        for field_name in ("claimed_by", "claim_token", "lease_expires_at")
    ):
        raise ScanExecutionAuthorityError("terminal replay dispatch still carries a live lease")

    ownership_pairs = (
        ("execution_id", execution_id),
        ("organization_id", organization_id),
        ("worker_generation", _binding_value(binding, "child_run_worker_generation")),
        ("correlation_id", _binding_value(binding, "child_run_correlation_id")),
    )
    for field_name, expected in ownership_pairs:
        if ownership.get(field_name) != expected:
            raise ScanExecutionAuthorityError(
                f"terminal replay ownership field {field_name} is inconsistent"
            )
    if not _nonblank(ownership.get("correlation_id")):
        raise ScanExecutionAuthorityError("terminal replay ownership correlation is missing")

    recovery_pairs = (
        ("execution_id", execution_id),
        ("organization_id", organization_id),
        ("worker_generation", _binding_value(binding, "child_run_worker_generation")),
    )
    for field_name, expected in recovery_pairs:
        if recovery.get(field_name) != expected:
            raise ScanExecutionAuthorityError(
                f"terminal replay recovery field {field_name} is inconsistent"
            )
    recovery_status = recovery.get("status")
    if recovery_status not in {"REQUESTED", "CONFIRMED_TERMINATED"}:
        raise ScanExecutionAuthorityError("terminal replay recovery state is not terminally explainable")
    recovery_attempt_number = recovery.get("attempt_number")
    if type(recovery_attempt_number) is not int or recovery_attempt_number < 0:
        raise ScanExecutionAuthorityError("terminal replay recovery attempt number is invalid")
    if (
        type(recovery.get("escalation_level")) is not int
        or recovery["escalation_level"] < 0
    ):
        raise ScanExecutionAuthorityError("terminal replay recovery escalation level is invalid")
    if recovery.get("last_error") is not None:
        raise ScanExecutionAuthorityError("terminal replay recovery retains an unresolved error")
    if any(
        recovery.get(field_name) is not None
        for field_name in ("owner", "lease_token", "lease_expires_at", "next_retry_at")
    ):
        raise ScanExecutionAuthorityError("terminal replay recovery retains an active lease")
    if recovery_status == "REQUESTED":
        if (
            recovery_attempt_number != 0
            or latest_attempt is not None
            or recovery.get("last_outcome") is not None
            or recovery.get("escalation_level") != 0
        ):
            raise ScanExecutionAuthorityError("terminal replay recovery evidence is contradictory")
        recovery_attempt_id = None
    else:
        if recovery_attempt_number < 1 or not isinstance(latest_attempt, Mapping):
            raise ScanExecutionAuthorityError("terminal replay recovery attempt is missing")
        recovery_attempt_id = latest_attempt.get("attempt_id")
        if not _nonblank(recovery_attempt_id):
            raise ScanExecutionAuthorityError("terminal replay recovery attempt identity is missing")
        if type(latest_attempt.get("attempt_number")) is not int:
            raise ScanExecutionAuthorityError("terminal replay recovery attempt number is invalid")
        for field_name, expected in (
            ("execution_id", execution_id),
            ("organization_id", organization_id),
            ("worker_identity", _binding_value(binding, "child_run_worker_identity")),
            ("worker_generation", _binding_value(binding, "child_run_worker_generation")),
            ("attempt_number", recovery_attempt_number),
            ("status", "CONFIRMED_TERMINATED"),
            ("correlation_id", _binding_value(binding, "child_run_correlation_id")),
        ):
            if latest_attempt.get(field_name) != expected:
                raise ScanExecutionAuthorityError(
                    f"terminal replay recovery attempt field {field_name} is inconsistent"
                )
        if (
            not _nonblank(latest_attempt.get("worker_identity"))
            or latest_attempt.get("cancellation_status")
            not in {"CONFIRMED", "KILLED", "ALREADY_EXITED", "NO_EXTERNAL_PROCESS", "PRE_DISPATCH"}
            or not _nonblank(latest_attempt.get("reason_code"))
            or not _nonblank(latest_attempt.get("health_reference"))
            or latest_attempt.get("reason_code") != run.get("reason_code")
            or recovery.get("last_outcome") is None
            or latest_attempt.get("error_code") is not None
            or latest_attempt.get("next_retry_at") is not None
        ):
            raise ScanExecutionAuthorityError("terminal replay recovery attempt evidence is incomplete")
        if (
            type(latest_attempt.get("escalation_level")) is not int
            or latest_attempt["escalation_level"] < 0
            or latest_attempt["escalation_level"] != recovery["escalation_level"]
        ):
            raise ScanExecutionAuthorityError("terminal replay recovery escalation evidence is inconsistent")
        requested_at = _require_recovery_timestamp(
            latest_attempt.get("requested_at"), "requested_at"
        )
        started_at = _require_recovery_timestamp(
            latest_attempt.get("started_at"), "started_at"
        )
        completed_at = _require_recovery_timestamp(
            latest_attempt.get("completed_at"), "completed_at"
        )
        if not requested_at <= started_at <= completed_at:
            raise ScanExecutionAuthorityError(
                "terminal replay recovery attempt timestamps are out of order"
            )

    for field_name in ("decision", "dispatch"):
        _require_digest(claim_digests.get(field_name), f"{field_name} claim digest")
    decision_claim_digest = claim_digests.get("decision")
    dispatch_claim_digest = claim_digests.get("dispatch")
    if (decision_claim_digest is None) != (dispatch_claim_digest is None):
        raise ScanExecutionAuthorityError("terminal replay claim evidence is incomplete")

    ownership_state = ownership.get("ownership_state")
    container_type = ownership.get("container_type")
    launch_state = ownership.get("launch_commit_state")
    no_process_shape = (
        ownership_state in {
            ProcessOwnershipState.NO_EXTERNAL_PROCESS.value,
            ProcessOwnershipState.TERMINAL.value,
        }
        and container_type == ProcessContainerType.NONE.value
        and launch_state == LaunchCommitState.NOT_ATTEMPTED.value
    )
    proof_text = ownership.get("no_process_proof")
    if not _nonblank(proof_text):
        raise ScanExecutionAuthorityError("terminal replay proof is missing")

    if no_process_shape:
        if any(
            ownership.get(field_name) is not None
            for field_name in (
                "container_identity", "root_process_id", "root_process_start_token",
                "process_group_id", "session_id", "identity_attestation",
            )
        ):
            raise ScanExecutionAuthorityError("terminal replay no-process proof carries process identity")
        if run.get("process_id") is not None or run.get("process_group_id") is not None:
            raise ScanExecutionAuthorityError("terminal replay no-process run carries process identity")
        try:
            payload = decode_execution_proof(
                proof_text, expected_proof_type="NO_EXTERNAL_PROCESS",
            )
        except Exception as exc:
            raise ScanExecutionAuthorityError("terminal replay no-process proof is invalid") from exc
        _require_proof_fields(payload, EXECUTION_PROOF_NO_PROCESS_KEYS)
        if payload.get("reason_code") not in EXECUTION_REASON_CODES:
            raise ScanExecutionAuthorityError("terminal replay no-process reason is not canonical")
        if type(payload.get("recovery_attempt_number")) is not int or payload["recovery_attempt_number"] < 0:
            raise ScanExecutionAuthorityError("terminal replay no-process recovery attempt number is invalid")
        if decision_claim_digest is None and not (
            run_state == "CANCELLED"
            and expected_dispatch == "BLOCKED"
            and payload.get("reason_code") == "EXECUTION_CANCELLED_BEFORE_DISPATCH"
        ):
            raise ScanExecutionAuthorityError(
                "terminal replay no-process proof has no durable claim evidence"
            )
        if payload.get("proof_code") != payload.get("reason_code"):
            raise ScanExecutionAuthorityError("terminal replay no-process reason proof is inconsistent")
        proof_shape = (
            ProcessOwnershipState.NO_EXTERNAL_PROCESS.value,
            ProcessContainerType.NONE.value,
            LaunchCommitState.NOT_ATTEMPTED.value,
        )
        for field_name, expected in (
            ("proof_type", "NO_EXTERNAL_PROCESS"),
            ("execution_id", execution_id),
            ("organization_id", organization_id),
            ("request_id", _binding_value(binding, "child_request_id")),
            ("decision_id", _binding_value(binding, "child_decision_id")),
            ("terminal_state", run_state),
            ("dispatch_state", expected_dispatch),
            ("ownership_state", proof_shape[0] if ownership_state == ProcessOwnershipState.NO_EXTERNAL_PROCESS.value else ProcessOwnershipState.TERMINAL.value),
            ("container_type", proof_shape[1]),
            ("launch_commit_state", proof_shape[2]),
            ("worker_identity", _binding_value(binding, "child_run_worker_identity")),
            ("worker_generation", _binding_value(binding, "child_run_worker_generation")),
            ("correlation_id", _binding_value(binding, "child_run_correlation_id")),
            ("claim_identity_digest", decision_claim_digest),
            ("dispatch_identity_digest", dispatch_claim_digest),
            ("reason_code", run.get("reason_code")),
            ("recovery_status", recovery_status),
            ("recovery_attempt_number", recovery_attempt_number),
            ("recovery_attempt_id", recovery_attempt_id),
        ):
            if payload.get(field_name) != expected:
                raise ScanExecutionAuthorityError(
                    f"terminal replay no-process proof field {field_name} is inconsistent"
                )
        _require_proof_timestamp(payload.get("observed_at"), ownership.get("last_verified_at"), "observation time")
        if recovery_status == "CONFIRMED_TERMINATED":
            if recovery.get("last_outcome") != proof_text:
                raise ScanExecutionAuthorityError("terminal replay recovery outcome is not proof-bound")
            if latest_attempt.get("cancellation_status") not in {"NO_EXTERNAL_PROCESS", "PRE_DISPATCH", "CONFIRMED"}:
                raise ScanExecutionAuthorityError("terminal replay recovery cancellation status is invalid")
        return

    if (
        ownership_state != ProcessOwnershipState.TERMINAL.value
        or container_type not in {ProcessContainerType.POSIX_SESSION.value, ProcessContainerType.WINDOWS_JOB.value}
        or launch_state != LaunchCommitState.COMMITTED.value
    ):
        raise ScanExecutionAuthorityError("terminal replay process ownership is not a supported terminal proof")
    if decision_claim_digest is None or dispatch_claim_digest is None:
        raise ScanExecutionAuthorityError("terminal replay process proof has no durable claim evidence")
    if ownership.get("no_process_proof") is None:
        raise ScanExecutionAuthorityError("terminal replay process proof is missing")
    is_windows = container_type == ProcessContainerType.WINDOWS_JOB.value
    required_identity_fields = ("container_identity", "root_process_start_token", "identity_attestation", "last_verified_at", "terminalized_at")
    if not is_windows:
        required_identity_fields += ("process_group_id", "session_id")
    for field_name in required_identity_fields:
        if not _nonblank(ownership.get(field_name)):
            raise ScanExecutionAuthorityError(
                f"terminal replay process proof field {field_name} is missing"
            )
    if type(ownership.get("root_process_id")) is not int or ownership["root_process_id"] <= 1:
        raise ScanExecutionAuthorityError("terminal replay root process identity is invalid")
    if is_windows:
        try:
            from app.core.execution_context import validate_windows_ownership
            validate_windows_ownership(ownership, worker_identity=_binding_value(binding, "child_run_worker_identity"), historical=True)
        except (TypeError, ValueError, KeyError) as exc:
            raise ScanExecutionAuthorityError("terminal replay Windows job attestation is invalid") from exc
        if run.get("process_id") != ownership["root_process_id"] or run.get("process_group_id") is not None:
            raise ScanExecutionAuthorityError("terminal replay Windows root is not bound to run")
    else:
        start_parts = str(ownership["root_process_start_token"]).split(":", 2)
        if (
            len(start_parts) != 3
            or start_parts[0] != "posix"
            or re.fullmatch(r"[0-9a-fA-F-]{8,128}", start_parts[1] or "") is None
            or not start_parts[2].isdigit()
            or int(start_parts[2]) <= 0
            or not str(ownership["process_group_id"]).isdigit()
            or int(str(ownership["process_group_id"])) <= 1
            or not str(ownership["session_id"]).isdigit()
        ):
            raise ScanExecutionAuthorityError("terminal replay POSIX process proof is malformed")
        expected_container = (
            f"posix-session:{ownership['session_id']}:group:{ownership['process_group_id']}"
        )
        if ownership.get("container_identity") != expected_container:
            raise ScanExecutionAuthorityError("terminal replay process container identity is inconsistent")
        if run.get("process_id") != ownership.get("root_process_id") or str(run.get("process_group_id")) != str(ownership.get("process_group_id")):
            raise ScanExecutionAuthorityError("terminal replay process identity is not bound to the run")
        try:
            attestation = PosixProcessAttestation.model_validate_json(ownership["identity_attestation"])
        except Exception as exc:
            raise ScanExecutionAuthorityError("terminal replay process attestation is invalid") from exc
        if (
            attestation.verification_result != "VERIFIED"
            or attestation.worker_generation != ownership["worker_generation"]
            or attestation.boot_id != start_parts[1]
            or attestation.root_start_ticks != int(start_parts[2])
            or attestation.root_start_ticks <= 0
            or attestation.session_id != int(ownership["session_id"])
            or attestation.process_group_id != int(ownership["process_group_id"])
            or attestation.process_group_id <= 1
        ):
            raise ScanExecutionAuthorityError("terminal replay process attestation is inconsistent")
    try:
        payload = decode_execution_proof(
            proof_text, expected_proof_type="TERMINATION_CONFIRMED",
        )
    except Exception as exc:
        raise ScanExecutionAuthorityError("terminal replay termination proof is invalid") from exc
    _require_proof_fields(payload, EXECUTION_PROOF_TERMINATION_KEYS)
    if not is_valid_execution_terminal_outcome(run_state, payload.get("reason_code")):
        raise ScanExecutionAuthorityError("terminal replay termination reason is not canonical")
    if type(payload.get("recovery_attempt_number")) is not int or payload["recovery_attempt_number"] < 0:
        raise ScanExecutionAuthorityError("terminal replay termination recovery attempt number is invalid")
    if payload.get("termination_status") not in {"KILLED", "ALREADY_EXITED"}:
        raise ScanExecutionAuthorityError("terminal replay termination status is invalid")
    if type(payload.get("process_id")) is not int or payload["process_id"] <= 1:
        raise ScanExecutionAuthorityError("terminal replay termination process identity is invalid")
    if is_windows:
        if payload.get("process_group_id") is not None or payload.get("session_id") is not None:
            raise ScanExecutionAuthorityError("terminal replay Windows proof contains POSIX identity")
    else:
        if (
            type(payload.get("process_group_id")) is not str
            or not payload["process_group_id"].isdigit()
            or int(payload["process_group_id"]) <= 1
        ):
            raise ScanExecutionAuthorityError("terminal replay termination process group is invalid")
        if type(payload.get("session_id")) is not int or payload["session_id"] < 0:
            raise ScanExecutionAuthorityError("terminal replay termination session is invalid")
        start_parts = str(payload.get("process_start_token") or "").split(":", 2)
        if (
            len(start_parts) != 3
            or start_parts[0] != "posix"
            or not re.fullmatch(r"[0-9a-fA-F-]{8,128}", start_parts[1])
            or not start_parts[2].isdigit()
        ):
            raise ScanExecutionAuthorityError("terminal replay termination start token is invalid")
    for field_name, expected in (
        ("proof_type", "TERMINATION_CONFIRMED"),
        ("execution_id", execution_id),
        ("organization_id", organization_id),
        ("request_id", _binding_value(binding, "child_request_id")),
        ("decision_id", _binding_value(binding, "child_decision_id")),
        ("terminal_state", run_state),
        ("dispatch_state", expected_dispatch),
        ("ownership_state", ProcessOwnershipState.TERMINAL.value),
        ("container_type", container_type),
        ("launch_commit_state", LaunchCommitState.COMMITTED.value),
        ("worker_identity", _binding_value(binding, "child_run_worker_identity")),
        ("worker_generation", _binding_value(binding, "child_run_worker_generation")),
        ("correlation_id", _binding_value(binding, "child_run_correlation_id")),
        ("claim_identity_digest", decision_claim_digest),
        ("dispatch_identity_digest", dispatch_claim_digest),
        ("reason_code", run.get("reason_code")),
        ("recovery_status", recovery_status),
        ("recovery_attempt_number", recovery_attempt_number),
        ("recovery_attempt_id", recovery_attempt_id),
        ("termination_status", payload.get("termination_status")),
        ("process_id", ownership.get("root_process_id")),
        ("process_group_id", ownership.get("process_group_id")),
        ("process_start_token", ownership.get("root_process_start_token")),
        ("session_id", None if is_windows else int(ownership.get("session_id"))),
        ("identity_attestation", ownership.get("identity_attestation")),
        ("identity_attestation_digest", canonical_binding_digest(ownership["identity_attestation"])),
    ):
        if payload.get(field_name) != expected:
            raise ScanExecutionAuthorityError(
                f"terminal replay process proof field {field_name} is inconsistent"
            )
    if payload.get("termination_status") not in {"KILLED", "ALREADY_EXITED"}:
        raise ScanExecutionAuthorityError("terminal replay termination status is invalid")
    if recovery_status == "CONFIRMED_TERMINATED":
        if recovery.get("last_outcome") != proof_text:
            raise ScanExecutionAuthorityError("terminal replay recovery outcome is not proof-bound")
        if latest_attempt.get("cancellation_status") != payload.get("termination_status"):
            raise ScanExecutionAuthorityError("terminal replay recovery cancellation status is inconsistent")
    _require_proof_timestamp(payload.get("observed_at"), ownership.get("terminalized_at"), "terminalization time")


class ScanExecutionAuthority:
    """Resolve one durable child authority for each exact tool launch.

    A provider instance carries only the scan/tenant/engine context supplied by
    the trusted orchestrator. It never stores a capability or selects an
    operation. The adapter must provide the exact server-generated
    ``operation_id`` for every launch.
    """

    def __init__(
        self,
        *,
        scan_request_id: str,
        organization_id: str,
        engine_id: str,
        validated_target: ValidatedTarget,
        database: Any = db_manager,
    ) -> None:
        self.scan_request_id = scan_request_id
        self.organization_id = organization_id
        self.engine_id = engine_id
        self.validated_target = validated_target
        self.database = database

    def resolve_launch_binding(
        self,
        *,
        operation_id: str,
        tool_id: Optional[str] = None,
        allow_terminal_replay: bool = False,
    ) -> ScanExecutionLaunchBinding:
        """Reload and validate one exact parent/operation/child tuple."""
        if not all(
            isinstance(value, str) and value.strip()
            for value in (self.scan_request_id, self.organization_id, self.engine_id, operation_id)
        ):
            raise ScanExecutionAuthorityError("scan execution authority identity is incomplete")
        if not operation_id.startswith(f"{self.engine_id}:"):
            raise ScanExecutionAuthorityError("operation identity is not owned by the requested engine")

        reader = getattr(self.database, "get_scan_authorization_launch_binding", None)
        if reader is None:
            raise ScanExecutionAuthorityError("authoritative launch-binding lookup is unavailable")
        raw = reader(self.scan_request_id, self.organization_id, operation_id)
        if raw is None:
            raise ScanExecutionAuthorityError("exact selected child operation was not found")
        try:
            binding = ScanExecutionLaunchBinding(**raw)
        except (TypeError, ValueError) as exc:
            raise ScanExecutionAuthorityError("authoritative launch-binding snapshot is malformed") from exc

        target = validate_validated_target(self.validated_target)
        if binding.organization_id != target.organization_id or binding.organization_id != self.organization_id:
            raise ScanExecutionAuthorityError("launch binding tenant does not match the validated target")
        if binding.scan_request_id != self.scan_request_id:
            raise ScanExecutionAuthorityError("launch binding request identity does not match")
        if binding.operation_id != operation_id or binding.operation_engine_id != self.engine_id:
            raise ScanExecutionAuthorityError("launch binding operation identity does not match")
        if tool_id is not None and binding.operation_tool_id != tool_id:
            raise ScanExecutionAuthorityError("launch binding tool identity does not match")
        if operation_id != f"{binding.operation_engine_id}:{binding.operation_tool_id}":
            raise ScanExecutionAuthorityError("operation identity is not the canonical engine/tool identity")

        terminal_replay = bool(
            allow_terminal_replay
            and binding.child_run_state in EXECUTION_RUN_TERMINAL_STATES
            and binding.dispatch_state == _expected_terminal_dispatch(binding.child_run_state)
        )
        if binding.parent_state != "DISPATCHABLE" and not (
            terminal_replay and binding.parent_state in TERMINAL_REPLAY_PARENT_STATES
        ):
            raise ScanExecutionAuthorityError("scan parent is not dispatchable")
        if binding.operation_selection_state != "SELECTED":
            raise ScanExecutionAuthorityError("operation is not selected in the approved manifest")
        if binding.operation_capability_state in {"NATIVE", "MANUAL_ONLY", "POLICY_GAP", "DEFERRED_UNVERIFIED"}:
            raise ScanExecutionAuthorityError("operation is not eligible for external process execution")
        if not all((binding.child_request_id, binding.child_decision_id, binding.child_execution_id)):
            raise ScanExecutionAuthorityError("selected operation has incomplete child authority identity")

        target_bindings = (
            (binding.parent_project_id, target.project_id, "project"),
            (binding.parent_asset_id, target.asset_id, "asset"),
            (binding.parent_target_id, target.target_id, "target"),
            (binding.parent_target_integrity_seal, target.integrity_seal, "target integrity"),
            (binding.parent_target_policy_version, target.policy_version, "target policy"),
            (binding.operation_target_id, target.target_id, "operation target"),
            (binding.operation_authorization_decision_id, target.authorization_decision_id, "authorization decision"),
        )
        for stored, supplied, label in target_bindings:
            if stored != supplied:
                raise ScanExecutionAuthorityError(f"launch binding {label} does not match the validated target")

        policy = get_operation_policy(binding.operation_tool_id, binding.operation_family)
        if policy is None:
            raise ScanExecutionAuthorityError("operation is not represented by the canonical policy")
        if not is_canonical_operation_policy_revision(binding.operation_policy_revision):
            raise ScanExecutionAuthorityError("operation policy revision is not canonical")
        if binding.operation_policy_revision != OPERATION_POLICY_REVISION:
            raise ScanExecutionAuthorityError("operation policy revision is not current")
        expected_options = dict(policy.get("required_options", {}))
        expected_resources = dict(policy.get("resource_budget", {}))
        expected_account_budget = dict(policy.get("account_impact_budget", {}))
        expected_credentials = dict(policy.get("credential_scope", {}))
        if dict(binding.operation_options) != expected_options:
            raise ScanExecutionAuthorityError("operation options are not canonical")
        if dict(binding.operation_resource_budget) != expected_resources:
            raise ScanExecutionAuthorityError("operation resource budget is not canonical")
        if dict(binding.operation_account_impact_budget) != expected_account_budget:
            raise ScanExecutionAuthorityError("operation account-impact budget is not canonical")
        if dict(binding.operation_credential_scope) != expected_credentials:
            raise ScanExecutionAuthorityError("operation credential scope is not canonical")

        request_fields = (
            (binding.child_request_organization_id, binding.organization_id, "request tenant"),
            (binding.child_request_project_id, binding.parent_project_id, "request project"),
            (binding.child_request_asset_id, binding.parent_asset_id, "request asset"),
            (binding.child_request_target_id, binding.operation_target_id, "request target"),
            (binding.child_request_authorization_decision_id, binding.operation_authorization_decision_id, "request authorization decision"),
            (binding.child_request_target_policy_version, binding.parent_target_policy_version, "request target policy"),
            (binding.child_request_tool_id, binding.operation_tool_id, "request tool"),
            (binding.child_request_operation_family, binding.operation_family, "request operation family"),
            (binding.child_request_operation_policy_revision, binding.operation_policy_revision, "request policy revision"),
        )
        for stored, expected, label in request_fields:
            if stored != expected:
                raise ScanExecutionAuthorityError(f"child {label} binding does not match the selected operation")
        if binding.child_request_state != "AUTHORIZED" and not (
            terminal_replay and binding.child_request_state == "REVOKED"
        ):
            raise ScanExecutionAuthorityError("child execution request is not authorized")
        if not binding.child_request_fingerprint:
            raise ScanExecutionAuthorityError("child execution request fingerprint is missing")
        if not _same_mapping(binding.child_request_operation_options, binding.operation_options):
            raise ScanExecutionAuthorityError("child execution request operation snapshot does not match")
        if not _same_mapping(binding.child_request_resource_budget, binding.operation_resource_budget):
            raise ScanExecutionAuthorityError("child execution request resource budget does not match")
        if not _same_mapping(binding.child_request_account_impact_budget, binding.operation_account_impact_budget):
            raise ScanExecutionAuthorityError("child execution request account budget does not match")
        if not _same_mapping(binding.child_request_credential_scope, binding.operation_credential_scope):
            raise ScanExecutionAuthorityError("child execution request credential scope does not match")

        decision_fields = (
            (binding.child_decision_organization_id, binding.organization_id, "decision tenant"),
            (binding.child_decision_project_id, binding.child_request_project_id, "decision project"),
            (binding.child_decision_asset_id, binding.child_request_asset_id, "decision asset"),
            (binding.child_decision_target_id, binding.child_request_target_id, "decision target"),
            (binding.child_decision_authorization_decision_id, binding.child_request_authorization_decision_id, "decision authorization decision"),
            (binding.child_decision_target_policy_version, binding.child_request_target_policy_version, "decision target policy"),
            (binding.child_decision_tool_id, binding.child_request_tool_id, "decision tool"),
            (binding.child_decision_operation_family, binding.child_request_operation_family, "decision operation family"),
            (binding.child_decision_operation_policy_revision, binding.operation_policy_revision, "decision policy revision"),
        )
        for stored, expected, label in decision_fields:
            if stored != expected:
                raise ScanExecutionAuthorityError(f"child {label} binding does not match the selected operation")
        if binding.child_decision_approval_state != "APPROVED":
            raise ScanExecutionAuthorityError("child execution decision is not approved")
        if not binding.child_decision_session_jti or not binding.child_decision_worker_identity:
            raise ScanExecutionAuthorityError("child execution decision identity is incomplete")
        if not _same_mapping(binding.child_decision_operation_options, binding.operation_options):
            raise ScanExecutionAuthorityError("child execution decision operation snapshot does not match")
        if not _same_mapping(binding.child_decision_resource_budget, binding.operation_resource_budget):
            raise ScanExecutionAuthorityError("child execution decision resource budget does not match")
        if not _same_mapping(binding.child_decision_account_impact_budget, binding.operation_account_impact_budget):
            raise ScanExecutionAuthorityError("child execution decision account budget does not match")
        if not _same_mapping(binding.child_decision_credential_scope, binding.operation_credential_scope):
            raise ScanExecutionAuthorityError("child execution decision credential scope does not match")

        run_fields = (
            (binding.child_run_request_id, binding.child_request_id, "run request"),
            (binding.child_run_organization_id, binding.organization_id, "run tenant"),
            (binding.child_run_approved_decision_id, binding.child_decision_id, "run decision"),
            (binding.child_run_target_policy_version, binding.child_request_target_policy_version, "run target policy"),
            (binding.child_run_operation_policy_revision, binding.operation_policy_revision, "run policy revision"),
            (binding.child_run_request_fingerprint, binding.child_request_fingerprint, "run request fingerprint"),
            (binding.child_run_worker_identity, binding.child_decision_worker_identity, "run worker identity"),
        )
        for stored, expected, label in run_fields:
            if stored != expected:
                raise ScanExecutionAuthorityError(f"child {label} binding does not match the selected operation")
        if binding.child_run_snapshot_completeness != "COMPLETE":
            raise ScanExecutionAuthorityError("child execution run snapshot is incomplete")
        if binding.child_run_state not in {"REQUESTED", "STARTING"} and not terminal_replay:
            raise ScanExecutionAuthorityError("child execution run is not launchable")
        if not _same_mapping(binding.child_run_operation_options, binding.operation_options):
            raise ScanExecutionAuthorityError("child execution run operation snapshot does not match")
        if not _same_mapping(binding.child_run_resource_budget, binding.operation_resource_budget):
            raise ScanExecutionAuthorityError("child execution run resource budget does not match")
        if not _same_mapping(binding.child_run_account_impact_budget, binding.operation_account_impact_budget):
            raise ScanExecutionAuthorityError("child execution run account budget does not match")
        if not _same_mapping(binding.child_run_credential_scope, binding.operation_credential_scope):
            raise ScanExecutionAuthorityError("child execution run credential scope does not match")

        if binding.dispatch_state not in {"PENDING", "CLAIMED"} and not (
            terminal_replay and binding.dispatch_state == _expected_terminal_dispatch(binding.child_run_state)
        ):
            raise ScanExecutionAuthorityError("child dispatch intent is not launchable")
        from app.core.execution_service import get_worker_generation, get_worker_identity

        if binding.child_decision_worker_identity != get_worker_identity():
            raise ScanExecutionAuthorityError("child decision is bound to another worker identity")
        if binding.child_run_worker_generation != get_worker_generation():
            raise ScanExecutionAuthorityError("child run is bound to another worker generation")
        if terminal_replay:
            validate_terminal_replay_proof(binding, database=self.database)
        else:
            if self.database.is_token_revoked(binding.child_decision_session_jti):
                raise ScanExecutionAuthorityError("approving administrator session is revoked")

            now = datetime.now(timezone.utc)
            for value, label in (
                (binding.child_request_expires_at, "request"),
                (binding.child_decision_expires_at, "decision"),
            ):
                if _parse_timestamp(value, label) <= now:
                    raise ScanExecutionAuthorityError(f"child {label} authority is expired")
            if binding.child_decision_revoked_at:
                raise ScanExecutionAuthorityError("child decision is revoked")
            if binding.child_decision_consumed_at:
                raise ScanExecutionAuthorityError("child decision is already consumed")
        return binding

    def issue_capability(
        self,
        *,
        operation_id: str,
        tool_id: Optional[str] = None,
        operation_family: Optional[str] = None,
        operation_options: Optional[Mapping[str, Any]] = None,
        command: list[str],
    ) -> ExecutionDecisionCapability:
        """Resolve one exact operation and issue one command-bound capability.

        The durable operation row is authoritative for policy metadata.  Adapter
        metadata is accepted only as an optional consistency assertion; it can
        never select or alter the persisted operation.  This lets existing
        adapters provide the exact operation ID without duplicating the canonical
        policy document at every launch site.
        """
        binding = self.resolve_launch_binding(operation_id=operation_id, tool_id=tool_id)
        if operation_family is not None and operation_family != binding.operation_family:
            raise ScanExecutionAuthorityError("launch operation family does not match the selected operation")
        if operation_options is not None and dict(operation_options) != dict(binding.operation_options):
            raise ScanExecutionAuthorityError("launch operation options do not match the selected operation")
        return issue_execution_capability(
            decision_id=binding.child_decision_id,
            validated_target=self.validated_target,
            tool_id=binding.operation_tool_id,
            operation_family=binding.operation_family,
            operation_options=dict(binding.operation_options),
            command=command,
            database=self.database,
        )


__all__ = [
    "ScanExecutionAuthority",
    "ScanExecutionAuthorityError",
    "ScanExecutionLaunchBinding",
    "TERMINAL_REPLAY_PARENT_STATES",
    "validate_terminal_replay_proof",
]
