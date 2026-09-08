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
from types import MappingProxyType
from typing import Any, Mapping, Optional

from app.core.db import db_manager
from app.core.execution_decision import (
    ExecutionDecisionCapability,
    ExecutionDecisionError,
    issue_execution_capability,
)
from app.core.models import ValidatedTarget
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

        if binding.parent_state != "DISPATCHABLE":
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
        if binding.child_request_state != "AUTHORIZED":
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
        if binding.child_run_state not in {"REQUESTED", "STARTING"}:
            raise ScanExecutionAuthorityError("child execution run is not launchable")
        if not _same_mapping(binding.child_run_operation_options, binding.operation_options):
            raise ScanExecutionAuthorityError("child execution run operation snapshot does not match")
        if not _same_mapping(binding.child_run_resource_budget, binding.operation_resource_budget):
            raise ScanExecutionAuthorityError("child execution run resource budget does not match")
        if not _same_mapping(binding.child_run_account_impact_budget, binding.operation_account_impact_budget):
            raise ScanExecutionAuthorityError("child execution run account budget does not match")
        if not _same_mapping(binding.child_run_credential_scope, binding.operation_credential_scope):
            raise ScanExecutionAuthorityError("child execution run credential scope does not match")

        if binding.dispatch_state not in {"PENDING", "CLAIMED"}:
            raise ScanExecutionAuthorityError("child dispatch intent is not launchable")
        from app.core.execution_service import get_worker_generation, get_worker_identity

        if binding.child_decision_worker_identity != get_worker_identity():
            raise ScanExecutionAuthorityError("child decision is bound to another worker identity")
        if binding.child_run_worker_generation != get_worker_generation():
            raise ScanExecutionAuthorityError("child run is bound to another worker generation")
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
]
