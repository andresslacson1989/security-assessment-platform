"""Authoritative execution-decision verification for the worker boundary."""

from __future__ import annotations

import os
import secrets
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from app.core.db import db_manager
from app.core.models import ExecutionDecisionRecord, ValidatedTarget
from app.core.ssrf_protector import validate_validated_target
from app.core.tool_operation_policy import (
    OPERATION_POLICY_REVISION,
    get_operation_policy,
    is_canonical_operation_policy_revision,
)


_CAPABILITY_TOKEN = object()


class ExecutionDecisionError(ValueError):
    """Raised when an execution decision cannot authorize a worker launch."""


@dataclass(frozen=True)
class ExecutionDecisionCapability:
    """Opaque verifier-issued capability bound to one exact execution request."""

    decision: ExecutionDecisionRecord
    target: ValidatedTarget
    tool_id: str
    operation_family: str
    operation_options_digest: str
    command_digest: str
    worker_identity: str
    _issuer_token: object
    database: Any
    claim_token: Optional[str] = None

    def assert_valid_for_launch(
        self,
        *,
        tool_id: str,
        operation_family: str,
        operation_options: dict[str, Any],
        command: list[str],
        worker_identity: str,
    ) -> None:
        if self._issuer_token is not _CAPABILITY_TOKEN:
            raise ExecutionDecisionError("execution capability was not issued by the decision verifier")
        if (
            self.tool_id != tool_id
            or self.operation_family != operation_family
            or self.operation_options_digest != _operation_digest(operation_options)
            or self.command_digest != _command_digest(command)
            or self.worker_identity != worker_identity
        ):
            raise ExecutionDecisionError("execution capability does not match the launch request")

    def revalidate_and_claim(
        self,
        *,
        tool_id: str,
        operation_family: str,
        operation_options: dict[str, Any],
        command: list[str],
        worker_identity: str,
        timeout: float,
        max_output_bytes: int,
    ) -> None:
        """Re-read authority and atomically reserve this decision for one launch."""
        self.assert_valid_for_launch(
            tool_id=tool_id, operation_family=operation_family,
            operation_options=operation_options, command=command,
            worker_identity=worker_identity,
        )
        decision = self.database.get_execution_decision(
            self.decision.id, organization_id=self.decision.organization_id,
        )
        if decision is None or decision != self.decision:
            raise ExecutionDecisionError("execution decision changed after capability issuance")
        now = datetime.now(timezone.utc)
        if decision.revoked_at is not None or decision.consumed_at is not None or decision.expires_at <= now:
            raise ExecutionDecisionError("execution decision is revoked, expired, or already consumed")
        if self.database.is_token_revoked(decision.session_jti):
            raise ExecutionDecisionError("approving administrator session is revoked")
        if not is_canonical_operation_policy_revision(decision.operation_policy_revision):
            raise ExecutionDecisionError("execution policy revision is no longer current")
        timeout_limit = decision.resource_budget.get("timeout_seconds")
        output_limit = decision.resource_budget.get("max_output_bytes")
        if timeout_limit is None or output_limit is None or timeout <= 0 or max_output_bytes <= 0:
            raise ExecutionDecisionError("execution resource budget is incomplete")
        if timeout > float(timeout_limit) or max_output_bytes > int(output_limit):
            raise ExecutionDecisionError("launch request exceeds approved resource budget")
        claim = self.database.claim_execution_decision(
            decision.id, decision.organization_id, decision.session_jti,
            decision.worker_identity, decision.operation_policy_revision, now=now,
        )
        if not claim:
            raise ExecutionDecisionError("execution decision could not be atomically claimed")
        object.__setattr__(self, "claim_token", claim if isinstance(claim, str) else None)

    def mark_started(self) -> None:
        marker = getattr(self.database, "mark_execution_decision_started", None)
        if marker is not None and not self.claim_token:
            raise ExecutionDecisionError("execution decision has no launch fence")
        if marker is not None and not marker(self.decision.id, self.decision.organization_id, self.worker_identity, self.claim_token):
            raise ExecutionDecisionError("execution decision launch lease could not be committed")

    def release_claim(self) -> None:
        releaser = getattr(self.database, "release_execution_decision_claim", None)
        if releaser is not None:
            if not self.claim_token:
                return
            releaser(self.decision.id, self.decision.organization_id, self.worker_identity, self.claim_token)


def _operation_digest(operation_options: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(operation_options, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _command_digest(command: list[str]) -> str:
    if not isinstance(command, list) or not command or any(not isinstance(item, str) for item in command):
        raise ExecutionDecisionError("exact command vector is required")
    return hashlib.sha256(json.dumps(command, separators=(",", ":")).encode("utf-8")).hexdigest()


def issue_execution_capability(
    *,
    decision_id: str,
    validated_target: ValidatedTarget,
    tool_id: str,
    operation_family: str,
    operation_options: dict[str, Any],
    command: list[str],
    worker_identity: str,
    database: Any = db_manager,
) -> ExecutionDecisionCapability:
    """Verify the durable decision and issue an opaque one-launch capability."""
    if not isinstance(decision_id, str) or not decision_id.strip():
        raise ExecutionDecisionError("execution decision identifier is required")
    if not isinstance(validated_target, ValidatedTarget):
        raise ExecutionDecisionError("gateway-issued ValidatedTarget is required")
    if not isinstance(operation_options, dict):
        raise ExecutionDecisionError("operation options must be an object")
    command_digest = _command_digest(command)
    if not isinstance(worker_identity, str) or not worker_identity.strip():
        raise ExecutionDecisionError("worker identity is required")
    expected_worker = os.environ.get("CYBERASSESS_WORKER_IDENTITY", "").strip()
    if not expected_worker or not secrets.compare_digest(expected_worker, worker_identity):
        raise ExecutionDecisionError("worker identity is not authoritative for this process")

    target = validate_validated_target(validated_target)
    decision = database.get_execution_decision(decision_id, organization_id=target.organization_id)
    if decision is None:
        raise ExecutionDecisionError("execution decision was not found in the authorized tenant")
    now = datetime.now(timezone.utc)
    if decision.revoked_at is not None or decision.expires_at <= now:
        raise ExecutionDecisionError("execution decision is revoked or expired")
    if decision.approval_state != "APPROVED":
        raise ExecutionDecisionError("execution decision is not approved")
    if not decision.session_jti or database.is_token_revoked(decision.session_jti):
        raise ExecutionDecisionError("approving administrator session is revoked")
    if decision.worker_identity != worker_identity:
        raise ExecutionDecisionError("execution decision is bound to another worker")
    if (
        decision.organization_id != target.organization_id
        or decision.project_id != target.project_id
        or decision.asset_id != target.asset_id
        or decision.target_id != target.target_id
        or decision.authorization_decision_id != target.authorization_decision_id
        or decision.target_policy_version != target.policy_version
    ):
        raise ExecutionDecisionError("execution decision target binding does not match")
    if not is_canonical_operation_policy_revision(decision.operation_policy_revision):
        raise ExecutionDecisionError("execution decision policy revision is not canonical")
    policy = get_operation_policy(decision.tool_id, decision.operation_family)
    if policy is None or decision.tool_id != tool_id or decision.operation_family != operation_family:
        raise ExecutionDecisionError("requested tool operation is not represented by the policy")
    if _operation_digest(decision.operation_options) != _operation_digest(operation_options):
        raise ExecutionDecisionError("execution operation options do not match the approved decision")
    required_options = policy.get("required_options", {})
    if any(decision.operation_options.get(key) != value for key, value in required_options.items()):
        raise ExecutionDecisionError("execution options do not satisfy the canonical policy row")
    if decision.operation_policy_revision != OPERATION_POLICY_REVISION:
        raise ExecutionDecisionError("execution decision revision does not match the loaded policy artifact")
    if decision.credential_scope.get("provider") != decision.operation_options.get("provider"):
        raise ExecutionDecisionError("credential scope is not bound to the approved provider")
    if decision.resource_budget and any(int(value) <= 0 for value in decision.resource_budget.values()):
        raise ExecutionDecisionError("execution resource budget is invalid")
    if decision.account_impact_budget and any(int(value) < 0 for value in decision.account_impact_budget.values()):
        raise ExecutionDecisionError("execution account-impact budget is invalid")

    return ExecutionDecisionCapability(
        decision=decision,
        target=target,
        tool_id=tool_id,
        operation_family=operation_family,
        operation_options_digest=_operation_digest(operation_options),
        command_digest=command_digest,
        worker_identity=worker_identity,
        _issuer_token=_CAPABILITY_TOKEN,
        database=database,
    )
