"""Adversarial tests for the durable worker execution-decision boundary."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.execution_decision import ExecutionDecisionError, issue_execution_capability
from app.core.models import ExecutionDecisionRecord, Target, TargetType
from app.core.ssrf_protector import create_validated_target
from app.core.tool_operation_policy import OPERATION_POLICY_REVISION


class FakeDecisionStore:
    def __init__(self, decision, revoked=False):
        self.decision = decision
        self.revoked = revoked

    def get_execution_decision(self, decision_id, organization_id=None):
        if decision_id != self.decision.id or organization_id != self.decision.organization_id:
            return None
        return self.decision

    def is_token_revoked(self, _jti):
        return self.revoked


def _target():
    return create_validated_target(
        Target(name="AWS account", type=TargetType.CLOUD_ACCOUNT, value="aws://123456789012"),
        organization_id="org-a", project_id="project-a", asset_id="asset-a",
        active_probing_granted=True,
    )


def _decision(target, **changes):
    values = {
        "id": "decision-1",
        "organization_id": target.organization_id,
        "project_id": target.project_id,
        "asset_id": target.asset_id,
        "target_id": target.target_id,
        "authorization_decision_id": target.authorization_decision_id,
        "target_policy_version": target.policy_version,
        "tool_id": "prowler",
        "operation_family": "cloud_audit",
        "operation_options": {"provider": "aws", "output_format": "json-asff", "quiet": True},
        "operation_policy_revision": OPERATION_POLICY_REVISION,
        "approval_state": "APPROVED",
        "approver_user_id": "admin-1",
        "session_jti": "session-1",
        "worker_identity": "worker-1",
        "resource_budget": {"timeout_seconds": 120, "max_output_bytes": 10485760},
        "account_impact_budget": {"read_only": 1},
        "credential_scope": {"provider": "aws"},
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    values.update(changes)
    return ExecutionDecisionRecord(**values)


def _issue(store, target, **kwargs):
    import os
    os.environ["CYBERASSESS_WORKER_IDENTITY"] = "worker-1"
    options = {"provider": "aws", "output_format": "json-asff", "quiet": True}
    options.update(kwargs.pop("operation_options", {}))
    return issue_execution_capability(
        decision_id="decision-1", validated_target=target, tool_id="prowler",
        operation_family="cloud_audit", operation_options=options,
        command=["/managed/prowler", "aws", "-M", "json-asff"],
        worker_identity="worker-1", database=store,
    )


def test_factory_issued_capability_binds_exact_request(monkeypatch):
    monkeypatch.setenv("CYBERASSESS_WORKER_IDENTITY", "worker-1")
    target = _target()
    capability = _issue(FakeDecisionStore(_decision(target)), target)
    capability.assert_valid_for_launch(
        tool_id="prowler", operation_family="cloud_audit",
        operation_options={"provider": "aws", "output_format": "json-asff", "quiet": True},
        command=["/managed/prowler", "aws", "-M", "json-asff"], worker_identity="worker-1",
    )
    with pytest.raises(ExecutionDecisionError):
        capability.assert_valid_for_launch(
            tool_id="sqlmap", operation_family="cloud_audit",
            operation_options={"provider": "aws", "output_format": "json-asff", "quiet": True},
            command=["/managed/prowler", "aws", "-M", "json-asff"], worker_identity="worker-1",
        )


@pytest.mark.parametrize("changes", [
    {"approval_state": "REVOKED"},
    {"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)},
    {"organization_id": "org-other"},
    {"tool_id": "sqlmap"},
    {"operation_family": "sql_injection"},
])
def test_decision_mismatch_or_expiry_fails_closed(monkeypatch, changes):
    monkeypatch.setenv("CYBERASSESS_WORKER_IDENTITY", "worker-1")
    target = _target()
    store = FakeDecisionStore(_decision(target, **changes), revoked=changes.get("approval_state") == "REVOKED")
    with pytest.raises(ExecutionDecisionError):
        _issue(store, target)


def test_revoked_approver_session_fails_closed(monkeypatch):
    monkeypatch.setenv("CYBERASSESS_WORKER_IDENTITY", "worker-1")
    target = _target()
    with pytest.raises(ExecutionDecisionError):
        _issue(FakeDecisionStore(_decision(target), revoked=True), target)
