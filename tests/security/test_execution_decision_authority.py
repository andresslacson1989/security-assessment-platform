"""Adversarial tests for the durable worker execution-decision boundary."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.execution_decision import ExecutionDecisionError, issue_execution_capability
from app.core.models import ExecutionDecisionRecord, ExecutionLeaseClaim, Target, TargetType
from app.core.models import UserProfile, UserRole
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

    def claim_execution_decision(self, decision_id, organization_id, session_jti, worker_identity, policy_revision, now=None):
        if self.revoked or self.decision.consumed_at is not None:
            return None
        lease_time = now or datetime.now(timezone.utc)
        self.decision = self.decision.model_copy(update={"claim_owner": worker_identity, "claim_token": "test-claim", "claim_expires_at": lease_time + timedelta(seconds=30)})
        return ExecutionLeaseClaim(token="test-claim", owner=worker_identity, expires_at=lease_time + timedelta(seconds=30))


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


def test_launch_revalidation_consumes_decision_once_and_enforces_budget(monkeypatch):
    monkeypatch.setenv("CYBERASSESS_WORKER_IDENTITY", "worker-1")
    target = _target()
    store = FakeDecisionStore(_decision(target))
    capability = _issue(store, target)
    options = {"provider": "aws", "output_format": "json-asff", "quiet": True}
    command = ["/managed/prowler", "aws", "-M", "json-asff"]

    capability.revalidate_and_claim(
        tool_id="prowler", operation_family="cloud_audit", operation_options=options,
        command=command, worker_identity="worker-1", timeout=120, max_output_bytes=10485760,
    )
    with pytest.raises(ExecutionDecisionError, match="consumed|changed"):
        capability.revalidate_and_claim(
            tool_id="prowler", operation_family="cloud_audit", operation_options=options,
            command=command, worker_identity="worker-1", timeout=120, max_output_bytes=10485760,
        )


def test_launch_revalidation_rejects_expired_or_over_budget_decision(monkeypatch):
    monkeypatch.setenv("CYBERASSESS_WORKER_IDENTITY", "worker-1")
    target = _target()
    store = FakeDecisionStore(_decision(target))
    capability = _issue(store, target)
    with pytest.raises(ExecutionDecisionError, match="budget"):
        capability.revalidate_and_claim(
            tool_id="prowler", operation_family="cloud_audit",
            operation_options={"provider": "aws", "output_format": "json-asff", "quiet": True},
            command=["/managed/prowler", "aws", "-M", "json-asff"],
            worker_identity="worker-1", timeout=121, max_output_bytes=10485760,
        )
    store.decision = store.decision.model_copy(update={"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)})
    with pytest.raises(ExecutionDecisionError, match="changed|expired"):
        capability.revalidate_and_claim(
            tool_id="prowler", operation_family="cloud_audit",
            operation_options={"provider": "aws", "output_format": "json-asff", "quiet": True},
            command=["/managed/prowler", "aws", "-M", "json-asff"],
            worker_identity="worker-1", timeout=120, max_output_bytes=10485760,
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


def test_sqlite_decision_claim_is_durable_atomic_and_audited(tmp_path):
    from app.core.db import DatabaseManager

    database = DatabaseManager(tmp_path / "authority.db")
    now = datetime.now(timezone.utc).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)", ("org-a", "Org A", "org-a", now))
        conn.execute("INSERT INTO projects (id, organization_id, name, created_at) VALUES (?, ?, ?, ?)", ("project-a", "org-a", "Project A", now))
        conn.execute("INSERT INTO assets (id, organization_id, project_id, name, type, target_value, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", ("asset-a", "org-a", "project-a", "AWS account", "CLOUD_ACCOUNT", "aws://123456789012", now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, ?, 'ADMIN', ?, 1, ?)", ("admin-1", "admin", "admin@example.test", "hash", "org-a", now))

    target = _target()
    decision = _decision(target)
    database.create_execution_decision(decision)
    assert database.get_execution_decision(decision.id, organization_id="org-a").id == decision.id
    assert database.claim_execution_decision(decision.id, "org-a", "session-1", "worker-1", OPERATION_POLICY_REVISION)
    assert not database.claim_execution_decision(decision.id, "org-a", "session-1", "worker-1", OPERATION_POLICY_REVISION)
    stored = database.get_execution_decision(decision.id, organization_id="org-a")
    assert stored.consumed_at is None
    assert stored.claim_owner == "worker-1"
    assert stored.claim_token
    assert database.mark_execution_decision_started(decision.id, "org-a", "worker-1", stored.claim_token)
    assert database.get_execution_decision(decision.id, organization_id="org-a").consumed_at is not None
    events, _ = database.list_audit_events(organization_id="org-a", limit=20)
    assert {event.action.value for event in events} >= {
        "EXECUTION_DECISION_CREATED", "EXECUTION_DECISION_CLAIMED", "EXECUTION_DECISION_STARTED",
    }


def test_revoke_route_resolves_request_id_to_linked_decision():
    import asyncio
    from app.api import executions

    class RequestAwareStore:
        def __init__(self):
            self.called = None

        def revoke_execution_request(self, *args, **kwargs):
            self.called = (args, kwargs)
            return True

    store = RequestAwareStore()
    original = executions.db_manager
    executions.db_manager = store
    try:
        user = UserProfile(id="admin-1", username="admin", email="admin@example.test", role=UserRole.ADMIN, organization_id="org-a")
        result = asyncio.run(executions.revoke_execution_request("request-1", user))
    finally:
        executions.db_manager = original
    assert result == {"request_id": "request-1", "revoked": True}
    assert store.called == (("request-1",), {"organization_id": "org-a", "actor": "admin"})


def test_approval_session_must_match_authenticated_principal(monkeypatch):
    from app.api import executions

    monkeypatch.setattr(executions, "decode_access_token", lambda _token: {"sub": "other-user", "org_id": "org-other", "jti": "session-1"})
    user = UserProfile(id="admin-1", username="admin", email="admin@example.test", role=UserRole.ADMIN, organization_id="org-a")
    with pytest.raises(Exception, match="does not match"):
        executions._session_jti("Bearer token", user)
