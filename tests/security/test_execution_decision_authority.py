"""Adversarial tests for the durable worker execution-decision boundary."""

from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

from app.core.execution_decision import ExecutionDecisionError, issue_execution_capability
from app.core.models import AuditAction, AuditEvent, ExecutionDecisionRecord, ExecutionLeaseClaim, ExecutionRunRecord, Target, TargetType
from app.core.models import UserProfile, UserRole
from app.core.ssrf_protector import create_validated_target
from app.core.tool_operation_policy import OPERATION_POLICY_REVISION


def _assert_audit_event_hash(event):
    details = event["details_json"]
    canonical = "|".join(str(value) for value in (
        event["id"], event["timestamp"], event["actor"], event["organization_id"],
        event["action"], event["object_type"], event["object_id"], event["result"],
        details, event["previous_event_hash"] or "",
    ))
    assert event["event_hash"] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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


def test_approval_atomically_creates_one_durable_execution_run(tmp_path):
    from app.core.db import DatabaseManager
    from app.core.correlation import reset_correlation_id, set_correlation_id

    database = DatabaseManager(tmp_path / "approval-run.db")
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    options = json.dumps({"provider": "aws", "output_format": "json-asff", "quiet": True}, separators=(",", ":"), sort_keys=True)
    budget = json.dumps({"timeout_seconds": 120, "max_output_bytes": 10485760}, separators=(",", ":"), sort_keys=True)
    account_budget = json.dumps({"read_only": 1}, separators=(",", ":"), sort_keys=True)
    credentials = json.dumps({"provider": "aws"}, separators=(",", ":"), sort_keys=True)
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)", ("org-a", "Org A", "org-a", now))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, active_probing_granted, created_at, updated_at) VALUES (?, ?, ?, 'CLOUD_ACCOUNT', ?, 1, ?, ?)", ("asset-a", "org-a", "asset", "aws://123456789012", now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, 'hash', 'ADMIN', ?, 1, ?)", ("admin-a", "admin", "admin@example.test", "org-a", now))
        conn.execute(
            "INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_options_json, operation_policy_revision, resource_budget_json, account_impact_budget_json, credential_scope_json, requested_by_user_id, state, created_at, expires_at) "
            "VALUES (?, ?, ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, ?, ?, ?, ?, 'admin-a', 'REQUESTED', ?, ?)",
            ("req-a", "idem-a", "f" * 64, options, OPERATION_POLICY_REVISION, budget, account_budget, credentials, now, expires),
        )

    token = set_correlation_id("corr-approval-run")
    try:
        result, decision_id, execution_id = database.approve_execution_request(
            "req-a", "org-a", "f" * 64, "approval-idem", "admin-a", "session-a", "worker-a",
        )
        assert result == "AUTHORIZED"
        assert decision_id
        assert execution_id.startswith("run-")
        replay = database.approve_execution_request(
            "req-a", "org-a", "f" * 64, "approval-idem", "admin-a", "session-a", "worker-a",
        )
    finally:
        reset_correlation_id(token)
    assert replay == ("REPLAY", decision_id, execution_id)
    with database._connection_scope() as conn:
        runs = conn.execute(
            "SELECT execution_id, request_id, organization_id, state, worker_identity, assurance_state, "
            "coverage_state, correlation_id FROM execution_runs WHERE request_id = ? AND organization_id = ?",
            ("req-a", "org-a"),
        ).fetchall()
        run_events = conn.execute(
            "SELECT action, object_type, organization_id, correlation_id, details_json FROM audit_events "
            "WHERE object_type = 'execution_run' AND organization_id = ?",
            ("org-a",),
        ).fetchall()
    assert len(runs) == 1
    assert runs[0]["request_id"] == "req-a"
    assert runs[0]["state"] == "REQUESTED"
    assert runs[0]["worker_identity"] == "worker-a"
    assert runs[0]["assurance_state"] == "UNVERIFIED"
    assert runs[0]["coverage_state"] == "UNAVAILABLE"
    assert runs[0]["correlation_id"] == "corr-approval-run"
    assert len(run_events) == 1
    assert run_events[0]["action"] == AuditAction.EXECUTION_RUN_CREATED.value
    assert run_events[0]["object_type"] == "execution_run"
    assert run_events[0]["correlation_id"] == "corr-approval-run"


def test_approval_requires_correlation_before_any_authority_mutation(tmp_path):
    from app.core.db import DatabaseManager

    database = DatabaseManager(tmp_path / "missing-correlation.db")
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    options = json.dumps({"provider": "aws", "output_format": "json-asff", "quiet": True}, separators=(",", ":"), sort_keys=True)
    budget = json.dumps({"timeout_seconds": 120, "max_output_bytes": 10485760}, separators=(",", ":"), sort_keys=True)
    account_budget = json.dumps({"read_only": 1}, separators=(",", ":"), sort_keys=True)
    credentials = json.dumps({"provider": "aws"}, separators=(",", ":"), sort_keys=True)
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)", ("org-a", "Org A", "org-a", now))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, active_probing_granted, created_at, updated_at) VALUES (?, ?, ?, 'CLOUD_ACCOUNT', ?, 1, ?, ?)", ("asset-a", "org-a", "asset", "aws://123456789012", now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, 'hash', 'ADMIN', ?, 1, ?)", ("admin-a", "admin", "admin@example.test", "org-a", now))
        conn.execute(
            "INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_options_json, operation_policy_revision, resource_budget_json, account_impact_budget_json, credential_scope_json, requested_by_user_id, state, created_at, expires_at) VALUES (?, ?, ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, ?, ?, ?, ?, 'admin-a', 'REQUESTED', ?, ?)",
            ("req-a", "idem-a", "f" * 64, options, OPERATION_POLICY_REVISION, budget, account_budget, credentials, now, expires),
        )
    assert database.approve_execution_request(
        "req-a", "org-a", "f" * 64, "approval-idem", "admin-a", "session-a", "worker-a",
    ) == ("CORRELATION_REQUIRED", None, None)
    with database._connection_scope() as conn:
        request = conn.execute("SELECT state, approved_decision_id FROM execution_requests WHERE id = ?", ("req-a",)).fetchone()
        decisions = conn.execute("SELECT COUNT(*) AS count FROM execution_decisions WHERE organization_id = ?", ("org-a",)).fetchone()
        runs = conn.execute("SELECT COUNT(*) AS count FROM execution_runs WHERE organization_id = ?", ("org-a",)).fetchone()
        events = conn.execute(
            "SELECT id, timestamp, action, object_type, object_id, result, actor, organization_id, "
            "details_json, correlation_id, previous_event_hash, event_hash, sequence_number "
            "FROM audit_events WHERE object_id = ?",
            ("req-a",),
        ).fetchall()
    assert request["state"] == "REQUESTED"
    assert request["approved_decision_id"] is None
    assert decisions["count"] == 0
    assert runs["count"] == 0
    assert len(events) == 1
    assert events[0]["action"] == AuditAction.EXECUTION_AUTHORITY_INVARIANT_FAILED.value
    assert events[0]["result"] == "FAILURE"
    assert events[0]["actor"] == "system"
    assert events[0]["organization_id"] == "org-a"
    assert events[0]["object_type"] == "execution_request"
    assert events[0]["object_id"] == "req-a"
    assert events[0]["sequence_number"] == 1
    assert events[0]["previous_event_hash"] is None
    assert events[0]["event_hash"]
    _assert_audit_event_hash(events[0])
    assert json.loads(events[0]["details_json"]) == {"reason_code": "CORRELATION_REQUIRED"}
    assert events[0]["correlation_id"].startswith("corr-")


def test_authorized_request_without_run_fails_closed_at_api_observation_boundary(monkeypatch):
    import asyncio
    from fastapi import HTTPException
    from app.api import executions
    from app.core.models import ExecutionRequestRecord

    request = ExecutionRequestRecord(
        id="req-orphan", idempotency_key="idem", request_fingerprint="f" * 64,
        organization_id="org-a", asset_id="asset-a", target_id="target-a",
        authorization_decision_id="auth-a", target_policy_version="v1", tool_id="nmap",
        operation_family="safe", operation_policy_revision=OPERATION_POLICY_REVISION,
        requested_by_user_id="admin-a", state="AUTHORIZED",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5), approved_decision_id="decision-a",
    )

    class InconsistentStore:
        def get_execution_request(self, request_id, organization_id=None):
            return request if request_id == request.id and organization_id == request.organization_id else None

        def get_execution_run_for_request(self, request_id, organization_id):
            return None

    original = executions.db_manager
    executions.db_manager = InconsistentStore()
    try:
        user = UserProfile(id="admin-a", username="admin", email="admin@example.test", role=UserRole.ADMIN, organization_id="org-a")
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(executions.get_execution_request("req-orphan", user))
    finally:
        executions.db_manager = original
    assert exc_info.value.status_code == 409


def test_api_approval_maps_missing_correlation_to_sanitized_503(monkeypatch):
    import asyncio
    from fastapi import HTTPException
    from app.api import executions

    class CorrelationUnavailableStore:
        def approve_execution_request(self, *args, **kwargs):
            return "CORRELATION_REQUIRED", None, None

    original_store = executions.db_manager
    original_session = executions._session_jti
    executions.db_manager = CorrelationUnavailableStore()
    executions._session_jti = lambda authorization, current_user: "session-a"
    try:
        user = UserProfile(id="admin-a", username="admin", email="admin@example.test", role=UserRole.ADMIN, organization_id="org-a")
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(executions.approve_execution_request(
                "req-a",
                executions.ApprovalPayload(request_fingerprint="f" * 64, confirm_owned_target=True),
                authorization="Bearer token",
                idempotency_key="approval-idem",
                current_user=user,
            ))
    finally:
        executions.db_manager = original_store
        executions._session_jti = original_session
    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Execution observability context is unavailable; approval was not applied."


@pytest.mark.asyncio
async def test_http_api_approval_returns_503_and_correlation_header(monkeypatch):
    import httpx
    from app.main import app
    from app.core.models import PrincipalType
    from app.core.auth import create_access_token

    class CorrelationUnavailableStore:
        def approve_execution_request(self, *args, **kwargs):
            return "CORRELATION_REQUIRED", None, None

    user = UserProfile(
        id="admin-a", username="admin", email="admin@example.test", role=UserRole.ADMIN,
        organization_id="org-a", principal_type=PrincipalType.SYSTEM_PRINCIPAL, scopes=["*"],
    )
    from app.api import executions
    original_store = executions.db_manager
    original_session = executions._session_jti
    original_overrides = dict(app.dependency_overrides)
    executions.db_manager = CorrelationUnavailableStore()
    executions._session_jti = lambda authorization, current_user: "session-a"
    for route in app.routes:
        if getattr(route, "path", "") == "/api/system/executions/{request_id}/approve":
            for dependency in route.dependant.dependencies:
                app.dependency_overrides[dependency.call] = lambda: user
    try:
        token = create_access_token(user)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/api/system/executions/req-a/approve",
                headers={"Authorization": f"Bearer {token}", "Idempotency-Key": "approval-idem"},
                json={"request_fingerprint": "f" * 64, "confirm_owned_target": True},
            )
    finally:
        executions.db_manager = original_store
        executions._session_jti = original_session
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original_overrides)
    assert response.status_code == 503
    assert response.json()["detail"] == "Execution observability context is unavailable; approval was not applied."
    assert response.headers["x-correlation-id"].startswith("corr-")


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


def test_revoke_fails_closed_on_missing_linked_decision(tmp_path):
    from app.core.db import DatabaseManager
    from app.core.correlation import reset_correlation_id, set_correlation_id

    database = DatabaseManager(tmp_path / "missing-decision.db")
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at) VALUES ('org-a', 'Org A', 'missing-decision-org', ?)", (now,))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) VALUES ('asset-a', 'org-a', 'asset', 'CLOUD_ACCOUNT', 'aws://123456789012', ?, ?)", (now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, created_at) VALUES ('user-a', 'user-a', 'missing@example.test', 'hash', 'ADMIN', 'org-a', ?)", (now,))
        conn.execute("""
            INSERT INTO execution_requests (
                id, idempotency_key, request_fingerprint, organization_id,
                asset_id, target_id, authorization_decision_id, target_policy_version,
                tool_id, operation_family, operation_policy_revision,
                requested_by_user_id, state, created_at, expires_at, approved_decision_id
            ) VALUES ('req-a', 'idem-a', ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1',
                      'prowler', 'cloud_audit', ?, 'user-a', 'AUTHORIZED', ?, ?, 'missing-decision')
        """, ("f" * 64, OPERATION_POLICY_REVISION, now, expires))

    correlation_token = set_correlation_id("corr-missing-decision")
    try:
        with pytest.raises(ValueError, match="invalid approved decision"):
            database.revoke_execution_request("req-a", "org-a", "admin")
    finally:
        reset_correlation_id(correlation_token)
    request = database.get_execution_request("req-a", organization_id="org-a")
    assert request is not None and request.state == "AUTHORIZED"
    with database._connection_scope() as conn:
        events = conn.execute(
            "SELECT id, timestamp, action, object_type, object_id, result, actor, organization_id, correlation_id, "
            "details_json, previous_event_hash, event_hash, sequence_number "
            "FROM audit_events WHERE object_id = ? ORDER BY timestamp",
            ("req-a",),
        ).fetchall()
    assert len(events) == 1
    assert events[0]["action"] == AuditAction.EXECUTION_AUTHORITY_INVARIANT_FAILED.value
    assert events[0]["object_type"] == "execution_request"
    assert events[0]["result"] == "FAILURE"
    assert events[0]["actor"] == "admin"
    assert events[0]["organization_id"] == "org-a"
    assert events[0]["correlation_id"] == "corr-missing-decision"
    assert events[0]["event_hash"]
    assert events[0]["previous_event_hash"] is None
    assert events[0]["sequence_number"] == 1
    _assert_audit_event_hash(events[0])
    assert "APPROVED_DECISION_REFERENCE_MISSING" in events[0]["details_json"]
    with database._connection_scope() as conn:
        reference = conn.execute(
            "SELECT approved_decision_id FROM execution_requests WHERE id = ? AND organization_id = ?",
            ("req-a", "org-a"),
        ).fetchone()
        decision = conn.execute(
            "SELECT id FROM execution_decisions WHERE id = ? AND organization_id = ?",
            ("missing-decision", "org-a"),
        ).fetchone()
    assert reference["approved_decision_id"] == "missing-decision"
    assert decision is None


def test_revoke_does_not_disclose_same_decision_id_owned_by_other_tenant(tmp_path):
    from app.core.db import DatabaseManager

    database = DatabaseManager(tmp_path / "cross-tenant-decision.db")
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    with database._connection_scope() as conn:
        for org, suffix in (("org-a", "a"), ("org-b", "b")):
            conn.execute(
                "INSERT INTO organizations (id, name, slug, created_at) VALUES (?, ?, ?, ?)",
                (org, f"Org {suffix.upper()}", f"org-{suffix}", now),
            )
            conn.execute(
                "INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) "
                "VALUES (?, ?, ?, 'DOMAIN', ?, ?, ?)",
                (f"asset-{suffix}", org, "asset", "example.invalid", now, now),
            )
            conn.execute(
                "INSERT INTO users (id, username, email, hashed_password, role, organization_id, created_at) "
                "VALUES (?, ?, ?, 'hash', 'ADMIN', ?, ?)",
                (f"user-{suffix}", f"user-{suffix}", f"{suffix}@example.invalid", org, now),
            )
        conn.execute(
            "INSERT INTO execution_decisions (id, organization_id, project_id, asset_id, target_id, "
            "authorization_decision_id, target_policy_version, tool_id, operation_family, "
            "operation_policy_revision, approval_state, approver_user_id, session_jti, worker_identity, "
            "created_at, expires_at) VALUES (?, ?, NULL, ?, ?, ?, 'v1', 'nmap', 'safe', ?, 'APPROVED', "
            "'user-b', 'session-b', 'worker-b', ?, ?)",
            ("shared-id", "org-b", "asset-b", "target-b", "auth-b", OPERATION_POLICY_REVISION, now, expires),
        )
        conn.execute(
            "INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, "
            "asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, "
            "operation_policy_revision, requested_by_user_id, state, created_at, expires_at, approved_decision_id) "
            "VALUES (?, ?, ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1', 'nmap', 'safe', ?, 'user-a', "
            "'AUTHORIZED', ?, ?, ?)",
            ("req-a", "idem-a", "f" * 64, OPERATION_POLICY_REVISION, now, expires, "shared-id"),
        )

    from app.core.correlation import reset_correlation_id, set_correlation_id
    correlation_token = set_correlation_id("corr-cross-tenant")
    try:
        with pytest.raises(ValueError, match="invalid approved decision"):
            database.revoke_execution_request("req-a", "org-a", "admin")
    finally:
        reset_correlation_id(correlation_token)
    with database._connection_scope() as conn:
        request = conn.execute(
            "SELECT state, approved_decision_id FROM execution_requests WHERE id = ? AND organization_id = ?",
            ("req-a", "org-a"),
        ).fetchone()
        events = conn.execute(
            "SELECT organization_id, actor, action, object_type, result, correlation_id, details_json, "
            "previous_event_hash, event_hash, sequence_number FROM audit_events WHERE object_id = ?",
            ("req-a",),
        ).fetchall()
    assert request["state"] == "AUTHORIZED"
    assert request["approved_decision_id"] == "shared-id"
    assert len(events) == 1
    assert events[0]["organization_id"] == "org-a"
    assert events[0]["actor"] == "admin"
    assert events[0]["action"] == AuditAction.EXECUTION_AUTHORITY_INVARIANT_FAILED.value
    assert events[0]["object_type"] == "execution_request"
    assert events[0]["result"] == "FAILURE"
    assert events[0]["correlation_id"] == "corr-cross-tenant"
    assert events[0]["event_hash"]
    assert events[0]["previous_event_hash"] is None
    assert events[0]["sequence_number"] == 1
    with database._connection_scope() as conn:
        event = conn.execute(
            "SELECT id, timestamp, action, object_type, object_id, result, actor, organization_id, "
            "details_json, previous_event_hash, event_hash FROM audit_events WHERE object_id = ?",
            ("req-a",),
        ).fetchone()
    _assert_audit_event_hash(event)
    assert json.loads(events[0]["details_json"]) == {"reason_code": "APPROVED_DECISION_REFERENCE_MISSING"}
    assert "shared-id" not in events[0]["details_json"]


def test_audit_chain_continuity_is_verified_for_multiple_events(tmp_path):
    from app.core.db import DatabaseManager

    database = DatabaseManager(tmp_path / "audit-chain.db")
    database.record_audit_event(AuditEvent(
        id="audit-chain-one", actor="admin", organization_id="org-chain",
        action=AuditAction.EXECUTION_REQUESTED, object_type="execution_request",
        object_id="request-chain", result="SUCCESS", details={"step": 1},
        correlation_id="corr-chain",
    ))
    database.record_audit_event(AuditEvent(
        id="audit-chain-two", actor="admin", organization_id="org-chain",
        action=AuditAction.EXECUTION_CANCEL_REQUESTED, object_type="execution_request",
        object_id="request-chain", result="SUCCESS", details={"step": 2},
        correlation_id="corr-chain",
    ))

    with database._connection_scope() as conn:
        events = conn.execute(
            "SELECT id, timestamp, action, object_type, object_id, result, actor, organization_id, "
            "details_json, previous_event_hash, event_hash, sequence_number "
            "FROM audit_events ORDER BY sequence_number",
        ).fetchall()
    assert len(events) == 2
    for event in events:
        _assert_audit_event_hash(event)
    assert events[0]["sequence_number"] == 1
    assert events[0]["previous_event_hash"] is None
    assert events[1]["sequence_number"] == 2
    assert events[1]["previous_event_hash"] == events[0]["event_hash"]
    assert database.verify_audit_log_integrity() == (True, None)


def test_audit_chain_detects_details_json_tampering(tmp_path):
    from app.core.db import DatabaseManager

    database = DatabaseManager(tmp_path / "audit-tamper.db")
    database.record_audit_event(AuditEvent(
        id="audit-tamper-one", actor="admin", organization_id="org-tamper",
        action=AuditAction.EXECUTION_REQUESTED, object_type="execution_request",
        object_id="request-tamper", result="SUCCESS", details={"step": 1},
        correlation_id="corr-tamper",
    ))
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE audit_events SET details_json = ? WHERE id = ?",
            ('{ "step": 1 }', "audit-tamper-one"),
        )
    assert database.verify_audit_log_integrity() == (False, "audit-tamper-one")


def test_execution_run_rejects_cross_tenant_request_and_invalid_transitions(tmp_path):
    from app.core.db import DatabaseManager
    from app.core.models import ExecutionRunRecord

    database = DatabaseManager(tmp_path / "runs.db")
    now = datetime.now(timezone.utc).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)", ("org-a", "Org A", "org-a", now))
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)", ("org-b", "Org B", "org-b", now))
        for org in ("org-a", "org-b"):
            conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) VALUES (?, ?, ?, 'CLOUD_ACCOUNT', ?, ?, ?)", (f"asset-{org[-1]}", org, "account", "aws://123456789012", now, now))
            conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, 'hash', 'ADMIN', ?, 1, ?)", (f"user-{org[-1]}", f"user-{org[-1]}", f"{org}@example.test", org, now))
        conn.execute("INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, requested_by_user_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", ("req-b", "idem-b", "f" * 64, "org-b", "asset-b", "target-b", "auth-b", "v1", "prowler", "cloud_audit", OPERATION_POLICY_REVISION, "user-b", now, now))
    run = ExecutionRunRecord(execution_id="run-a", request_id="req-b", organization_id="org-a")
    with pytest.raises(ValueError, match="tenant-bound"):
        database.create_execution_run(run)


def test_execution_run_transition_matrix_and_terminal_immutability(tmp_path):
    from app.core.db import DatabaseManager
    from app.core.models import ExecutionRunRecord

    database = DatabaseManager(tmp_path / "run-state.db")
    now = datetime.now(timezone.utc).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)", ("org-a", "Org A", "org-a", now))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) VALUES ('asset-a', 'org-a', 'account', 'CLOUD_ACCOUNT', 'aws://123456789012', ?, ?)", (now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES ('user-a', 'user-a', 'a@example.test', 'hash', 'ADMIN', 'org-a', 1, ?)", (now,))
        conn.execute("INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, requested_by_user_id, state, created_at, expires_at, approved_decision_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'AUTHORIZED', ?, ?, ?)", ("req-a", "idem-a", "f" * 64, "org-a", "asset-a", "target-a", "auth-a", "v1", "prowler", "cloud_audit", OPERATION_POLICY_REVISION, "user-a", now, (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(), "decision-a"))
        conn.execute("INSERT INTO execution_decisions (id, organization_id, project_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, approval_state, approver_user_id, session_jti, worker_identity, created_at, expires_at) VALUES ('decision-a', 'org-a', NULL, 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, 'APPROVED', 'user-a', 'session-a', 'worker-a', ?, ?)", (OPERATION_POLICY_REVISION, now, (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()))
    database.create_execution_run(ExecutionRunRecord(execution_id="run-a", request_id="req-a", organization_id="org-a"))
    assert not database.transition_execution_run("run-a", "org-a", "REQUESTED", "SUCCEEDED")
    assert database.transition_execution_run("run-a", "org-a", "REQUESTED", "STARTING")
    assert database.transition_execution_run("run-a", "org-a", "STARTING", "RUNNING")
    assert database.transition_execution_run("run-a", "org-a", "RUNNING", "SUCCEEDED")
    assert not database.transition_execution_run("run-a", "org-a", "SUCCEEDED", "RUNNING")


def test_execution_run_rejects_request_decision_authority_mismatch(tmp_path):
    from app.core.db import DatabaseManager
    from app.core.models import ExecutionRunRecord

    database = DatabaseManager(tmp_path / "authority-binding.db")
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES ('org-a', 'Org A', 'org-a', ?, 1)", (now,))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) VALUES ('asset-a', 'org-a', 'account', 'CLOUD_ACCOUNT', 'aws://123456789012', ?, ?)", (now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES ('user-a', 'user-a', 'a@example.test', 'hash', 'ADMIN', 'org-a', 1, ?)", (now,))
        conn.execute("INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, requested_by_user_id, state, created_at, expires_at, approved_decision_id) VALUES ('req-a', 'idem-a', ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, 'user-a', 'AUTHORIZED', ?, ?, 'decision-a')", ("f" * 64, OPERATION_POLICY_REVISION, now, expires))
        conn.execute("INSERT INTO execution_decisions (id, organization_id, project_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, approval_state, approver_user_id, session_jti, worker_identity, created_at, expires_at) VALUES ('decision-a', 'org-a', NULL, 'asset-a', 'target-other', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, 'APPROVED', 'user-a', 'session-a', 'worker-a', ?, ?)", (OPERATION_POLICY_REVISION, now, expires))

    with pytest.raises(ValueError, match="authority binding"):
        database.create_execution_run(ExecutionRunRecord(execution_id="run-a", request_id="req-a", organization_id="org-a"))


def test_execution_run_is_unique_per_authorized_request(tmp_path):
    from app.core.db import DatabaseManager
    from app.core.models import ExecutionRunRecord

    database = DatabaseManager(tmp_path / "run-uniqueness.db")
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES ('org-a', 'Org A', 'org-a', ?, 1)", (now,))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) VALUES ('asset-a', 'org-a', 'account', 'CLOUD_ACCOUNT', 'aws://123456789012', ?, ?)", (now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES ('user-a', 'user-a', 'a@example.test', 'hash', 'ADMIN', 'org-a', 1, ?)", (now,))
        conn.execute("INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, requested_by_user_id, state, created_at, expires_at, approved_decision_id) VALUES ('req-a', 'idem-a', ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, 'user-a', 'AUTHORIZED', ?, ?, 'decision-a')", ("f" * 64, OPERATION_POLICY_REVISION, now, expires))
        conn.execute("INSERT INTO execution_decisions (id, organization_id, project_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, approval_state, approver_user_id, session_jti, worker_identity, created_at, expires_at) VALUES ('decision-a', 'org-a', NULL, 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, 'APPROVED', 'user-a', 'session-a', 'worker-a', ?, ?)", (OPERATION_POLICY_REVISION, now, expires))
    database.create_execution_run(ExecutionRunRecord(execution_id="run-a", request_id="req-a", organization_id="org-a"))

    with pytest.raises(Exception):
        database.create_execution_run(ExecutionRunRecord(execution_id="run-b", request_id="req-a", organization_id="org-a"))


def test_postgres_execution_run_validation_locks_request_row(monkeypatch):
    from app.core.db import PostgresDatabaseManager

    class Connection:
        def __init__(self):
            self.queries = []

        def execute(self, sql, params=()):
            self.queries.append(sql)
            return self

        def fetchone(self):
            return None

    connection = Connection()

    class Scope:
        def __enter__(self):
            return connection

        def __exit__(self, *_):
            return False

    manager = object.__new__(PostgresDatabaseManager)
    monkeypatch.setattr(manager, "_connection_scope", lambda: Scope())
    with pytest.raises(ValueError, match="not tenant-bound"):
        manager.create_execution_run(ExecutionRunRecord(execution_id="run-lock", request_id="req-lock", organization_id="org-lock"))
    assert "FOR UPDATE" in connection.queries[0]


def test_legacy_execution_runs_schema_is_rebuilt_with_tenant_fk(tmp_path):
    import sqlite3
    from app.core.db import DatabaseManager

    db_path = tmp_path / "legacy-runs.db"
    database = DatabaseManager(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES ('org-a', 'Org A', 'org-a', ?, 1)", (now,))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) VALUES ('asset-a', 'org-a', 'account', 'CLOUD_ACCOUNT', 'aws://123456789012', ?, ?)", (now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES ('user-a', 'user-a', 'a@example.test', 'hash', 'ADMIN', 'org-a', 1, ?)", (now,))
        conn.execute("INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, requested_by_user_id, state, created_at, expires_at) VALUES ('req-a', 'idem-a', ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, 'user-a', 'REQUESTED', ?, ?)", ("f" * 64, OPERATION_POLICY_REVISION, now, now))
        conn.execute("DELETE FROM schema_migrations WHERE version = 1")
        conn.execute("DROP INDEX uq_execution_runs_request")
        conn.execute("ALTER TABLE execution_runs RENAME TO execution_runs_legacy")
        conn.execute("""CREATE TABLE execution_runs (execution_id TEXT PRIMARY KEY, request_id TEXT NOT NULL, organization_id TEXT NOT NULL, state TEXT NOT NULL, worker_identity TEXT, process_id INTEGER, process_group_id TEXT, assurance_state TEXT NOT NULL, coverage_state TEXT NOT NULL, reason_code TEXT, evidence_ref TEXT, correlation_id TEXT, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT, FOREIGN KEY (request_id) REFERENCES execution_requests(id), FOREIGN KEY (organization_id) REFERENCES organizations(id))""")
        conn.execute("INSERT INTO execution_runs SELECT * FROM execution_runs_legacy WHERE 0")
        conn.execute("DROP TABLE execution_runs_legacy")
    DatabaseManager(db_path)
    with sqlite3.connect(db_path) as conn:
        foreign_keys = conn.execute("PRAGMA foreign_key_list(execution_runs)").fetchall()
        composite = [row for row in foreign_keys if row[2] == "execution_requests"]
        assert {(row[1], row[3], row[4]) for row in composite} == {
            (0, "request_id", "id"), (1, "organization_id", "organization_id")
        }
        assert len({row[0] for row in composite}) == 1
        parent_unique = []
        for index in conn.execute("PRAGMA index_list(execution_requests)").fetchall():
            if index[2]:
                columns = conn.execute(f"PRAGMA index_info('{index[1].replace(chr(39), chr(39) + chr(39))}')").fetchall()
                parent_unique.append([column[2] for column in sorted(columns, key=lambda value: value[0])])
        assert ["id", "organization_id"] in parent_unique
        assert conn.execute("SELECT version FROM schema_migrations WHERE version = 1").fetchone()
        assert conn.execute("SELECT version FROM schema_migrations WHERE version = 2").fetchone()


def test_legacy_execution_runs_duplicate_preflight_fails_closed(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "legacy-duplicate-runs.db"
    database = DatabaseManager(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES ('org-a', 'Org A', 'org-a', ?, 1)", (now,))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) VALUES ('asset-a', 'org-a', 'account', 'CLOUD_ACCOUNT', 'aws://123456789012', ?, ?)", (now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES ('user-a', 'user-a', 'a@example.test', 'hash', 'ADMIN', 'org-a', 1, ?)", (now,))
        conn.execute("INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, requested_by_user_id, state, created_at, expires_at) VALUES ('req-a', 'idem-a', ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, 'user-a', 'REQUESTED', ?, ?)", ("f" * 64, OPERATION_POLICY_REVISION, now, now))
        conn.execute("DELETE FROM schema_migrations WHERE version = 1")
        conn.execute("DROP INDEX uq_execution_runs_request")
        conn.execute("INSERT INTO execution_runs (execution_id, request_id, organization_id, state, assurance_state, coverage_state, created_at) VALUES ('run-a', 'req-a', 'org-a', 'FAILED', 'UNVERIFIED', 'UNAVAILABLE', ?), ('run-b', 'req-a', 'org-a', 'FAILED', 'UNVERIFIED', 'UNAVAILABLE', ?)", (now, now))
    with pytest.raises(ValueError, match="duplicate runs"):
        DatabaseManager(db_path)


def test_execution_migration_version_two_reruns_without_reconciling_fresh_schema(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "version-two-rerun.db"
    database = DatabaseManager(db_path)
    with database._connection_scope() as conn:
        conn.execute("DELETE FROM schema_migrations WHERE version = 2")
    DatabaseManager(db_path)
    with database._connection_scope() as conn:
        versions = [row["version"] for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()]
        assert versions[-2:] == [1, 2]


def test_execution_schema_drift_after_version_two_fails_closed(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "version-two-drift.db"
    database = DatabaseManager(db_path)
    with database._connection_scope() as conn:
        conn.execute("DROP INDEX uq_execution_runs_request")
    with pytest.raises(ValueError, match="schema health check"):
        DatabaseManager(db_path)


def test_execution_schema_wrong_column_index_fails_closed(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "wrong-run-index.db"
    database = DatabaseManager(db_path)
    with database._connection_scope() as conn:
        conn.execute("DROP INDEX uq_execution_runs_request")
        conn.execute("CREATE UNIQUE INDEX uq_execution_runs_request ON execution_runs(execution_id)")
    with pytest.raises(ValueError, match="schema health check"):
        DatabaseManager(db_path)


def test_execution_schema_partial_index_fails_closed(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "partial-run-index.db"
    database = DatabaseManager(db_path)
    with database._connection_scope() as conn:
        conn.execute("DROP INDEX uq_execution_runs_request")
        conn.execute("CREATE UNIQUE INDEX uq_execution_runs_request ON execution_runs(request_id, organization_id) WHERE state = 'SUCCEEDED'")
    with pytest.raises(ValueError, match="schema health check"):
        DatabaseManager(db_path)
