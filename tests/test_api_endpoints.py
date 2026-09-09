"""
Integration test suite for FastAPI REST endpoints and SSE streaming (v10.0.0).
"""

import asyncio
from contextlib import contextmanager
import json
from unittest.mock import AsyncMock, patch
import pytest
from httpx import AsyncClient, ASGITransport
from pydantic import ValidationError

from app.main import app
from app.api.scans import StartScanRequest
from app.core.version import APP_VERSION
from app.core.models import (
    TargetType,
    ScanProfile,
    ScanStatus,
    ScanJob,
    Target,
    Severity,
    AuthType,
    AuthConfig,
    CrawlerConfig,
    DiscoveredEndpoint,
    EndpointTestRecord,
    EndpointTestStatus,
    UserProfile,
    UserRole,
    PrincipalType,
    LogLevel,
    Finding,
    Evidence,
    RejectedDiscovery,
    SystemCapabilities,
    ScanAuthorizationManifest,
    sanitize_sensitive_data,
    calculate_fingerprint,
)
from app.core.auth import create_access_token, revoke_token
from app.core.storage import save_scan
from app.core.db import db_manager
from app.core.orchestrator import orchestrator
from starlette.requests import Request


@pytest.fixture
def auth_headers():
    from app.core.models import PrincipalType
    user = UserProfile(
        id="usr-api-system-admin",
        username="admin",
        email="admin@sec.local",
        role=UserRole.ADMIN,
        principal_type=PrincipalType.SYSTEM_PRINCIPAL,
        scopes=["*"],
    )
    token = create_access_token(user)
    with db_manager._connection_scope() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)",
            ("org-default", "Test Organization", "test-organization", "2026-09-05T00:00:00+00:00"),
        )
        conn.execute(
            "INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at, principal_type) "
            "VALUES (?, ?, ?, ?, 'ADMIN', ?, 1, ?, 'SYSTEM_PRINCIPAL') "
            "ON CONFLICT(id) DO UPDATE SET role=excluded.role, organization_id=excluded.organization_id, "
            "is_active=1, principal_type=excluded.principal_type",
            (user.id, user.username, user.email, "test-hash", "org-default", "2026-09-05T00:00:00+00:00"),
        )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_system_endpoints(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Health check
        resp = await ac.get("/api/system/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "HEALTHY"
        assert data["version"] == APP_VERSION
        assert "uptime_seconds" in data
        assert "storage" in data
        assert data["storage"]["status"] == "OK"
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["x-frame-options"] == "DENY"
        assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"
        assert "default-src 'self'" in resp.headers["content-security-policy"]

        # 2. Engines catalog
        assert (await ac.get("/api/system/engines")).status_code == 401
        resp_eng = await ac.get("/api/system/engines", headers=auth_headers)
        assert resp_eng.status_code == 200
        data_eng = resp_eng.json()
        assert data_eng["count"] == 5


@pytest.mark.asyncio
async def test_capabilities_endpoint_requires_auth_and_supports_forced_refresh(auth_headers):
    live_snapshot = SystemCapabilities(tools=[])
    with patch("app.adapters.get_cached_system_capabilities", new_callable=AsyncMock, return_value=live_snapshot) as detector:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            assert (await ac.get("/api/system/capabilities")).status_code == 401
            response = await ac.get("/api/system/capabilities?refresh=true", headers=auth_headers)
        assert response.status_code == 200
        detector.assert_awaited_once_with(force_refresh=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_key", [None, "", " leading", "bad/key", "a" * 129])
async def test_scan_creation_requires_an_exact_idempotency_key(auth_headers, invalid_key):
    headers = dict(auth_headers)
    if invalid_key is not None:
        headers["Idempotency-Key"] = invalid_key
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post(
            "/api/scans/start",
            json={"target_type": "DOMAIN", "target_value": "example.com"},
            headers=headers,
        )
    assert response.status_code == 422
    assert "Idempotency-Key" in response.json()["detail"]


@pytest.mark.parametrize(
    "payload",
    [
        {"target_type": TargetType.DOMAIN, "target_value": ""},
        {"target_type": TargetType.DOMAIN, "target_value": "x" * 1025},
        {"target_type": TargetType.DOMAIN, "target_value": "example.com", "target_name": ""},
        {"target_type": TargetType.DOMAIN, "target_value": "example.com", "target_name": "x" * 121},
    ],
)
def test_scan_creation_enforces_target_field_bounds(payload):
    with pytest.raises(ValidationError):
        StartScanRequest(**payload)


@pytest.mark.asyncio
async def test_scan_creation_idempotency_key_is_tenant_scoped(auth_headers):
    organization_id = "org-idempotency-isolation"
    user_id = "user-idempotency-isolation"
    with db_manager._connection_scope() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)",
            (organization_id, "Idempotency Isolation", "idempotency-isolation", "2026-09-05T00:00:00+00:00"),
        )
        conn.execute(
            "INSERT OR IGNORE INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) "
            "VALUES (?, ?, ?, ?, 'ADMIN', ?, 1, ?)",
            (user_id, "idempotency-isolation-admin", "idempotency-isolation@example.test", "test-hash", organization_id, "2026-09-05T00:00:00+00:00"),
        )
    tenant_user = UserProfile(
        id=user_id,
        username="idempotency-isolation-admin",
        email="idempotency-isolation@example.test",
        role=UserRole.ADMIN,
        principal_type=PrincipalType.TENANT_PRINCIPAL,
        organization_id=organization_id,
    )
    tenant_headers = {"Authorization": f"Bearer {create_access_token(tenant_user)}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        first_asset = await ac.post(
            "/api/assets",
            json={"name": "Idempotency tenant A", "type": "DOMAIN", "target_value": "example.com"},
            headers=auth_headers,
        )
        second_asset = await ac.post(
            "/api/assets",
            json={"name": "Idempotency tenant B", "type": "DOMAIN", "target_value": "example.com"},
            headers=tenant_headers,
        )
        assert first_asset.status_code == 201, first_asset.text
        assert second_asset.status_code == 201, second_asset.text

        first_request = await ac.post(
            "/api/scans/start",
            json={
                "target_type": "DOMAIN",
                "target_value": "example.com",
                "asset_id": first_asset.json()["id"],
                "enabled_engines": ["network"],
            },
            headers={**auth_headers, "Idempotency-Key": "shared-tenant-idempotency-key"},
        )
        second_request = await ac.post(
            "/api/scans/start",
            json={
                "target_type": "DOMAIN",
                "target_value": "example.com",
                "asset_id": second_asset.json()["id"],
                "enabled_engines": ["network"],
            },
            headers={**tenant_headers, "Idempotency-Key": "shared-tenant-idempotency-key"},
        )

    assert first_request.status_code == 201, first_request.text
    assert second_request.status_code == 201, second_request.text
    assert first_request.json().get("idempotent_replay") is not True
    assert second_request.json().get("idempotent_replay") is not True
    assert first_request.json()["scan_request_id"] != second_request.json()["scan_request_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper_kind", ["operation", "fleet"])
async def test_scan_approval_rejects_pre_approval_normalized_row_tampering(auth_headers, tamper_kind):
    approver_id = f"approval-tamper-{tamper_kind}"
    with db_manager._connection_scope() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) "
            "VALUES (?, ?, ?, ?, 'ADMIN', ?, 1, ?)",
            (approver_id, approver_id, f"{approver_id}@sec.local", "test-hash", "org-default", "2026-09-05T00:00:00+00:00"),
        )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        asset_response = await ac.post(
            "/api/assets",
            json={"name": f"Tamper {tamper_kind} asset", "type": "DOMAIN", "target_value": "example.com"},
            headers=auth_headers,
        )
        assert asset_response.status_code == 201, asset_response.text
        asset_id = asset_response.json()["id"]
        start_response = await ac.post(
            "/api/scans/start",
            json={
                "target_type": "DOMAIN",
                "target_value": "example.com",
                "asset_id": asset_id,
                "enabled_engines": ["network"],
            },
            headers={**auth_headers, "Idempotency-Key": f"tamper-{tamper_kind}"},
        )
    assert start_response.status_code == 201, start_response.text
    started = start_response.json()
    with db_manager._connection_scope() as conn:
        if tamper_kind == "operation":
            operation = conn.execute(
                "SELECT operation_id FROM scan_authorization_operations "
                "WHERE scan_request_id=? AND organization_id=? AND selection_state='SELECTED' "
                "ORDER BY operation_id LIMIT 1",
                (started["scan_request_id"], "org-default"),
            ).fetchone()
            assert operation
            conn.execute(
                "UPDATE scan_authorization_operations SET operation_options_json=? "
                "WHERE scan_request_id=? AND organization_id=? AND operation_id=?",
                ('{"tampered":true}', started["scan_request_id"], "org-default", operation["operation_id"]),
            )
        else:
            conn.execute(
                "UPDATE scan_authorization_fleet SET reason=? WHERE scan_request_id=? AND organization_id=? AND tool_id=?",
                ("tampered", started["scan_request_id"], "org-default", "nmap"),
            )

    with pytest.raises(RuntimeError, match="normalized|manifest"):
        db_manager.approve_scan_authorization_request(
            started["scan_request_id"], "org-default", started["manifest_hash"],
            f"approval-{tamper_kind}", approver_id, f"session-{tamper_kind}",
            f"worker-{tamper_kind}", f"generation-{tamper_kind}",
        )
    with db_manager._connection_scope() as conn:
        assert conn.execute(
            "SELECT state FROM scan_authorization_requests WHERE scan_request_id=? AND organization_id=?",
            (started["scan_request_id"], "org-default"),
        ).fetchone()["state"] == "REQUESTED"
        assert conn.execute(
            "SELECT COUNT(*) AS count FROM scan_authorization_operations "
            "WHERE scan_request_id=? AND organization_id=? AND child_request_id IS NOT NULL",
            (started["scan_request_id"], "org-default"),
        ).fetchone()["count"] == 0
        assert conn.execute(
            "SELECT COUNT(*) AS count FROM execution_requests "
            "WHERE organization_id=? AND idempotency_key LIKE ?",
            ("org-default", f"{started['scan_request_id']}:%"),
        ).fetchone()["count"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["owner", "lifecycle"])
async def test_scan_approval_rejects_post_creation_asset_authority_changes(auth_headers, mutation):
    approver_id = f"approval-asset-{mutation}"
    with db_manager._connection_scope() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) "
            "VALUES (?, ?, ?, ?, 'ADMIN', ?, 1, ?)",
            (approver_id, approver_id, f"{approver_id}@sec.local", "test-hash", "org-default", "2026-09-05T00:00:00+00:00"),
        )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        asset_response = await ac.post(
            "/api/assets",
            json={"name": f"Authority {mutation} asset", "type": "DOMAIN", "target_value": "example.com"},
            headers=auth_headers,
        )
        assert asset_response.status_code == 201, asset_response.text
        asset_id = asset_response.json()["id"]
        start_response = await ac.post(
            "/api/scans/start",
            json={
                "target_type": "DOMAIN", "target_value": "example.com",
                "asset_id": asset_id, "enabled_engines": ["network"],
            },
            headers={**auth_headers, "Idempotency-Key": f"asset-authority-{mutation}"},
        )
    assert start_response.status_code == 201, start_response.text
    started = start_response.json()
    with db_manager._connection_scope() as conn:
        if mutation == "owner":
            conn.execute("UPDATE assets SET owner=? WHERE id=? AND organization_id=?", ("changed-owner", asset_id, "org-default"))
        else:
            conn.execute("UPDATE assets SET lifecycle_status='ARCHIVED' WHERE id=? AND organization_id=?", (asset_id, "org-default"))

    expected = "owner binding" if mutation == "owner" else "lifecycle binding|eligible"
    with pytest.raises(RuntimeError, match=expected):
        db_manager.approve_scan_authorization_request(
            started["scan_request_id"], "org-default", started["manifest_hash"],
            f"approval-asset-{mutation}", approver_id, f"session-asset-{mutation}",
            f"worker-asset-{mutation}", f"generation-asset-{mutation}",
        )


@pytest.mark.asyncio
async def test_scan_approval_rolls_back_partial_child_authority_materialization(auth_headers, monkeypatch):
    approver_id = "approval-child-rollback"
    with db_manager._connection_scope() as conn:
        for user_id, role in (("usr-test-01", "ADMIN"), (approver_id, "ADMIN")):
            conn.execute(
                "INSERT OR IGNORE INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                (user_id, user_id, f"{user_id}@sec.local", "test-hash", role, "org-default", "2026-09-05T00:00:00+00:00"),
            )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        asset_response = await ac.post(
            "/api/assets",
            json={"name": "Child rollback asset", "type": "DOMAIN", "target_value": "example.com"},
            headers=auth_headers,
        )
        assert asset_response.status_code == 201, asset_response.text
        start_response = await ac.post(
            "/api/scans/start",
            json={
                "target_type": "DOMAIN",
                "target_value": "example.com",
                "asset_id": asset_response.json()["id"],
                "enabled_engines": ["network"],
            },
            headers={**auth_headers, "Idempotency-Key": "child-rollback-request"},
        )
    assert start_response.status_code == 201, start_response.text
    started = start_response.json()

    with db_manager._connection_scope() as conn:
        before_counts = {
            table: conn.execute(
                f"SELECT COUNT(*) AS count FROM {table} WHERE organization_id=?",
                ("org-default",),
            ).fetchone()["count"]
            for table in (
                "execution_requests", "execution_decisions", "execution_runs",
                "execution_dispatch_intents", "execution_process_ownership",
                "execution_recovery_state",
            )
        }
        before_operation_links = conn.execute(
            "SELECT COUNT(*) AS count FROM scan_authorization_operations "
            "WHERE scan_request_id=? AND organization_id=? AND child_request_id IS NOT NULL",
            (started["scan_request_id"], "org-default"),
        ).fetchone()["count"]

    original_scope = db_manager._connection_scope

    class FailingConnection:
        def __init__(self, connection):
            self._connection = connection

        def execute(self, sql, *args, **kwargs):
            if "INSERT INTO execution_decisions" in sql:
                raise RuntimeError("injected child decision materialization failure")
            return self._connection.execute(sql, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(self._connection, name)

    @contextmanager
    def failing_scope():
        with original_scope() as connection:
            yield FailingConnection(connection)

    monkeypatch.setattr(db_manager, "_connection_scope", failing_scope)
    with pytest.raises(RuntimeError, match="child decision materialization failure"):
        db_manager.approve_scan_authorization_request(
            started["scan_request_id"], "org-default", started["manifest_hash"],
            "approval-child-rollback-key", approver_id, "session-child-rollback",
            "worker-child-rollback", "generation-child-rollback",
        )

    with db_manager._connection_scope() as conn:
        assert dict(conn.execute(
            "SELECT state, approver_user_id, approval_session_jti FROM scan_authorization_requests "
            "WHERE scan_request_id=? AND organization_id=?",
            (started["scan_request_id"], "org-default"),
        ).fetchone()) == {
            "state": "REQUESTED",
            "approver_user_id": None,
            "approval_session_jti": None,
        }
        after_counts = {
            table: conn.execute(
                f"SELECT COUNT(*) AS count FROM {table} WHERE organization_id=?",
                ("org-default",),
            ).fetchone()["count"]
            for table in before_counts
        }
        assert after_counts == before_counts
        assert conn.execute(
            "SELECT COUNT(*) AS count FROM scan_authorization_operations "
            "WHERE scan_request_id=? AND organization_id=? AND child_request_id IS NOT NULL",
            (started["scan_request_id"], "org-default"),
        ).fetchone()["count"] == before_operation_links


@pytest.mark.asyncio
async def test_scan_correlation_id_propagates_to_request_telemetry_and_audit(auth_headers):
    """Contract 04: request correlation is retained before explicit dispatch."""
    correlation_id = "corr-contract-04"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        asset_response = await ac.post(
            "/api/assets",
            json={
                "name": "Correlation contract target",
                "type": "DOMAIN",
                "target_value": "example.com",
            },
            headers=auth_headers,
        )
        assert asset_response.status_code == 201, asset_response.text
        payload = {
            "target_type": "DOMAIN",
            "target_value": "example.com",
            "asset_id": asset_response.json()["id"],
            "profile": "QUICK",
            "enabled_engines": [],
        }
        response = await ac.post(
            "/api/scans/start",
            json=payload,
            headers={
                **auth_headers,
                "X-Correlation-ID": correlation_id,
                "Idempotency-Key": "correlation-contract-04",
            },
        )
        assert response.status_code == 201, response.text
        response_data = response.json()
        assert response_data["authorization_state"] == "REQUESTED"
        assert response_data["dispatch_state"] == "PENDING_APPROVAL"
        assert response_data["execution_started"] is False

        job = db_manager.get_scan_record(response_data["scan_id"], organization_id="org-default")
        assert job is not None
        assert job.correlation_id == correlation_id
        assert job.logs == []

        telemetry = await ac.get(f"/api/scans/{job.id}/telemetry", headers=auth_headers)
        assert telemetry.status_code == 200
        assert telemetry.json()["correlation_id"] == correlation_id

        audit_events, _ = db_manager.list_audit_events(organization_id=job.organization_id)
        scan_events = [
            event for event in audit_events
            if event.object_id == response_data["scan_request_id"]
        ]
        assert scan_events
        assert all(event.correlation_id == correlation_id for event in scan_events)


@pytest.mark.asyncio
async def test_scan_asset_binding_carries_explicit_intrusive_authorization(monkeypatch, auth_headers):
    captured = {}

    async def fake_start_scan(job):
        captured["job"] = job
        return asyncio.create_task(asyncio.sleep(0))

    monkeypatch.setattr(orchestrator, "start_scan", fake_start_scan)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        asset_response = await ac.post(
            "/api/assets",
            json={
                "name": "Authorized probe target",
                "type": "IP_ADDRESS",
                "target_value": "192.168.1.50",
                "active_probing_granted": True,
            },
            headers=auth_headers,
        )
        assert asset_response.status_code == 201, asset_response.text
        asset_id = asset_response.json()["id"]

        start_response = await ac.post(
            "/api/scans/start",
            json={
                "target_type": "IP",
                "target_value": "192.168.1.50",
                "asset_id": asset_id,
                "enabled_engines": [],
            },
            headers={**auth_headers, "Idempotency-Key": "scan-idempotency-1"},
        )
        assert start_response.status_code == 201
        response_data = start_response.json()
        assert response_data["authorization_state"] == "REQUESTED"
        assert response_data["status"] == "AUTHORIZATION_REQUIRED"
        assert response_data["execution_started"] is False
        scan_row = db_manager.get_scan_record(response_data["scan_id"], organization_id="org-default")
        assert scan_row is not None
        with db_manager._connection_scope() as conn:
            persisted = conn.execute("SELECT manifest_json, manifest_hash FROM scan_authorization_requests WHERE scan_request_id=? AND organization_id=?", (response_data["scan_request_id"], "org-default")).fetchone()
            assert persisted
            reconstructed = ScanAuthorizationManifest.model_validate(json.loads(persisted["manifest_json"]))
            assert reconstructed.manifest_hash == persisted["manifest_hash"] == response_data["manifest_hash"]
            assert conn.execute("SELECT COUNT(*) AS count FROM scan_authorization_fleet WHERE scan_request_id=? AND organization_id=?", (response_data["scan_request_id"], "org-default")).fetchone()["count"] == 26
        audit_events, _ = db_manager.list_audit_events(organization_id="org-default")
        assert any(event.object_id == response_data["scan_request_id"] for event in audit_events)

        replay = await ac.post(
            "/api/scans/start",
            json={
                "target_type": "IP", "target_value": "192.168.1.50",
                "asset_id": asset_id, "enabled_engines": [],
            },
            headers={**auth_headers, "Idempotency-Key": "scan-idempotency-1"},
        )
        assert replay.status_code == 201
        assert replay.json()["idempotent_replay"] is True
        assert replay.json()["scan_id"] == response_data["scan_id"]

        changed = await ac.post(
            "/api/scans/start",
            json={
                "target_type": "IP", "target_value": "192.168.1.50",
                "asset_id": asset_id, "target_name": "Changed request", "enabled_engines": [],
            },
            headers={**auth_headers, "Idempotency-Key": "scan-idempotency-1"},
        )
        assert changed.status_code == 409

        with db_manager._connection_scope() as conn:
            for user_id, username in (("usr-test-01", "requester"), ("approver-a", "approver")):
                conn.execute(
                    "INSERT OR IGNORE INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, ?, 'ADMIN', ?, 1, ?)",
                    (user_id, username, f"{username}@example.test", "test-hash", "org-default", "2026-09-05T00:00:00+00:00"),
                )
        approved, children = db_manager.approve_scan_authorization_request(
            response_data["scan_request_id"], "org-default", response_data["manifest_hash"],
            "approval-key-a", "approver-a", "session-a", "worker-a", "generation-a",
        )
        assert approved == "AUTHORIZED"
        assert children
        replayed, replay_children = db_manager.approve_scan_authorization_request(
            response_data["scan_request_id"], "org-default", response_data["manifest_hash"],
            "approval-key-a", "approver-a", "session-a", "worker-a", "generation-a",
        )
        assert replayed == "REPLAY"
        assert replay_children == children

        with db_manager._connection_scope() as conn:
            row = conn.execute(
                "SELECT manifest_json FROM scan_authorization_requests WHERE scan_request_id=? AND organization_id=?",
                (response_data["scan_request_id"], "org-default"),
            ).fetchone()
            tampered = json.loads(row["manifest_json"])
            tampered["policy_revision"] = "tampered-policy-revision"
            conn.execute(
                "UPDATE scan_authorization_requests SET manifest_json=? WHERE scan_request_id=? AND organization_id=?",
                (json.dumps(tampered), response_data["scan_request_id"], "org-default"),
            )
            child_count = conn.execute(
                "SELECT COUNT(*) AS count FROM scan_authorization_operations WHERE scan_request_id=? AND organization_id=? AND child_request_id IS NOT NULL",
                (response_data["scan_request_id"], "org-default"),
            ).fetchone()["count"]
        with pytest.raises(RuntimeError, match="manifest cannot be reconstructed"):
            db_manager.approve_scan_authorization_request(
                response_data["scan_request_id"], "org-default", response_data["manifest_hash"],
                "approval-key-a", "approver-a", "session-a", "worker-a", "generation-a",
            )
        with db_manager._connection_scope() as conn:
            assert conn.execute(
                "SELECT COUNT(*) AS count FROM scan_authorization_operations WHERE scan_request_id=? AND organization_id=? AND child_request_id IS NOT NULL",
                (response_data["scan_request_id"], "org-default"),
            ).fetchone()["count"] == child_count

        mismatch = await ac.post(
            "/api/scans/start",
            json={
                "target_type": "IP",
                "target_value": "192.168.1.51",
                "asset_id": asset_id,
                "enabled_engines": [],
            },
            headers={**auth_headers, "Idempotency-Key": "asset-mismatch"},
        )
        assert mismatch.status_code == 400


@pytest.mark.asyncio
async def test_tenant_admin_real_request_and_approval_chain_is_tenant_scoped():
    organization_id = "org-tenant-chain"
    user_id = "tenant-admin-chain"
    with db_manager._connection_scope() as conn:
        conn.execute(
            "INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)",
            (organization_id, "Tenant Chain", "tenant-chain", "2026-09-05T00:00:00+00:00"),
        )
        conn.execute(
            "INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, ?, 'ADMIN', ?, 1, ?)",
            (user_id, "tenant-chain-admin", "tenant-chain@example.test", "test-hash", organization_id, "2026-09-05T00:00:00+00:00"),
        )
    tenant_user = UserProfile(
        id=user_id, username="tenant-chain-admin", email="tenant-chain@example.test",
        role=UserRole.ADMIN, principal_type=PrincipalType.TENANT_PRINCIPAL,
        organization_id=organization_id,
    )
    token = create_access_token(tenant_user)
    headers = {"Authorization": f"Bearer {token}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        asset_response = await ac.post(
            "/api/assets",
            json={"name": "Tenant chain asset", "type": "DOMAIN", "target_value": "example.com"},
            headers=headers,
        )
        assert asset_response.status_code == 201, asset_response.text
        asset_id = asset_response.json()["id"]
        start_response = await ac.post(
            "/api/scans/start",
            # Select an engine that is not applicable to this domain so the
            # real dispatch path can be awaited without running an external
            # assessment tool.
            json={"target_type": "DOMAIN", "target_value": "example.com", "asset_id": asset_id, "enabled_engines": ["infra_iac"]},
            headers={**headers, "Idempotency-Key": "tenant-chain-request"},
        )
        assert start_response.status_code == 201, start_response.text
        started = start_response.json()
        with db_manager._connection_scope() as conn:
            stored_scan = conn.execute("SELECT id, organization_id FROM scans WHERE id=?", (started["scan_id"],)).fetchone()
            assert stored_scan and stored_scan["organization_id"] == organization_id
            assert db_manager.get_user_by_id(user_id).organization_id == organization_id
            loaded_scan = db_manager.get_scan_record(started["scan_id"], organization_id=organization_id)
            assert loaded_scan is not None and loaded_scan.authorization_request_id == started["scan_request_id"]
            persisted_data = json.loads(conn.execute("SELECT data_json FROM scans WHERE id=?", (started["scan_id"],)).fetchone()["data_json"])
            assert persisted_data["authorization_request_id"] == started["scan_request_id"]
            sanitized = sanitize_sensitive_data({"authorization_request_id": started["scan_request_id"], "bearer_token": "secret"})
            assert sanitized == {"authorization_request_id": "[REDACTED]", "bearer_token": "[REDACTED]"}
        # The approval route must exercise the real API/orchestrator boundary,
        # while capability probing remains deterministic and external-tool free.
        # This keeps the assertion about dispatch, rather than host tool
        # installation latency or availability.
        with patch(
            "app.core.orchestrator.discover_system_capabilities",
            new=AsyncMock(return_value=SystemCapabilities(tools=[])),
        ):
            approval_response = await ac.post(
                f"/api/scans/{started['scan_id']}/approve",
                json={"manifest_hash": started["manifest_hash"], "confirm_owned_target": True},
                headers={**headers, "Idempotency-Key": "tenant-chain-approval"},
            )
            assert approval_response.status_code == 202, approval_response.text
            assert approval_response.json()["authorization_state"] == "DISPATCHABLE"
            assert approval_response.json()["dispatch_state"] == "DISPATCHED"
            assert approval_response.json()["execution_started"] is False
            dispatched_task = orchestrator._tasks.get(started["scan_id"])
            assert dispatched_task is not None
            await asyncio.wait_for(asyncio.shield(dispatched_task), timeout=5)
            assert dispatched_task.done()
            assert db_manager.get_scan_record(started["scan_id"], organization_id=organization_id) is not None
            with db_manager._connection_scope() as conn:
                before_replay = {
                    table: conn.execute(
                        f"SELECT COUNT(*) AS count FROM {table} WHERE organization_id=?",
                        (organization_id,),
                    ).fetchone()["count"]
                    for table in ("scan_authorization_operations", "execution_requests", "execution_decisions", "execution_runs", "execution_dispatch_intents")
                }
            exact_replay = await ac.post(
                f"/api/scans/{started['scan_id']}/approve",
                json={"manifest_hash": started["manifest_hash"], "confirm_owned_target": True},
                headers={**headers, "Idempotency-Key": "tenant-chain-approval"},
            )
            assert exact_replay.status_code == 202, exact_replay.text
            assert exact_replay.json()["dispatch_state"] == "DISPATCHED"
            assert exact_replay.json()["idempotent_replay"] is True
            with db_manager._connection_scope() as conn:
                after_replay = {
                    table: conn.execute(
                        f"SELECT COUNT(*) AS count FROM {table} WHERE organization_id=?",
                        (organization_id,),
                    ).fetchone()["count"]
                    for table in before_replay
                }
            assert after_replay == before_replay

        wrong_user = UserProfile(
            id="unprovisioned-approver", username="unprovisioned", email="unprovisioned@example.test",
            role=UserRole.ADMIN, principal_type=PrincipalType.TENANT_PRINCIPAL,
            organization_id=organization_id,
        )
        wrong_user_response = await ac.post(
            f"/api/scans/{started['scan_id']}/approve",
            json={"manifest_hash": started["manifest_hash"], "confirm_owned_target": True},
            headers={"Authorization": f"Bearer {create_access_token(wrong_user)}", "Idempotency-Key": "wrong-user-approval"},
        )
        assert wrong_user_response.status_code == 403
        mismatched_org = UserProfile(
            id="unprovisioned-approver", username="unprovisioned", email="unprovisioned@example.test",
            role=UserRole.ADMIN, principal_type=PrincipalType.TENANT_PRINCIPAL,
            organization_id="org-other-chain",
        )
        mismatched_org_response = await ac.post(
            f"/api/scans/{started['scan_id']}/approve",
            json={"manifest_hash": started["manifest_hash"], "confirm_owned_target": True},
            headers={"Authorization": f"Bearer {create_access_token(mismatched_org)}", "Idempotency-Key": "wrong-org-approval"},
        )
        assert mismatched_org_response.status_code == 404

        revoke_token(token)
        revoked_replay = await ac.post(
            f"/api/scans/{started['scan_id']}/approve",
            json={"manifest_hash": started["manifest_hash"], "confirm_owned_target": True},
            headers={"Authorization": f"Bearer {token}", "Idempotency-Key": "tenant-chain-approval"},
        )
        assert revoked_replay.status_code == 401

        analyst_id = "tenant-chain-analyst"
        with db_manager._connection_scope() as conn:
            conn.execute(
                "INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, ?, 'SECURITY_ANALYST', ?, 1, ?)",
                (analyst_id, "tenant-chain-analyst", "analyst@example.test", "test-hash", organization_id, "2026-09-05T00:00:00+00:00"),
            )
        analyst = UserProfile(
            id=analyst_id, username="tenant-chain-analyst", email="analyst@example.test",
            role=UserRole.SECURITY_ANALYST, principal_type=PrincipalType.TENANT_PRINCIPAL,
            organization_id=organization_id,
        )
        analyst_token = create_access_token(analyst)
        wrong_role = await ac.post(
            f"/api/scans/{started['scan_id']}/approve",
            json={"manifest_hash": started["manifest_hash"], "confirm_owned_target": True},
            headers={"Authorization": f"Bearer {analyst_token}", "Idempotency-Key": "analyst-chain-approval"},
        )
        assert wrong_role.status_code == 403

        from app.api.export import export_raw_json_report
        from app.core.models import AuditEvent, AuditAction
        loaded_for_export = db_manager.get_scan_record(started["scan_id"], organization_id=organization_id)
        orchestrator._active_jobs[started["scan_id"]] = loaded_for_export
        try:
            export_response = await export_raw_json_report(started["scan_id"], tenant_user)
            export_body = export_response.body.decode("utf-8")
            assert "jwt-secret" not in export_body
            assert "cloud-secret" not in export_body
            assert started["scan_request_id"] not in export_body
        finally:
            orchestrator._active_jobs.pop(started["scan_id"], None)
        db_manager.record_audit_event(AuditEvent(
            id="audit-redaction-chain", actor=user_id, organization_id=organization_id,
            action=AuditAction.REPORT_GENERATED, object_type="scan", object_id=started["scan_id"],
            result="SUCCESS", details={
                "bearer_token": "jwt-secret", "session_jti": "jti-secret",
                "credential": "cloud-secret", "public_status": "SUCCESS",
            },
        ))
        audit_events, _ = db_manager.list_audit_events(organization_id=organization_id)
        audit_details = json.dumps(next(event.details for event in audit_events if event.id == "audit-redaction-chain"))
        assert "jwt-secret" not in audit_details
        assert "jti-secret" not in audit_details
        assert "cloud-secret" not in audit_details
        assert "SUCCESS" in audit_details

        other_user = UserProfile(
            id="tenant-chain-other", username="other-tenant-admin", email="other@example.test",
            role=UserRole.ADMIN, principal_type=PrincipalType.TENANT_PRINCIPAL,
            organization_id="org-other-chain",
        )
        with db_manager._connection_scope() as conn:
            conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)", ("org-other-chain", "Other Chain", "other-chain", "2026-09-05T00:00:00+00:00"))
            conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, ?, 'ADMIN', ?, 1, ?)", (other_user.id, other_user.username, other_user.email, "test-hash", "org-other-chain", "2026-09-05T00:00:00+00:00"))
        other_token = create_access_token(other_user)
        cross_tenant = await ac.post(
            f"/api/scans/{started['scan_id']}/approve",
            json={"manifest_hash": started["manifest_hash"], "confirm_owned_target": True},
            headers={"Authorization": f"Bearer {other_token}", "Idempotency-Key": "other-chain-approval"},
        )
        assert cross_tenant.status_code == 404

        with db_manager._connection_scope() as conn:
            conn.execute(
                "UPDATE scan_authorization_requests SET expires_at=? WHERE scan_request_id=? AND organization_id=?",
                ("2020-01-01T00:00:00+00:00", started["scan_request_id"], organization_id),
            )
        expired_replay = await ac.post(
            f"/api/scans/{started['scan_id']}/approve",
            json={"manifest_hash": started["manifest_hash"], "confirm_owned_target": True},
            headers={"Authorization": f"Bearer {create_access_token(tenant_user)}", "Idempotency-Key": "tenant-chain-approval"},
        )
        assert expired_replay.status_code == 409
        with db_manager._connection_scope() as conn:
            assert conn.execute(
                "SELECT state FROM scan_authorization_requests WHERE scan_request_id=? AND organization_id=?",
                (started["scan_request_id"], organization_id),
            ).fetchone()["state"] == "DISPATCHABLE"


@pytest.mark.asyncio
async def test_scan_sse_redacts_authority_and_credential_material():
    scan_id = "sse-redaction-test"
    queue = orchestrator.subscribe_events(scan_id)
    try:
        await orchestrator.emit_log(
            scan_id, LogLevel.INFO, "network", "bearer_token=jwt-secret credential=cloud-secret",
            tool="nmap",
        )
        await orchestrator.emit_auth_status(
            scan_id, {"session_jti": "jti-secret", "authority_token": "auth-secret", "session_active": True},
        )
        log_event = await queue.get()
        auth_event = await queue.get()
        assert "jwt-secret" not in json.dumps(log_event)
        assert "cloud-secret" not in json.dumps(log_event)
        assert "jti-secret" not in json.dumps(auth_event)
        assert "auth-secret" not in json.dumps(auth_event)
        assert auth_event["data"]["session_active"] is True
    finally:
        orchestrator.unsubscribe_events(scan_id, queue)


@pytest.mark.asyncio
async def test_tool_install_sse_redacts_sensitive_event_data():
    from app.api.tools import stream_tool_events
    from app.installers.manager import ToolInstallationManager

    manager = ToolInstallationManager.get_instance()
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request({
        "type": "http", "method": "GET", "path": "/api/tools/events",
        "headers": [], "query_string": b"", "server": ("test", 80),
        "scheme": "http", "client": ("127.0.0.1", 1),
    }, receive)
    user = UserProfile(id="tool-sse-user", username="tool-sse", email="tool-sse@example.test", role=UserRole.ADMIN)
    response = await stream_tool_events(request, user)
    iterator = response.body_iterator
    first = await anext(iterator)
    assert "event: ping" in first
    pending = asyncio.create_task(anext(iterator))
    await asyncio.sleep(0)
    await manager.broadcast_event("install_log", {
        "message": "bearer_token=jwt-secret credential=cloud-secret",
        "session_jti": "jti-secret",
        "status": "RUNNING",
    })
    chunk = await pending
    assert "jwt-secret" not in chunk
    assert "cloud-secret" not in chunk
    assert "jti-secret" not in chunk
    assert "RUNNING" in chunk
    await iterator.aclose()


@pytest.mark.asyncio
async def test_unexpected_api_errors_are_generic_and_correlated():
    request = Request({
        "type": "http",
        "method": "GET",
        "path": "/api/test",
        "headers": [(b"x-correlation-id", b"corr-test-123")],
        "query_string": b"",
        "server": ("test", 80),
        "scheme": "http",
        "client": ("127.0.0.1", 1),
    })
    request.state.correlation_id = "corr-test-123"
    from app.main import handle_unexpected_exception

    response = await handle_unexpected_exception(request, RuntimeError("secret filesystem path"))
    assert response.status_code == 500
    assert response.body == b'{"error_code":"INTERNAL_ERROR","message":"An internal server error occurred.","correlation_id":"corr-test-123"}'
    assert b"secret filesystem path" not in response.body


@pytest.mark.asyncio
async def test_scan_lifecycle_api(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. A scan request without an explicitly admitted inventory asset is rejected.
        bad_resp = await ac.post("/api/scans/start", json={
            "target_type": "URL",
            "target_value": "not-a-url",
        }, headers={**auth_headers, "Idempotency-Key": "missing-asset"})
        assert bad_resp.status_code == 422
        assert "monitored inventory asset is required" in bad_resp.json()["detail"]

        asset_resp = await ac.post("/api/assets", json={
            "name": "Test Site Asset",
            "type": "WEB_APPLICATION",
            "target_value": "https://example.com",
        }, headers=auth_headers)
        assert asset_resp.status_code == 201, asset_resp.text
        asset_id = asset_resp.json()["id"]

        # 2. Inline authentication material is rejected because the durable
        #    request path has no tenant-scoped credential resolver.
        secret_resp = await ac.post("/api/scans/start", json={
            "target_type": "URL",
            "target_value": "https://example.com",
            "asset_id": asset_id,
            "target_name": "Test Site",
            "profile": "CUSTOM",
            "enabled_engines": [],
            "config": {
                "auth": {
                    "auth_type": "HEADER",
                    "headers": {"Authorization": "Bearer test-token"},
                }
            }
        }, headers={**auth_headers, "Idempotency-Key": "inline-auth-rejected"})
        assert secret_resp.status_code == 422, secret_resp.text
        assert "test-token" not in secret_resp.text

        # 3. Create the request with crawler configuration; execution remains pending approval.
        start_resp = await ac.post("/api/scans/start", json={
            "target_type": "URL",
            "target_value": "https://example.com",
            "asset_id": asset_id,
            "target_name": "Test Site",
            "profile": "CUSTOM",
            "enabled_engines": [],
            "config": {
                "crawler": {
                    "enabled": True,
                    "max_depth": 2,
                    "max_pages": 15,
                }
            }
        }, headers={**auth_headers, "Idempotency-Key": "lifecycle-request"})
        assert start_resp.status_code == 201, start_resp.text
        start_data = start_resp.json()
        scan_id = start_data["scan_id"]
        assert scan_id is not None
        assert start_data["authorization_state"] == "REQUESTED"
        assert start_data["dispatch_state"] == "PENDING_APPROVAL"
        assert start_data["execution_started"] is False

        # 4. Get scan details snapshot
        get_resp = await ac.get(f"/api/scans/{scan_id}", headers=auth_headers)
        assert get_resp.status_code == 200
        get_data = get_resp.json()
        assert get_data["id"] == scan_id
        assert get_data["target"]["name"] == "Test Site"
        assert "discovered_endpoints" in get_data
        assert "pages_crawled" in get_data["summary"]
        assert "authenticated_session_active" in get_data["summary"]

        # 5. List scan history
        hist_resp = await ac.get("/api/scans/history?limit=10&offset=0", headers=auth_headers)
        assert hist_resp.status_code == 200
        hist_data = hist_resp.json()
        assert hist_data["total"] >= 1

        # 6. Cancel scan endpoint
        cancel_resp = await ac.post(f"/api/scans/{scan_id}/cancel", headers=auth_headers)
        assert cancel_resp.status_code == 200
        assert cancel_resp.json()["status"] == "CANCELLED"

        # 7. Historical scan records are retained; no ordinary delete endpoint exists.
        del_resp = await ac.delete(f"/api/scans/{scan_id}", headers=auth_headers)
        assert del_resp.status_code == 405
        retained_resp = await ac.get(f"/api/scans/{scan_id}", headers=auth_headers)
        assert retained_resp.status_code == 200


@pytest.mark.asyncio
async def test_export_endpoints(auth_headers):
    target = Target(name="Export Test App", type=TargetType.URL, value="https://example.com")
    job = ScanJob(
        target=target,
        profile=ScanProfile.FULL_STACK,
    )
    save_scan(job)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. HTML export
        html_resp = await ac.get(f"/api/scans/{job.id}/export/html", headers=auth_headers)
        assert html_resp.status_code == 200
        assert "text/html" in html_resp.headers["content-type"]
        assert "attachment;" in html_resp.headers["content-disposition"]
        assert "<!DOCTYPE html>" in html_resp.text

        # 2. SARIF export
        sarif_resp = await ac.get(f"/api/scans/{job.id}/export/sarif", headers=auth_headers)
        assert sarif_resp.status_code == 200
        assert "application/json" in sarif_resp.headers["content-type"]
        sarif_json = sarif_resp.json()
        assert sarif_json["version"] == "2.1.0"

        # 3. JSON export
        json_resp = await ac.get(f"/api/scans/{job.id}/export/json", headers=auth_headers)
        assert json_resp.status_code == 200
        raw_json = json_resp.json()
        assert raw_json["id"] == job.id


@pytest.mark.asyncio
async def test_sse_streaming_endpoint(auth_headers):
    from app.core.grading import calculate_scan_grade
    target = Target(name="SSE Target", type=TargetType.URL, value="https://example.com")
    job = ScanJob(
        target=target,
        profile=ScanProfile.FULL_STACK,
        status=ScanStatus.COMPLETED,
        progress_percent=100,
        rejected_discoveries=[RejectedDiscovery(
            domain="outside.example.net",
            reason="OUT_OF_SCOPE",
            sources=["crtsh"],
            authorized_root="example.com",
            assessment_id="sse-rejected-evidence",
            organization_id="org-default",
        )],
    )
    job.summary = calculate_scan_grade([], duration_seconds=1.0)
    save_scan(job)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        query_token_resp = await ac.get(f"/api/scans/{job.id}/events?token={auth_headers['Authorization'].split(' ', 1)[1]}")
        assert query_token_resp.status_code == 401

        async with ac.stream("GET", f"/api/scans/{job.id}/events", headers=auth_headers) as resp:
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers["content-type"]
            
            lines = []
            async for line in resp.aiter_lines():
                if line:
                    lines.append(line)
            
            assert len(lines) >= 2
            assert any("event: completed" in l or "event: connected" in l for l in lines)
            assert any("event: discovery_rejected" in l for l in lines)


@pytest.mark.asyncio
async def test_live_scan_sse_streaming(auth_headers):
    from app.core.orchestrator import orchestrator
    from app.core.models import LogLevel
    scan_id = "test-live-sse-stream"
    job = ScanJob(
        id=scan_id,
        target=Target(name="Live SSE", type=TargetType.URL, value="https://live.test"),
        status=ScanStatus.RUNNING,
    )
    orchestrator._active_jobs[scan_id] = job

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Start SSE stream in background
        async def read_stream():
            received = []
            async with ac.stream("GET", f"/api/scans/{scan_id}/events", headers=auth_headers) as resp:
                assert resp.status_code == 200
                async for line in resp.aiter_lines():
                    if line:
                        received.append(line)
                    if "event: completed" in line or "event: cancelled" in line:
                        break
            return received

        stream_task = asyncio.create_task(read_stream())
        await asyncio.sleep(0.05)

        # Broadcast live progress, log, and cancelled
        await orchestrator.emit_progress(scan_id, 25, "Running network scanner...")
        await orchestrator.emit_log(scan_id, LogLevel.INFO, "network", "Port 80 is open")
        await orchestrator.emit_cancelled(scan_id, "Scan cancelled by user.")

        lines = await asyncio.wait_for(stream_task, timeout=5.0)
        assert any("event: progress" in l for l in lines)
        assert any("Running network scanner" in l for l in lines)
        assert any("event: log" in l for l in lines)
        assert any("Port 80 is open" in l for l in lines)
        assert any("event: cancelled" in l for l in lines)



@pytest.mark.asyncio
async def test_telemetry_endpoint_structure_and_filters(auth_headers):
    from app.core.models import LogEntry, LogLevel, Finding, Evidence, DiscoveredEndpoint, DiscoveredSubdomain, ToolFailureEvent
    target = Target(name="Telemetry Target", type=TargetType.URL, value="https://telemetry-test.local")
    job = ScanJob(
        target=target,
        profile=ScanProfile.FULL_STACK,
        status=ScanStatus.COMPLETED,
        progress_percent=100,
        active_adapters=["nmap", "nuclei", "katana"],
        tool_execution_states={"schemathesis": "TOOL_EXECUTION_FAILED"},
        tool_failure_events=[ToolFailureEvent(tool_name="schemathesis", engine="web_dast", state="TOOL_EXECUTION_FAILED")],
        logs=[
            LogEntry(level=LogLevel.INFO, engine="network", tool="nmap", message="Nmap detected open port 443"),
            LogEntry(level=LogLevel.WARNING, engine="web_dast", tool="nuclei", message="Nuclei detected CVE-2024-9999"),
            LogEntry(level=LogLevel.ERROR, engine="code_sast", tool="semgrep", message="Semgrep parse failure in file"),
        ],
        discovered_endpoints=[
            DiscoveredEndpoint(url="https://telemetry-test.local/login", method="GET", status_code=200, depth=1)
        ],
        discovered_subdomains=[
            DiscoveredSubdomain(domain="api.telemetry-test.local", ip_addresses=["10.0.0.1"], is_takeover_vulnerable=False)
        ],
        findings=[
            Finding(
                scan_id="scan-telemetry-run",
                engine="web_dast",
                source_tool="nuclei",
                check_id="CVE-2024-9999",
                category="Injection",
                title="SQL Injection Vulnerability",
                severity=Severity.HIGH,
                cvss_score=8.5,
                description="SQLi vulnerability detected",
                impact="Database compromise",
                remediation="Use parameterized queries",
                evidence=Evidence(location="https://telemetry-test.local/api/users", observed_value="error in SQL", expected_value="clean")
            )
        ]
    )
    job.summary.coverage.coverage_status = "COVERAGE_DEGRADED"
    job.summary.coverage.is_fully_assessed = False
    save_scan(job)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Unauthenticated request -> 401
        res_unauth = await ac.get(f"/api/scans/{job.id}/telemetry")
        assert res_unauth.status_code == 401

        # 2. Authenticated request -> 200 with full structure
        res = await ac.get(f"/api/scans/{job.id}/telemetry", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["scan_id"] == job.id
        assert data["target_value"] == "https://telemetry-test.local"
        assert data["total_logs"] == 3
        assert len(data["logs"]) == 3
        assert len(data["discovered_endpoints"]) == 1
        assert len(data["discovered_subdomains"]) == 1
        # Host availability is not proof of execution. Only recorded tool
        # states or findings belong in executed-tool telemetry.
        assert {item["tool_name"] for item in data["tools_executed"]} == {"nuclei", "schemathesis"}
        schemathesis = next(item for item in data["tools_executed"] if item["tool_name"] == "schemathesis")
        assert schemathesis["status"] == "FAILED"
        assert schemathesis["normalized_state"] == "TOOL_EXECUTION_FAILED"
        nuclei = next(item for item in data["tools_executed"] if item["tool_name"] == "nuclei")
        assert nuclei["status"] == "FINDINGS"
        assert nuclei["engine"] == "web_dast"
        assert data["coverage"]["coverage_status"] == "COVERAGE_DEGRADED"
        assert data["tool_failure_events"] == [
            {
                "tool_name": "schemathesis",
                "engine": "web_dast",
                "state": "TOOL_EXECUTION_FAILED",
                "correlation_id": None,
                "occurred_at": data["tool_failure_events"][0]["occurred_at"],
            }
        ]

        # A finding emitted before a later tool failure is partial evidence;
        # it must not make the failed execution look successful.
        job.tool_execution_states["nuclei"] = "TOOL_EXECUTION_FAILED"
        save_scan(job)
        degraded = await ac.get(f"/api/scans/{job.id}/telemetry", headers=auth_headers)
        degraded_nuclei = next(
            item for item in degraded.json()["tools_executed"] if item["tool_name"] == "nuclei"
        )
        assert degraded_nuclei["status"] == "FAILED"

        # 3. Filter by tool=nuclei
        res_tool = await ac.get(f"/api/scans/{job.id}/telemetry?tool=nuclei", headers=auth_headers)
        assert res_tool.status_code == 200
        data_tool = res_tool.json()
        assert len(data_tool["logs"]) == 1
        assert "Nuclei detected" in data_tool["logs"][0]["message"]

        # 4. Filter by level=ERROR
        res_lvl = await ac.get(f"/api/scans/{job.id}/telemetry?level=ERROR", headers=auth_headers)
        assert res_lvl.status_code == 200
        data_lvl = res_lvl.json()
        assert len(data_lvl["logs"]) == 1
        assert "Semgrep parse failure" in data_lvl["logs"][0]["message"]

        # 5. Search query
        res_search = await ac.get(f"/api/scans/{job.id}/telemetry?search=open port", headers=auth_headers)
        assert res_search.status_code == 200
        data_search = res_search.json()
        assert len(data_search["logs"]) == 1
        assert "open port 443" in data_search["logs"][0]["message"]


@pytest.mark.asyncio
async def test_passive_discovery_requires_explicit_inventory_admission(auth_headers):
    from app.core.models import AssetLifecycleStatus, DiscoveredSubdomain

    job = ScanJob(
        id="scan-explicit-discovery-admission",
        organization_id="org-default",
        target=Target(name="Discovery source", type=TargetType.DOMAIN, value="example.com"),
        profile=ScanProfile.PASSIVE_OSINT,
        status=ScanStatus.COMPLETED,
        discovered_subdomains=[DiscoveredSubdomain(
            domain="api.example.com",
            discovered_via="Subfinder",
            sources=["crtsh"],
            dns_status="UNRESOLVED",
            organization_id="org-default",
            assessment_id="scan-explicit-discovery-admission",
            authorized_root="example.com",
        )],
    )
    save_scan(job)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        admitted = await ac.post(
            "/api/assets/admit-discovery",
            json={"scan_id": job.id, "domain": "API.Example.com", "name": "Public API"},
            headers=auth_headers,
        )
        assert admitted.status_code == 201
        asset = admitted.json()
        assert asset["target_value"] == "api.example.com"
        assert asset["type"] == "DOMAIN"
        assert asset["lifecycle_status"] == AssetLifecycleStatus.DISCOVERED.value
        assert asset["active_probing_granted"] is False
        assert asset["live_secret_verification_granted"] is False

        missing = await ac.post(
            "/api/assets/admit-discovery",
            json={"scan_id": job.id, "domain": "admin.example.com"},
            headers=auth_headers,
        )
        assert missing.status_code == 404

        other_tenant = UserProfile(
            id="usr-admission-other",
            username="admission-other",
            email="admission-other@example.test",
            role=UserRole.ADMIN,
            organization_id="org-other",
        )
        other_headers = {"Authorization": f"Bearer {create_access_token(other_tenant)}"}
        cross_tenant = await ac.post(
            "/api/assets/admit-discovery",
            json={"scan_id": job.id, "domain": "api.example.com"},
            headers=other_headers,
        )
        assert cross_tenant.status_code == 404


@pytest.mark.asyncio
async def test_finding_occurrences_endpoint_is_tenant_scoped(auth_headers):
    """Contract 04 §1.4: occurrence history is durable and cannot cross tenants."""
    from app.core.db import db_manager

    scan_id = "occurrence-api-scan"
    job = ScanJob(
        id=scan_id,
        organization_id="org-default",
        target=Target(name="Occurrence API", type=TargetType.URL, value="https://occurrence.test"),
        profile=ScanProfile.FULL_STACK,
        findings=[
            Finding(
                scan_id=scan_id,
                engine="web_dast",
                source_tool="nuclei",
                check_id="DAST-OCC-001",
                category="Test",
                title="Occurrence API finding",
                severity=Severity.MEDIUM,
                cvss_score=5.0,
                description="Test finding",
                impact="Test impact",
                remediation="Test remediation",
                evidence=Evidence(
                    location="https://occurrence.test",
                    observed_value="observed",
                    expected_value="expected",
                ),
            )
        ],
    )
    save_scan(job)
    with db_manager._connection_scope() as conn:
        row = conn.execute(
            "SELECT id FROM findings WHERE scan_id = ? AND organization_id = ?",
            (scan_id, "org-default"),
        ).fetchone()
    assert row is not None
    finding_id = row["id"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get(f"/api/findings/{finding_id}/occurrences", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["finding_id"] == finding_id
        assert data["total"] == 1
        assert data["items"][0]["organization_id"] == "org-default"
        assert data["items"][0]["source_tool"] == "nuclei"

        other_tenant = UserProfile(
            id="usr-occurrence-other",
            username="other-tenant",
            email="other-tenant@example.test",
            role=UserRole.ADMIN,
            organization_id="org-other",
        )
        other_headers = {"Authorization": f"Bearer {create_access_token(other_tenant)}"}
        denied = await ac.get(f"/api/findings/{finding_id}/occurrences", headers=other_headers)
        assert denied.status_code == 404


@pytest.mark.asyncio
async def test_asset_creation_all_supported_types(auth_headers):
    """
    Verifies that all supported AssetType values (WEB_APPLICATION, API_ENDPOINT,
    DOMAIN, IP_ADDRESS, GIT_REPOSITORY, CONTAINER_IMAGE) pass security policy validation.
    """
    test_cases = [
        ("virtualhymn", "WEB_APPLICATION", "https://vh.pixelretrobooth.com"),
        ("users-api", "API_ENDPOINT", "https://api.pixelretrobooth.com/v1"),
        ("main-domain", "DOMAIN", "pixelretrobooth.com"),
        ("production-node", "IP_ADDRESS", "93.184.216.34"),
        ("backend-repo", "GIT_REPOSITORY", "https://github.com/example/security-platform.git"),
        ("api-container", "CONTAINER_IMAGE", "cyberassess/core-engine:v13.0.0"),
    ]

    with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            for name, a_type, target_val in test_cases:
                payload = {
                    "name": name,
                    "type": a_type,
                    "target_value": target_val,
                    "criticality": "HIGH",
                }
                res = await ac.post("/api/assets", json=payload, headers=auth_headers)
                assert res.status_code == 201, f"Failed for {a_type}: {res.text}"
                data = res.json()
                assert data["name"] == name
                assert data["type"] == a_type
                assert data["target_value"] == target_val


@pytest.mark.asyncio
async def test_per_link_assessment_dossier_structure(auth_headers):
    """
    Verifies that the /telemetry endpoint enriches discovered endpoints with:
    1. Executed tools per link.
    2. Performed security test records (SQLi, XSS, Headers, CORS, CSRF).
    3. Finding ID correlations for that specific URL.
    """
    target = Target(name="Dossier App", type=TargetType.URL, value="https://dossier-test.local")
    job = ScanJob(
        target=target,
        profile=ScanProfile.FULL_STACK,
        status=ScanStatus.COMPLETED,
        progress_percent=100,
        active_adapters=["nuclei"],
        discovered_endpoints=[
            DiscoveredEndpoint(
                url="https://dossier-test.local/admin/settings",
                method="GET",
                depth=1,
                status_code=200,
                content_type="text/html",
                is_authenticated=True,
                has_forms=True,
                discovered_forms=2,
                tools_executed=["native_dast", "katana", "parameter_fuzzer"],
                tests_performed=[
                    EndpointTestRecord(test_name="Security Headers", category="Configuration", tool="native_dast", status=EndpointTestStatus.VULNERABLE),
                    EndpointTestRecord(test_name="CORS Policy", category="Access Control", tool="native_dast", status=EndpointTestStatus.SAFE),
                    EndpointTestRecord(test_name="Active Parameter Injection", category="Injection", tool="parameter_fuzzer", status=EndpointTestStatus.SAFE),
                    EndpointTestRecord(test_name="CSRF Protection", category="Session Management", tool="native_dast", status=EndpointTestStatus.SAFE),
                ],
            )
        ],
        findings=[
            Finding(
                scan_id="scan-dossier-1",
                engine="web_dast",
                source_tool="native_dast",
                check_id="DAST-HDR-001",
                category="Configuration",
                title="Missing Content Security Policy (CSP)",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                description="No CSP header found",
                impact="XSS vulnerability",
                remediation="Configure CSP header",
                evidence=Evidence(location="https://dossier-test.local/admin/settings", observed_value="No CSP", expected_value="CSP present")
            )
        ]
    )
    save_scan(job)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get(f"/api/scans/{job.id}/telemetry", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        endpoints = data["discovered_endpoints"]
        assert len(endpoints) == 1
        ep = endpoints[0]
        assert ep["url"] == "https://dossier-test.local/admin/settings"
        assert len(ep["finding_ids"]) == 1
        assert len(ep["tools_executed"]) >= 3
        assert "nuclei" not in ep["tools_executed"], "availability must not masquerade as endpoint execution"
        assert len(ep["tests_performed"]) >= 4
        # Verify test records contain test name, category, tool, and status
        test_names = [t["test_name"] for t in ep["tests_performed"]]
        assert any("Security Headers" in name for name in test_names)
        assert any("CORS" in name for name in test_names)
        assert any("Injection" in name for name in test_names)


@pytest.mark.asyncio
async def test_subfinder_discovery_remains_passive_and_unresolved():
    """Subfinder discovery must not perform DNS resolution or claim active state."""
    from unittest.mock import AsyncMock, patch
    from app.adapters.subfinder_adapter import SubfinderAdapter
    from app.core.models import TargetType, ScanConfig

    adapter = SubfinderAdapter()
    target = Target(name="Passive discovery", type=TargetType.DOMAIN, value="dns.google")
    config = ScanConfig()
    discovered = []

    async def capture_discovery(item):
        discovered.append(item)

    with patch.object(adapter, "resolve_binary_path", return_value="/managed/subfinder"), \
         patch.object(adapter, "verify_managed_binary", return_value=True), \
         patch.object(adapter, "get_version", new=AsyncMock(return_value="subfinder v2.6.5")), \
         patch.object(adapter, "execute_command", new=AsyncMock(return_value=(
             0, '{"host":"api.dns.google","sources":["crtsh"]}\n', ""
         ))):
        findings = await adapter.run(target, config, AsyncMock(), AsyncMock(), emit_subdomain=capture_discovery)

    assert len(findings) == 1
    assert discovered[0].dns_status == "UNRESOLVED"
    assert discovered[0].ip_addresses == []
    assert not hasattr(adapter, "_resolve_host_dns")
