"""Route-level authentication and tenant-binding tests for quarantine recovery."""

import asyncio

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import app.core.auth as auth_module
import app.core.db as db_module
import app.api.executions as executions_api
from app.core.auth import create_access_token, hash_password
from app.core.db import DatabaseManager
from app.core.models import UserProfile, UserRole
from app.core.queue import ScanQueueManager
from app.main import app


class _QuarantineBackend:
    def __init__(self) -> None:
        self.states = {}
        self.calls = []
        self._lock = asyncio.Lock()

    async def acknowledge_quarantined(self, message_id, *, operator, authorization_request_id):
        async with self._lock:
            state = self.states.get(message_id)
            if state is None or state["acknowledged"]:
                return False
            if (
                operator.organization_id != state["organization_id"]
                or authorization_request_id != state["authorization_request_id"]
            ):
                return False
            state["acknowledged"] = True
            self.calls.append((message_id, operator, authorization_request_id))
            return True


@pytest.fixture
def quarantine_api_state(tmp_path, monkeypatch):
    database = DatabaseManager(tmp_path / "quarantine-api.db")
    monkeypatch.setattr(DatabaseManager, "_instance", database)
    monkeypatch.setattr(db_module, "db_manager", database)
    monkeypatch.setattr(executions_api, "db_manager", database)

    admin, organization = database.bootstrap_system(
        "recovery-admin",
        "recovery-admin@example.test",
        hash_password("AdminPass123!"),
        "Recovery Organization",
    )
    backend = _QuarantineBackend()
    monkeypatch.setattr(
        auth_module,
        "OPERATING_MODE",
        auth_module.OperatingMode.TEST,
    )
    import app.core.queue as queue_module

    monkeypatch.setattr(queue_module, "EXECUTION_QUEUE_URL", "redis://queue.test/15")
    monkeypatch.setattr(queue_module, "queue_manager", ScanQueueManager(durable_backend=backend))
    return database, admin, organization, backend


def _token(user: UserProfile, *, scopes=None) -> str:
    return create_access_token(user, scopes=scopes)


def _payload(request_id: str) -> dict[str, str]:
    return {"authorization_request_id": request_id}


def test_quarantine_route_requires_authenticated_admin_session(quarantine_api_state):
    _database, _admin, _organization, _backend = quarantine_api_state
    client = TestClient(app)
    response = client.post(
        "/api/system/executions/recovery/quarantine/message-unauthenticated/ack",
        json=_payload("request-a"),
    )
    assert response.status_code == 401


def test_quarantine_route_enforces_scope_role_expiry_and_revocation(
    quarantine_api_state,
):
    database, admin, organization, backend = quarantine_api_state
    client = TestClient(app)
    backend.states["message-auth"] = {
        "organization_id": organization.id,
        "authorization_request_id": "request-auth",
        "acknowledged": False,
    }

    expired = create_access_token(admin, expires_in=-1)
    expired_response = client.post(
        "/api/system/executions/recovery/quarantine/message-auth/ack",
        headers={"Authorization": f"Bearer {expired}"},
        json=_payload("request-auth"),
    )
    assert expired_response.status_code == 401

    analyst_id = "usr-recovery-analyst"
    now = database.get_user_by_id(admin.id).created_at.isoformat()
    with database._connection_scope() as conn:
        conn.execute(
            "INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) "
            "VALUES (?, ?, ?, ?, 'SECURITY_ANALYST', ?, 1, ?)",
            (analyst_id, "recovery-analyst", "analyst@example.test", "hash", organization.id, now),
        )
    analyst = UserProfile(
        id=analyst_id,
        username="recovery-analyst",
        email="analyst@example.test",
        role=UserRole.SECURITY_ANALYST,
        organization_id=organization.id,
    )
    analyst_response = client.post(
        "/api/system/executions/recovery/quarantine/message-auth/ack",
        headers={"Authorization": f"Bearer {_token(analyst)}"},
        json=_payload("request-auth"),
    )
    assert analyst_response.status_code == 403

    restricted_admin = admin.model_copy(update={"scopes": []})
    restricted_response = client.post(
        "/api/system/executions/recovery/quarantine/message-auth/ack",
        headers={"Authorization": f"Bearer {_token(restricted_admin, scopes=[])}"},
        json=_payload("request-auth"),
    )
    assert restricted_response.status_code == 403

    valid_token = _token(admin)
    assert auth_module.revoke_token(valid_token) is True
    revoked_response = client.post(
        "/api/system/executions/recovery/quarantine/message-auth/ack",
        headers={"Authorization": f"Bearer {valid_token}"},
        json=_payload("request-auth"),
    )
    assert revoked_response.status_code == 401


def test_quarantine_route_requires_exact_tenant_request_and_is_idempotently_rejected(
    quarantine_api_state,
):
    database, admin, organization, backend = quarantine_api_state
    client = TestClient(app)
    backend.states["message-valid"] = {
        "organization_id": organization.id,
        "authorization_request_id": "request-valid",
        "acknowledged": False,
    }
    token = _token(admin)
    headers = {"Authorization": f"Bearer {token}"}

    other_org_id = "org-other-tenant"
    other_user_id = "usr-other-tenant-admin"
    now = database.get_user_by_id(admin.id).created_at.isoformat()
    with database._connection_scope() as conn:
        conn.execute(
            "INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)",
            (other_org_id, "Other Organization", "other", now),
        )
        conn.execute(
            "INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) "
            "VALUES (?, ?, ?, ?, 'ADMIN', ?, 1, ?)",
            (other_user_id, "other-admin", "other-admin@example.test", "hash", other_org_id, now),
        )
    other_admin = UserProfile(
        id=other_user_id,
        username="other-admin",
        email="other-admin@example.test",
        role=UserRole.ADMIN,
        organization_id=other_org_id,
    )
    wrong_tenant = client.post(
        "/api/system/executions/recovery/quarantine/message-valid/ack",
        headers={"Authorization": f"Bearer {_token(other_admin)}"},
        json=_payload("request-valid"),
    )
    assert wrong_tenant.status_code == 409
    assert backend.calls == []

    wrong_request = client.post(
        "/api/system/executions/recovery/quarantine/message-valid/ack",
        headers=headers,
        json=_payload("request-wrong"),
    )
    assert wrong_request.status_code == 409
    assert backend.calls == []

    accepted = client.post(
        "/api/system/executions/recovery/quarantine/message-valid/ack",
        headers=headers,
        json=_payload("request-valid"),
    )
    assert accepted.status_code == 200
    assert accepted.json()["acknowledged"] is True

    replay = client.post(
        "/api/system/executions/recovery/quarantine/message-valid/ack",
        headers=headers,
        json=_payload("request-valid"),
    )
    assert replay.status_code == 409
    assert len(backend.calls) == 1
    assert backend.calls[0][1].organization_id == organization.id


@pytest.mark.asyncio
async def test_quarantine_route_concurrent_acknowledgement_has_one_winner(
    quarantine_api_state,
):
    _database, admin, organization, backend = quarantine_api_state
    backend.states["message-concurrent"] = {
        "organization_id": organization.id,
        "authorization_request_id": "request-concurrent",
        "acknowledged": False,
    }
    token = _token(admin)
    payload = executions_api.QuarantineAcknowledgementPayload(
        authorization_request_id="request-concurrent"
    )

    results = await asyncio.gather(
        executions_api.acknowledge_quarantined_dispatch(
            "message-concurrent", payload, f"Bearer {token}", admin
        ),
        executions_api.acknowledge_quarantined_dispatch(
            "message-concurrent", payload, f"Bearer {token}", admin
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(result, dict) and result["acknowledged"] for result in results) == 1
    assert sum(isinstance(result, HTTPException) and result.status_code == 409 for result in results) == 1
    assert len(backend.calls) == 1
