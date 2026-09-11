"""Adversarial coverage for tenant-admin and system-principal administration boundaries."""

from __future__ import annotations

import pytest

from app.api.auth import CreateUserRequest, create_user
from app.api.assets import CreateAssetRequest, create_asset
from app.api.scans import StartScanRequest, start_security_scan
from app.core.auth import UserProfile, authorize_internal_target
from app.core.models import PrincipalType, UserRole


@pytest.mark.asyncio
async def test_signed_viewer_token_cannot_escalate_through_synthetic_identity(monkeypatch):
    """A valid signature does not make token-provided elevated scopes authoritative."""
    import time
    import jwt
    import app.core.auth as auth_module
    import app.core.db as db_module

    monkeypatch.setattr(auth_module, "OPERATING_MODE", auth_module.OperatingMode.TEST)
    monkeypatch.setattr(db_module.db_manager, "get_user_by_id", lambda _subject: None)
    monkeypatch.setattr(db_module.db_manager, "is_token_revoked", lambda _jti: False)
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": auth_module.JWT_ISSUER,
            "aud": auth_module.JWT_AUDIENCE,
            "sub": "fixture-viewer-not-provisioned",
            "username": "viewer",
            "email": "viewer@example.test",
            "role": UserRole.VIEWER.value,
            "principal_type": PrincipalType.TENANT_PRINCIPAL.value,
            "org_id": "org-viewer",
            "scopes": ["tool:install", "scan:read"],
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": "fixture-viewer-elevated-scope",
        },
        auth_module.JWT_SECRET,
        algorithm=auth_module.JWT_ALGORITHM,
        headers={"typ": "JWT", "kid": auth_module.ACTIVE_KEY_ID},
    )

    resolved = await auth_module.get_current_user(authorization=f"Bearer {token}")

    assert resolved.role is UserRole.VIEWER
    assert resolved.scopes == ["scan:read"]
    assert "tool:install" not in resolved.scopes


@pytest.mark.asyncio
@pytest.mark.parametrize("approval_result", ["AUTHORIZED", "REPLAY"])
async def test_scan_approval_dispatches_through_orchestrator_and_replay_is_idempotent(monkeypatch, approval_result):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock
    from app.api import scans

    admin = UserProfile(
        id="approver-1", username="tenant-approver", email="approver@example.test",
        role=UserRole.ADMIN, organization_id="org-one",
        principal_type=PrincipalType.TENANT_PRINCIPAL, scopes=["execution:approve"],
    )
    job = SimpleNamespace(authorization_request_id="parent-1")
    monkeypatch.setattr(scans, "get_scan", lambda *args, **kwargs: job)
    monkeypatch.setattr(scans, "_scan_session_jti", lambda *args: "session-1")
    approve = Mock(return_value=(approval_result, []))
    monkeypatch.setattr(scans, "db_manager", SimpleNamespace(approve_scan_authorization_request=approve))
    dispatch = AsyncMock()
    monkeypatch.setattr(scans.orchestrator, "dispatch_approved_scan", dispatch)
    save = Mock()
    monkeypatch.setattr(scans, "save_scan", save)

    result = await scans.approve_scan_authorization(
        "scan-1", scans.ScanApprovalRequest(manifest_hash="a" * 64, confirm_owned_target=True),
        authorization="Bearer test-session", idempotency_key="approval-1", current_user=admin,
    )

    assert result["execution_started"] is False
    assert result["dispatch_state"] == "DISPATCHED"
    assert result["idempotent_replay"] is (approval_result == "REPLAY")
    approve.assert_called_once()
    dispatch.assert_awaited_once_with(job)
    save.assert_not_called()


@pytest.mark.asyncio
async def test_scan_approval_guard_accepts_real_tenant_admin_and_rejects_missing_scope():
    import inspect
    from fastapi import HTTPException
    from app.api.scans import approve_scan_authorization
    from app.core.auth import resolve_effective_scopes

    admin = UserProfile(
        username="tenant-approver", email="approver@example.test", role=UserRole.ADMIN,
        principal_type=PrincipalType.TENANT_PRINCIPAL, organization_id="org-one",
    )
    admin = admin.model_copy(update={"scopes": resolve_effective_scopes(admin)})
    guard = inspect.signature(approve_scan_authorization).parameters["current_user"].default.dependency
    assert "*" not in admin.scopes
    assert await guard(admin) is admin
    restricted = admin.model_copy(update={"scopes": ["scan:read"]})
    with pytest.raises(HTTPException) as denied:
        await guard(restricted)
    assert denied.value.status_code == 403


@pytest.mark.asyncio
async def test_tenant_admin_cannot_create_user_in_another_organization():
    tenant_admin = UserProfile(
        username="tenant-admin", email="tenant@example.test", role=UserRole.ADMIN,
        principal_type=PrincipalType.TENANT_PRINCIPAL, organization_id="org-one",
    )
    payload = CreateUserRequest(
        username="cross-tenant", email="cross@example.test", password="StrongPass123!",
        organization_id="org-two",
    )

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await create_user(payload, tenant_admin)
    assert exc_info.value.status_code == 403


def test_internal_target_requires_explicit_scope_even_for_admin_role():
    admin_without_scope = UserProfile(
        username="admin", email="admin@example.test", role=UserRole.ADMIN,
        scopes=["scan:repeater"],
    )
    admin_with_scope = admin_without_scope.model_copy(update={"scopes": ["scan:repeater", "scan:internal"]})

    assert authorize_internal_target(admin_without_scope, "http://127.0.0.1") is False
    assert authorize_internal_target(admin_with_scope, "http://127.0.0.1") is True


def test_internal_target_accepts_system_admin_wildcard_scope():
    # Tenant analyst cannot receive wildcard scope
    with pytest.raises(ValueError, match="SYSTEM_PRINCIPAL with ADMIN role"):
        UserProfile(
            username="analyst", email="analyst@example.test", role=UserRole.SECURITY_ANALYST,
            scopes=["*"]
        )

    # Only SYSTEM_PRINCIPAL + ADMIN may possess wildcard scope
    sys_admin = UserProfile(
        username="sys-admin", email="sysadmin@example.test", role=UserRole.ADMIN,
        principal_type=PrincipalType.SYSTEM_PRINCIPAL,
        scopes=["*"]
    )
    assert authorize_internal_target(sys_admin, "http://127.0.0.1") is True


@pytest.mark.asyncio
async def test_asset_registration_requires_internal_scope_even_for_admin_role():
    from fastapi import HTTPException

    admin_without_scope = UserProfile(
        username="admin", email="admin@example.test", role=UserRole.ADMIN,
        scopes=["asset:write"], organization_id="org-internal-test",
    )
    payload = CreateAssetRequest(
        name="Internal host", type="IP_ADDRESS", target_value="192.168.1.50",
    )

    with pytest.raises(HTTPException) as exc_info:
        await create_asset(payload, admin_without_scope)
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_live_secret_verification_grant_requires_organization_admin():
    from fastapi import HTTPException

    analyst = UserProfile(
        username="analyst", email="analyst@example.test", role=UserRole.SECURITY_ANALYST,
        scopes=["asset:write"], organization_id="org-secrets",
    )
    payload = CreateAssetRequest(
        name="Secret verification target",
        type="DOMAIN",
        target_value="example.com",
        live_secret_verification_granted=True,
    )

    with pytest.raises(HTTPException) as exc_info:
        await create_asset(payload, analyst)
    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_scan_start_requires_internal_scope_even_for_admin_role(monkeypatch):
    from starlette.requests import Request
    from fastapi import HTTPException
    from types import SimpleNamespace
    from app.api import scans
    from app.core.models import AssetType

    admin_without_scope = UserProfile(
        username="admin", email="admin@example.test", role=UserRole.ADMIN,
        scopes=["scan:create"], organization_id="org-internal-test",
    )
    monkeypatch.setattr(
        scans.db_manager,
        "get_asset",
        lambda *args, **kwargs: SimpleNamespace(
            id="asset-internal-test",
            organization_id="org-internal-test",
            project_id=None,
            type=AssetType.IP_ADDRESS,
            target_value="192.168.1.50",
        ),
    )
    payload = StartScanRequest(
        target_type="IP",
        target_value="192.168.1.50",
        asset_id="asset-internal-test",
        enabled_engines=[],
    )
    request = Request({
        "type": "http", "method": "POST", "path": "/api/scans/start",
        "headers": [], "query_string": b"", "server": ("test", 80),
        "scheme": "http", "client": ("127.0.0.1", 1),
    })

    with pytest.raises(HTTPException) as exc_info:
        await start_security_scan(
            payload,
            request,
            idempotency_key="internal-scope-test",
            current_user=admin_without_scope,
        )
    assert exc_info.value.status_code == 400
