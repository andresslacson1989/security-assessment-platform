"""Adversarial coverage for tenant-admin and system-principal administration boundaries."""

from __future__ import annotations

import pytest

from app.api.auth import CreateUserRequest, create_user
from app.api.assets import CreateAssetRequest, create_asset
from app.api.scans import StartScanRequest, start_security_scan
from app.core.auth import UserProfile, authorize_internal_target
from app.core.models import PrincipalType, UserRole


@pytest.mark.asyncio
async def test_tenant_admin_cannot_create_user_in_another_organization():
    tenant_admin = UserProfile(
        username="tenant-admin", email="tenant@example.test", role=UserRole.ADMIN,
        principal_type=PrincipalType.TENANT_PRINCIPAL, organization_id="org-one",
    )
    payload = CreateUserRequest(
        username="cross-tenant", email="cross@example.test", password="StrongPassphrase123!",
        organization_id="org-two",
    )

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await create_user(payload, tenant_admin)
    assert exc_info.value.status_code == 403


def test_internal_target_requires_explicit_scope_even_for_admin_role_object():
    admin_without_scope = UserProfile(
        username="admin", email="admin@example.test", role=UserRole.ADMIN,
        scopes=["scan:repeater"],
    )
    admin_with_scope = admin_without_scope.model_copy(update={"scopes": ["scan:repeater", "scan:internal"]})

    assert authorize_internal_target(admin_without_scope, "http://192.168.1.10") is False
    assert authorize_internal_target(admin_with_scope, "http://192.168.1.10") is True


def test_tenant_analyst_wildcard_claim_is_not_internal_authority():
    analyst = UserProfile(
        username="analyst", email="analyst@example.test", role=UserRole.SECURITY_ANALYST,
        scopes=["*"]
    )

    assert authorize_internal_target(analyst, "http://192.168.1.10") is False


@pytest.mark.asyncio
async def test_private_asset_can_be_registered_without_granting_execution_authority():
    admin_without_scope = UserProfile(
        username="admin", email="admin@example.test", role=UserRole.ADMIN,
        scopes=["asset:write"], organization_id="org-internal-test",
    )
    payload = CreateAssetRequest(
        name="Internal host", type="IP_ADDRESS", target_value="192.168.1.50",
    )

    asset = await create_asset(payload, admin_without_scope)
    assert asset.target_value == "192.168.1.50"
    assert asset.active_probing_granted is False


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
async def test_scan_start_requires_internal_scope_even_for_admin_role_object():
    from starlette.requests import Request
    from fastapi import HTTPException

    admin_without_scope = UserProfile(
        username="admin", email="admin@example.test", role=UserRole.ADMIN,
        scopes=["scan:create"], organization_id="org-internal-test",
    )
    payload = StartScanRequest(target_type="IP", target_value="192.168.1.50", enabled_engines=[])
    request = Request({
        "type": "http", "method": "POST", "path": "/api/scans/start",
        "headers": [], "query_string": b"", "server": ("test", 80),
        "scheme": "http", "client": ("127.0.0.1", 1),
    })

    with pytest.raises(HTTPException) as exc_info:
        await start_security_scan(payload, request, admin_without_scope)
    assert exc_info.value.status_code == 400
