"""Adversarial coverage for tenant-admin and system-principal administration boundaries."""

from __future__ import annotations

import pytest

from app.api.auth import CreateUserRequest, create_user
from app.core.auth import UserProfile, authorize_internal_target
from app.core.models import PrincipalType, UserRole


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


def test_internal_target_accepts_explicit_wildcard_scope():
    analyst = UserProfile(
        username="analyst", email="analyst@example.test", role=UserRole.SECURITY_ANALYST,
        scopes=["*"]
    )

    assert authorize_internal_target(analyst, "http://127.0.0.1") is True
