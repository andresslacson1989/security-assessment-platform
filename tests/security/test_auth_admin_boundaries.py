"""Adversarial coverage for tenant-admin and system-principal administration boundaries."""

from __future__ import annotations

import pytest

from app.api.auth import CreateUserRequest, create_user
from app.core.auth import UserProfile
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
