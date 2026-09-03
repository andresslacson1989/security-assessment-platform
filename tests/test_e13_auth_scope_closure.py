"""
E13.1 — Adversarial Acceptance Tests for Identity & Scope Closure
Validates zero-trust RBAC, least privilege, absence of wildcard escalation,
and strict RFC 8725 JWT algorithm binding.
"""

import base64
import hashlib
import json
import time
import pytest
import jwt
from fastapi import HTTPException
from starlette.requests import Request

from app.core.auth import (
    create_access_token,
    decode_access_token,
    resolve_effective_scopes,
    get_current_user,
    require_permission,
    authorize_internal_target,
    JWT_SECRET,
    ACTIVE_KEY_ID,
)
from app.core.models import (
    UserProfile,
    UserRole,
    PrincipalType,
    APIKeyRecord,
    utc_now,
)
from app.api.auth import (
    LoginRequest,
    login,
    CreateAPIKeyRequest,
    create_api_key,
)
from app.core.db import db_manager


def _make_mock_request(client_host: str = "127.0.0.1") -> Request:
    return Request({
        "type": "http",
        "method": "POST",
        "path": "/api/auth/login",
        "headers": [],
        "query_string": b"",
        "server": ("test", 80),
        "scheme": "http",
        "client": (client_host, 12345),
    })


@pytest.fixture(autouse=True)
def ensure_db():
    db_manager._init_db()


@pytest.mark.asyncio
async def test_1_viewer_login_does_not_receive_wildcard():
    """Test 1: Normal viewer login does not receive wildcard."""
    viewer = UserProfile(
        id="usr-test-viewer",
        username="test_viewer_e13",
        email="viewer@test.local",
        role=UserRole.VIEWER,
        principal_type=PrincipalType.TENANT_PRINCIPAL,
    )
    with db_manager._connection_scope() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
            (viewer.id, viewer.username, viewer.email, "pbkdf2_sha256$100000$salt$hash", viewer.role.value, viewer.organization_id, utc_now().isoformat()),
        )
    scopes = resolve_effective_scopes(viewer)
    assert "*" not in scopes
    assert "scan:read" in scopes
    assert "scan:create" not in scopes
    assert "scan:internal" not in scopes

    token = create_access_token(viewer)
    payload = decode_access_token(token)
    assert "*" not in payload.get("scopes", [])
    assert "scan:internal" not in payload.get("scopes", [])


@pytest.mark.asyncio
async def test_2_security_analyst_login_does_not_receive_wildcard():
    """Test 2: Security analyst login does not receive wildcard."""
    analyst = UserProfile(
        id="usr-test-analyst",
        username="test_analyst_e13",
        email="analyst@test.local",
        role=UserRole.SECURITY_ANALYST,
        principal_type=PrincipalType.TENANT_PRINCIPAL,
    )
    scopes = resolve_effective_scopes(analyst)
    assert "*" not in scopes
    assert "scan:repeater" in scopes
    assert "scan:create" in scopes
    assert "scan:internal" not in scopes
    assert "tool:install" not in scopes

    token = create_access_token(analyst)
    payload = decode_access_token(token)
    assert "*" not in payload.get("scopes", [])
    assert "scan:internal" not in payload.get("scopes", [])


@pytest.mark.asyncio
async def test_3_developer_login_does_not_receive_wildcard():
    """Test 3: Developer login does not receive wildcard."""
    dev = UserProfile(
        id="usr-test-dev",
        username="test_dev_e13",
        email="dev@test.local",
        role=UserRole.DEVELOPER,
        principal_type=PrincipalType.TENANT_PRINCIPAL,
    )
    scopes = resolve_effective_scopes(dev)
    assert "*" not in scopes
    assert "scan:create" in scopes
    assert "finding:triage" in scopes
    assert "scan:repeater" not in scopes
    assert "scan:internal" not in scopes
    assert "asset:delete" not in scopes

    token = create_access_token(dev)
    payload = decode_access_token(token)
    assert "*" not in payload.get("scopes", [])
    assert "scan:internal" not in payload.get("scopes", [])


@pytest.mark.asyncio
async def test_4_tenant_admin_login_does_not_receive_system_wildcard():
    """Test 4: Tenant admin login does not receive system wildcard."""
    tenant_admin = UserProfile(
        id="usr-test-tenant-admin",
        username="test_tenant_admin_e13",
        email="admin@tenant.local",
        role=UserRole.ADMIN,
        principal_type=PrincipalType.TENANT_PRINCIPAL,
    )
    scopes = resolve_effective_scopes(tenant_admin)
    assert "*" not in scopes
    assert "scan:create" in scopes
    assert "tool:install" in scopes
    assert "scan:internal" not in scopes  # scan:internal is NOT granted by default to tenant admin

    token = create_access_token(tenant_admin)
    payload = decode_access_token(token)
    assert "*" not in payload.get("scopes", [])
    assert "scan:internal" not in payload.get("scopes", [])


def test_5_only_system_principal_admin_may_receive_wildcard():
    """Test 5: Only system-principal admin may receive wildcard, if supported."""
    sys_admin = UserProfile(
        id="usr-sys-admin",
        username="system_admin",
        email="root@platform.local",
        role=UserRole.ADMIN,
        principal_type=PrincipalType.SYSTEM_PRINCIPAL,
        scopes=["*"],
    )
    scopes = resolve_effective_scopes(sys_admin)
    assert scopes == ["*"]

    token = create_access_token(sys_admin)
    payload = decode_access_token(token)
    assert payload.get("scopes") == ["*"]

    # Model-level validation rejects tenant principal with wildcard
    with pytest.raises(ValueError, match="SYSTEM_PRINCIPAL with ADMIN role"):
        UserProfile(
            username="bad_tenant",
            email="bad@tenant.local",
            role=UserRole.ADMIN,
            principal_type=PrincipalType.TENANT_PRINCIPAL,
            scopes=["*"],
        )

    # Model-level validation rejects non-admin system principal with wildcard
    with pytest.raises(ValueError, match="SYSTEM_PRINCIPAL with ADMIN role"):
        UserProfile(
            username="bad_sys_viewer",
            email="viewer@platform.local",
            role=UserRole.VIEWER,
            principal_type=PrincipalType.SYSTEM_PRINCIPAL,
            scopes=["*"],
        )


@pytest.mark.asyncio
async def test_6_jwt_missing_scopes_never_becomes_wildcard():
    """Test 6: JWT missing scopes never becomes wildcard."""
    # Craft token without 'scopes' claim
    now = int(time.time())
    payload = {
        "iss": "CyberAssess-Control-Plane",
        "aud": "CyberAssess-Platform",
        "sub": "usr-test-viewer",
        "username": "test_viewer_e13",
        "email": "viewer@test.local",
        "role": "VIEWER",
        "principal_type": "TENANT_PRINCIPAL",
        "org_id": "org-default",
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        "jti": "jti-test-missing-scopes",
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256", headers={"typ": "JWT", "kid": ACTIVE_KEY_ID})
    
    # Reconstruct user via get_current_user
    resolved_user = await get_current_user(authorization=f"Bearer {token}")
    assert "*" not in resolved_user.scopes
    assert resolved_user.scopes == resolve_effective_scopes(resolved_user)


@pytest.mark.asyncio
async def test_7_unknown_or_malformed_scopes_fail_closed():
    """Test 7: Unknown/malformed scopes fail closed."""
    now = int(time.time())
    
    # Non-list scopes claim fails closed
    payload_bad_type = {
        "iss": "CyberAssess-Control-Plane",
        "aud": "CyberAssess-Platform",
        "sub": "usr-test-viewer",
        "username": "viewer",
        "role": "VIEWER",
        "principal_type": "TENANT_PRINCIPAL",
        "org_id": "org-default",
        "scopes": "all_access",  # String instead of list
        "iat": now, "nbf": now, "exp": now + 3600,
        "jti": "jti-bad-scopes-1",
    }
    token_bad = jwt.encode(payload_bad_type, JWT_SECRET, algorithm="HS256", headers={"typ": "JWT", "kid": ACTIVE_KEY_ID})
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(authorization=f"Bearer {token_bad}")
    assert exc_info.value.status_code == 401

    # Unknown scope strings are stripped and never escalated
    payload_unknown = {
        "iss": "CyberAssess-Control-Plane",
        "aud": "CyberAssess-Platform",
        "sub": "usr-unknown-scope",
        "username": "viewer",
        "role": "VIEWER",
        "principal_type": "TENANT_PRINCIPAL",
        "org_id": "org-default",
        "scopes": ["unknown:scope:superadmin", "*"],
        "iat": now, "nbf": now, "exp": now + 3600,
        "jti": "jti-bad-scopes-2",
    }
    token_unknown = jwt.encode(payload_unknown, JWT_SECRET, algorithm="HS256", headers={"typ": "JWT", "kid": ACTIVE_KEY_ID})
    user = await get_current_user(authorization=f"Bearer {token_unknown}")
    assert "*" not in user.scopes
    assert "unknown:scope:superadmin" not in user.scopes


@pytest.mark.asyncio
async def test_8_api_key_cannot_exceed_caller_permissions():
    """Test 8: API key cannot exceed caller permissions."""
    # Caller is an analyst with read and scan scopes, but NOT scan:internal
    analyst = UserProfile(
        id="usr-analyst-delegate",
        username="analyst_delegate",
        email="analyst@tenant.local",
        role=UserRole.SECURITY_ANALYST,
        principal_type=PrincipalType.TENANT_PRINCIPAL,
        organization_id="org-test-delegation",
    )
    analyst.scopes = resolve_effective_scopes(analyst)
    assert "scan:internal" not in analyst.scopes

    # Requesting scan:internal when caller lacks it must be denied with 403
    request_payload = CreateAPIKeyRequest(
        name="Escalated Key",
        scopes=["scan:read", "scan:internal"],
    )
    with pytest.raises(HTTPException) as exc_info:
        await create_api_key(request_payload, analyst)
    assert exc_info.value.status_code == 403
    assert "cannot exceed" in exc_info.value.detail


@pytest.mark.asyncio
async def test_9_api_key_wildcard_request_is_rejected():
    """Test 9: API key wildcard request is rejected."""
    tenant_admin = UserProfile(
        id="usr-admin-wildcard-req",
        username="admin_wildcard_req",
        email="admin@tenant.local",
        role=UserRole.ADMIN,
        principal_type=PrincipalType.TENANT_PRINCIPAL,
    )
    tenant_admin.scopes = resolve_effective_scopes(tenant_admin)

    request_payload = CreateAPIKeyRequest(
        name="Wildcard Key",
        scopes=["*"],
    )
    with pytest.raises(HTTPException) as exc_info:
        await create_api_key(request_payload, tenant_admin)
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_10_deactivated_user_fails_authorization():
    """Test 10: Deactivated user still fails authorization."""
    user = UserProfile(
        id="usr-deactivated",
        username="deactivated_user",
        email="deact@tenant.local",
        role=UserRole.SECURITY_ANALYST,
        principal_type=PrincipalType.TENANT_PRINCIPAL,
        is_active=False,
    )
    with db_manager._connection_scope() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
            (user.id, user.username, user.email, "hash", user.role.value, user.organization_id, utc_now().isoformat()),
        )

    token = create_access_token(user)
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(authorization=f"Bearer {token}")
    assert exc_info.value.status_code == 401
    assert "deactivated" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_11_algorithm_confusion_attempt_is_rejected():
    """Test 11: Algorithm confusion attempt is rejected (alg=none, RS256, unknown kid, missing kid)."""
    now = int(time.time())
    payload = {
        "iss": "CyberAssess-Control-Plane",
        "aud": "CyberAssess-Platform",
        "sub": "usr-attacker",
        "username": "attacker",
        "role": "ADMIN",
        "principal_type": "SYSTEM_PRINCIPAL",
        "scopes": ["*"],
        "iat": now, "nbf": now, "exp": now + 3600,
        "jti": "jti-confusion-1",
    }

    # 1. alg=none
    token_none = jwt.encode(payload, key="", algorithm="none")
    with pytest.raises(HTTPException) as exc_none:
        decode_access_token(token_none)
    assert exc_none.value.status_code == 401

    # 2. RS256 against HS256 store
    # Unsigned / forged RS256 header with valid-looking structure
    header_rs256 = base64.urlsafe_b64encode(json.dumps({"typ": "JWT", "alg": "RS256", "kid": ACTIVE_KEY_ID}).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    fake_token = f"{header_rs256}.{payload_b64}.fake_sig"
    with pytest.raises(HTTPException) as exc_rs:
        decode_access_token(fake_token)
    assert exc_rs.value.status_code == 401
    assert "Unsupported or forbidden token algorithm" in exc_rs.value.detail

    # 3. Missing kid
    token_no_kid = jwt.encode(payload, JWT_SECRET, algorithm="HS256", headers={"typ": "JWT"})
    with pytest.raises(HTTPException) as exc_no_kid:
        decode_access_token(token_no_kid)
    assert exc_no_kid.value.status_code == 401
    assert "key identifier" in exc_no_kid.value.detail

    # 4. Unknown kid
    token_bad_kid = jwt.encode(payload, JWT_SECRET, algorithm="HS256", headers={"typ": "JWT", "kid": "k-unknown-rogue"})
    with pytest.raises(HTTPException) as exc_bad_kid:
        decode_access_token(token_bad_kid)
    assert exc_bad_kid.value.status_code == 401
    assert "key identifier" in exc_bad_kid.value.detail
