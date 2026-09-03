"""Adversarial assurance for the 2026-09-03 authentication audit closure."""

from __future__ import annotations

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from app.core.auth import (
    ALLOWED_JWT_ALGORITHMS,
    JWT_ALGORITHM,
    JWT_AUDIENCE,
    JWT_ISSUER,
    JWT_KEY_ROTATION_STORE,
    MIN_SINGLE_FACTOR_PASSWORD_LENGTH,
    PBKDF2_SHA256_ITERATIONS,
    create_access_token,
    decode_access_token,
    hash_password,
    scopes_for_user,
    validate_password_strength,
    verify_password,
)
from app.core.models import PrincipalType, UserProfile, UserRole


def _user(role: UserRole, *, principal_type: PrincipalType = PrincipalType.TENANT_PRINCIPAL) -> UserProfile:
    return UserProfile(
        id=f"usr-{role.value.lower()}",
        username=f"{role.value.lower()}-user",
        email=f"{role.value.lower()}@example.test",
        role=role,
        principal_type=principal_type,
        organization_id="org-one",
        scopes=[],
    )


def test_non_admin_tenant_roles_never_inherit_wildcard_or_internal_scan_scope():
    for role in (UserRole.VIEWER, UserRole.DEVELOPER, UserRole.SECURITY_ANALYST):
        scopes = scopes_for_user(_user(role))
        assert "*" not in scopes
        assert "scan:internal" not in scopes


def test_tenant_admin_has_explicit_internal_scope_but_not_wildcard():
    scopes = scopes_for_user(_user(UserRole.ADMIN))
    assert "*" not in scopes
    assert "scan:internal" in scopes


def test_only_system_admin_receives_wildcard_session_authority():
    system_admin = _user(UserRole.ADMIN, principal_type=PrincipalType.SYSTEM_PRINCIPAL)
    assert scopes_for_user(system_admin) == ["*"]


def test_new_password_policy_and_hash_work_factor_match_enterprise_baseline():
    valid_password = "correct horse battery staple"
    valid, reason = validate_password_strength(valid_password)
    assert valid is True, reason
    assert MIN_SINGLE_FACTOR_PASSWORD_LENGTH == 15

    encoded = hash_password(valid_password)
    algorithm, iteration_text, *_ = encoded.split("$")
    assert algorithm == "pbkdf2_sha256"
    assert int(iteration_text) >= PBKDF2_SHA256_ITERATIONS
    assert PBKDF2_SHA256_ITERATIONS >= 600_000
    assert verify_password(valid_password, encoded) is True


def test_legacy_pbkdf2_hashes_remain_verifiable_during_migration():
    import base64
    import hashlib

    password = "legacy-password-value"
    salt = b"0123456789abcdef"
    iterations = 100_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    encoded = "pbkdf2_sha256$%d$%s$%s" % (
        iterations,
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )
    assert verify_password(password, encoded) is True


def test_mixed_algorithm_verification_is_not_enabled():
    assert JWT_ALGORITHM == "HS256"
    assert ALLOWED_JWT_ALGORITHMS == ["HS256"]


def test_rs256_header_is_rejected_before_key_family_confusion(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(
        {
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "sub": "usr-rsa",
            "exp": 4_102_444_800,
            "iat": 1_700_000_000,
            "nbf": 1_700_000_000,
            "jti": "rsa-not-accepted",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": next(iter(JWT_KEY_ROTATION_STORE)), "typ": "JWT"},
    )
    with pytest.raises(HTTPException) as exc_info:
        decode_access_token(token)
    assert exc_info.value.status_code == 401
    assert "algorithm" in str(exc_info.value.detail).lower()


@pytest.mark.asyncio
async def test_analyst_cannot_delegate_internal_scan_scope_to_api_key(monkeypatch):
    import app.api.auth as auth_api

    analyst = _user(UserRole.SECURITY_ANALYST)
    analyst.scopes = scopes_for_user(analyst)
    request = auth_api.CreateAPIKeyRequest(name="forbidden-internal", scopes=["scan:internal"])

    with pytest.raises(HTTPException) as exc_info:
        await auth_api.create_api_key(request, current_user=analyst)
    assert exc_info.value.status_code == 403


def test_tenant_admin_token_contains_explicit_internal_but_no_wildcard_scope():
    admin = _user(UserRole.ADMIN)
    token = create_access_token(admin)
    payload = jwt.decode(token, options={"verify_signature": False})
    assert "*" not in payload["scopes"]
    assert "scan:internal" in payload["scopes"]
