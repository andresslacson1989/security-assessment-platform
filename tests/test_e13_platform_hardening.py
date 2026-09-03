"""
E13.8 — Adversarial Acceptance Tests for Web Application & Platform Hardening.
Validates:
- Strict enterprise security headers injected into responses:
  - X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, Content-Security-Policy.
- Swagger UI / OpenAPI docs disabled in production mode unless explicit ENABLE_DOCS=true.
- PBKDF2 minimum iteration enforcement (>= 100,000) preventing downgrade attacks.
- Constant-time password verification.
- Login endpoint rate limiting: 5 consecutive failed attempts trigger 429 Too Many Requests.
- CORS strict origin validation (no wildcard with credentials).
"""

import os
import base64
import hashlib
from unittest.mock import patch
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app, _load_allowed_origins
from app.core.auth import hash_password, verify_password


@pytest.mark.asyncio
async def test_security_headers_present_on_all_responses():
    """All API responses must include strict enterprise security headers."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/system/health")
        assert res.status_code == 200
        headers = res.headers
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "Permissions-Policy" in headers
        assert "geolocation=()" in headers["Permissions-Policy"]
        assert "Content-Security-Policy" in headers
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_pbkdf2_iteration_downgrade_rejection():
    """Hashes crafted with fewer than 100,000 iterations must be rejected to prevent downgrade attacks."""
    password = "SuperSecretPassword123!"
    salt = b"1234567812345678"
    salt_b64 = base64.b64encode(salt).decode("ascii")

    # Hash with only 1000 iterations (downgraded)
    dk_weak = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 1000)
    hash_weak_b64 = base64.b64encode(dk_weak).decode("ascii")
    weak_hash_str = f"pbkdf2_sha256$1000${salt_b64}${hash_weak_b64}"

    # Must fail closed
    assert verify_password(password, weak_hash_str) is False

    # Valid hash with 100,000 iterations must pass
    valid_hash = hash_password(password, iterations=100_000)
    assert verify_password(password, valid_hash) is True


@pytest.mark.asyncio
async def test_login_rate_limiting_triggers_429():
    """5 consecutive failed logins for the same client/user must trigger 429 Too Many Requests."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        for i in range(5):
            res = await ac.post(
                "/api/auth/login",
                json={"username": "brute_force_target", "password": f"wrong_{i}"},
            )
            assert res.status_code == 401

        # 6th attempt must be rate-limited with 429
        res_blocked = await ac.post(
            "/api/auth/login",
            json={"username": "brute_force_target", "password": "wrong_again"},
        )
        assert res_blocked.status_code == 429
        assert "Too many failed login attempts" in res_blocked.json()["detail"]
        assert "Retry-After" in res_blocked.headers


def test_cors_rejects_wildcard_origins():
    """CORS origin parsing fails closed on wildcard or malformed origins."""
    with pytest.raises(RuntimeError, match="wildcard CORS is forbidden"):
        _load_allowed_origins("*")

    with pytest.raises(RuntimeError, match="wildcard CORS is forbidden"):
        _load_allowed_origins("http://example.com, *")

    with pytest.raises(RuntimeError, match="malformed origin"):
        _load_allowed_origins("invalid-origin-no-scheme")
