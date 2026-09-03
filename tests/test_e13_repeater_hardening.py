"""
E13.5 — Adversarial Acceptance Tests for Repeater Resource and TLS Evidence Hardening.
Validates:
- Repeater SSRF Protection:
  - Loopback (127.0.0.1, localhost) always rejected, even for System Admin.
  - Cloud metadata (169.254.169.254) always rejected, even for System Admin.
  - RFC1918 Private IP rejected without explicit scan:internal scope.
  - RFC1918 Private IP allowed with explicit scan:internal scope.
- Bounded Streaming & Truncation:
  - Streaming reads with 5 MB bound, setting truncated=True.
- Robust Binary Handling:
  - Invalid UTF-8 / binary payload handled gracefully without crash (is_binary=True).
- Truthful TLS Evidence:
  - Plain HTTP produces tls_version=None, cipher=None, tls_verified=None.
  - No synthetic TLSv1.3 default.
"""

from unittest.mock import patch, AsyncMock
import pytest
from httpx import AsyncClient, ASGITransport, Response

from app.main import app
from app.core.models import UserProfile, UserRole, PrincipalType
from app.core.auth import create_access_token


@pytest.fixture
def admin_token():
    user = UserProfile(
        id="usr-admin-sys",
        username="sysadmin",
        email="sysadmin@cyberassess.local",
        role=UserRole.ADMIN,
        principal_type=PrincipalType.SYSTEM_PRINCIPAL,
        scopes=["*"],
    )
    return create_access_token(user)


@pytest.fixture
def analyst_token_no_internal():
    user = UserProfile(
        id="usr-analyst-external",
        username="external_analyst",
        email="analyst@sec.local",
        role=UserRole.SECURITY_ANALYST,
        principal_type=PrincipalType.TENANT_PRINCIPAL,
        scopes=["scan:repeater", "scan:read", "scan:write"],
    )
    return create_access_token(user)


@pytest.fixture
def analyst_token_with_internal():
    user = UserProfile(
        id="usr-analyst-internal",
        username="internal_analyst",
        email="internal_analyst@sec.local",
        role=UserRole.SECURITY_ANALYST,
        principal_type=PrincipalType.TENANT_PRINCIPAL,
        scopes=["scan:repeater", "scan:internal", "scan:read", "scan:write"],
    )
    return create_access_token(user)


@pytest.mark.asyncio
async def test_repeater_rejects_loopback_for_all_users(admin_token, analyst_token_with_internal):
    """Repeater must reject 127.0.0.1 and localhost for all callers including system admin."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        for token in [admin_token, analyst_token_with_internal]:
            for target in ["http://127.0.0.1:8080/admin", "http://localhost:8080/test"]:
                res = await ac.post(
                    "/api/tools/repeater",
                    json={"url": target, "method": "GET"},
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert res.status_code == 400
                assert "SSRF Protection Gate" in res.json()["detail"]


@pytest.mark.asyncio
async def test_repeater_rejects_cloud_metadata_for_all_users(admin_token, analyst_token_with_internal):
    """Repeater must reject 169.254.169.254 for all callers including system admin."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        for token in [admin_token, analyst_token_with_internal]:
            res = await ac.post(
                "/api/tools/repeater",
                json={"url": "http://169.254.169.254/latest/meta-data/", "method": "GET"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert res.status_code == 400
            assert "SSRF Protection Gate" in res.json()["detail"]


@pytest.mark.asyncio
async def test_repeater_rejects_private_ip_without_internal_scope(analyst_token_no_internal):
    """Caller without scan:internal scope must be denied access to private IPs."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        for private_url in ["http://10.0.0.1:8080/api", "http://192.168.1.1:80/status"]:
            res = await ac.post(
                "/api/tools/repeater",
                json={"url": private_url, "method": "GET"},
                headers={"Authorization": f"Bearer {analyst_token_no_internal}"},
            )
            assert res.status_code == 400
            assert "SSRF Protection Gate" in res.json()["detail"]


@pytest.mark.asyncio
async def test_repeater_allows_private_ip_with_internal_scope(analyst_token_with_internal):
    """Caller with scan:internal scope passes SSRF gate for private IPs."""
    mock_resp = Response(
        status_code=200,
        headers={"content-type": "text/plain"},
        content=b"internal service online",
    )
    with patch("app.core.ssrf_protector.ValidatedTargetTransport.handle_async_request", new=AsyncMock(return_value=mock_resp)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res = await ac.post(
                "/api/tools/repeater",
                json={"url": "http://192.168.1.100:8080/api/status", "method": "GET"},
                headers={"Authorization": f"Bearer {analyst_token_with_internal}"},
            )
            assert res.status_code == 200
            data = res.json()
            assert data["status_code"] == 200
            assert "internal service online" in data["body"]


@pytest.mark.asyncio
async def test_repeater_truncates_large_streamed_response(admin_token):
    """Repeater streams responses and truncates payloads exceeding 5 MB limit."""
    # Create 6 MB content
    large_bytes = b"A" * (6 * 1024 * 1024)
    mock_resp = Response(
        status_code=200,
        headers={"content-type": "text/plain"},
        content=large_bytes,
    )

    with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]), \
         patch("app.core.ssrf_protector.ValidatedTargetTransport.handle_async_request", new=AsyncMock(return_value=mock_resp)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res = await ac.post(
                "/api/tools/repeater",
                json={"url": "https://example.com/bigfile.bin", "method": "GET"},
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert res.status_code == 200
            data = res.json()
            assert data["truncated"] is True
            assert data["content_length"] == 5 * 1024 * 1024
            assert "Response Truncated" in data["body"]


@pytest.mark.asyncio
async def test_repeater_handles_binary_content_gracefully(admin_token):
    """Repeater safely handles non-UTF8 binary data with base64 preview without crashing."""
    binary_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xfe\xfd\xfc"
    mock_resp = Response(
        status_code=200,
        headers={"content-type": "image/png"},
        content=binary_bytes,
    )

    with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]), \
         patch("app.core.ssrf_protector.ValidatedTargetTransport.handle_async_request", new=AsyncMock(return_value=mock_resp)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res = await ac.post(
                "/api/tools/repeater",
                json={"url": "https://example.com/logo.png", "method": "GET"},
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert res.status_code == 200
            data = res.json()
            assert data["is_binary"] is True
            assert "[Binary payload" in data["body"]
            assert "preview (base64)" in data["body"]


@pytest.mark.asyncio
async def test_repeater_plain_http_produces_none_tls_evidence(admin_token):
    """Plain HTTP request must not claim or synthesize TLS information."""
    mock_resp = Response(
        status_code=200,
        headers={"content-type": "text/plain"},
        content=b"plain http hello",
    )

    with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]), \
         patch("app.core.ssrf_protector.ValidatedTargetTransport.handle_async_request", new=AsyncMock(return_value=mock_resp)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res = await ac.post(
                "/api/tools/repeater",
                json={"url": "http://example.com/plain", "method": "GET"},
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert res.status_code == 200
            data = res.json()
            assert data["tls_version"] is None
            assert data["cipher"] is None
            assert data["tls_verified"] is None


@pytest.mark.asyncio
async def test_repeater_https_no_synthetic_tls_default(admin_token):
    """HTTPS request where TLS extensions are unavailable must not synthesize TLSv1.3."""
    mock_resp = Response(
        status_code=200,
        headers={"content-type": "text/plain"},
        content=b"secure hello",
    )
    # No extensions attribute on mock_resp
    with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]), \
         patch("app.core.ssrf_protector.ValidatedTargetTransport.handle_async_request", new=AsyncMock(return_value=mock_resp)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res = await ac.post(
                "/api/tools/repeater",
                json={"url": "https://example.com/secure", "method": "GET"},
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert res.status_code == 200
            data = res.json()
            assert data["tls_version"] is None
            assert data["cipher"] is None
            assert data["tls_verified"] is True


@pytest.mark.asyncio
async def test_repeater_rejects_payload_exceeding_byte_limit_even_if_char_count_is_small(admin_token):
    """
    R2.2 Invariant:
    Payload with character count < 2,000,000 but UTF-8 byte count > 2,097,152 bytes
    MUST be rejected before outbound transmission with HTTP 400.
    """
    # 700,000 4-byte unicode emojis: len(char_string) = 700,000 (< 2,000,000)
    # len(utf8_bytes) = 2,800,000 (> 2,097,152 bytes = 2 MB)
    large_unicode_body = "\U0001F600" * 700000
    assert len(large_unicode_body) < 2000000
    assert len(large_unicode_body.encode("utf-8")) > 2 * 1024 * 1024

    with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
        with patch("app.core.ssrf_protector.ValidatedTargetTransport.handle_async_request") as mock_send:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                res = await ac.post(
                    "/api/tools/repeater",
                    json={
                        "url": "https://example.com/test",
                        "method": "POST",
                        "body": large_unicode_body,
                    },
                    headers={"Authorization": f"Bearer {admin_token}"},
                )
                assert res.status_code == 400
                assert "2 MB" in res.json()["detail"]
                # Outbound request must NOT have been sent
                mock_send.assert_not_called()

