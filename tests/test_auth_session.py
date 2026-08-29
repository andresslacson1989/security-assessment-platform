"""
Unit test suite for Authentication & Session Manager and Form Auditor (Contract 01, 03, 06, 08).
"""

from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest

from app.core.models import (
    AuthConfig,
    AuthType,
    DiscoveredEndpoint,
    Severity,
)
from app.engines.web_dast.auth_session import AuthSessionManager


@pytest.mark.asyncio
async def test_header_and_cookie_auth():
    client = httpx.AsyncClient()

    # 1. Header Auth
    hdr_mgr = AuthSessionManager(
        target_url="https://example.com",
        config=AuthConfig(
            auth_type=AuthType.HEADER,
            headers={"Authorization": "Bearer sample-jwt-token"},
        ),
        client=client,
    )
    assert await hdr_mgr.authenticate() is True
    assert client.headers.get("Authorization") == "Bearer sample-jwt-token"
    assert hdr_mgr.is_authenticated is True

    # 2. Cookie Auth
    cookie_mgr = AuthSessionManager(
        target_url="https://example.com",
        config=AuthConfig(
            auth_type=AuthType.COOKIE,
            cookies={"sessionid": "sess_abc123"},
        ),
        client=client,
    )
    assert await cookie_mgr.authenticate() is True
    assert client.cookies.get("sessionid") == "sess_abc123"
    assert cookie_mgr.is_authenticated is True


@pytest.mark.asyncio
async def test_form_login_success_and_csrf_extraction():
    mock_client = AsyncMock()

    # Mock GET login page returning CSRF token
    get_resp = MagicMock(spec=httpx.Response)
    get_resp.status_code = 200
    get_resp.headers = {"content-type": "text/html"}
    get_resp.text = """
    <html>
      <body>
        <form action="/login" method="POST">
          <input type="hidden" name="_csrf" value="csrf_token_secret_xyz">
          <input type="text" name="username">
          <input type="password" name="password">
          <button type="submit">Log In</button>
        </form>
      </body>
    </html>
    """

    # Mock POST response confirming login
    post_resp = MagicMock(spec=httpx.Response)
    post_resp.status_code = 200
    post_resp.headers = {"content-type": "text/html"}
    post_resp.text = "<html><body>Welcome, admin user!</body></html>"

    mock_client.get = AsyncMock(return_value=get_resp)
    mock_client.post = AsyncMock(return_value=post_resp)

    mgr = AuthSessionManager(
        target_url="https://example.com",
        config=AuthConfig(
            auth_type=AuthType.FORM_LOGIN,
            login_url="https://example.com/login",
            username="admin",
            password="secretpassword",
            csrf_token_field="_csrf",
            logged_in_indicator="Welcome, admin user!",
        ),
        client=mock_client,
    )

    success = await mgr.authenticate()
    assert success is True
    assert mgr.is_authenticated is True

    # Verify POST payload contained username, password, and extracted CSRF token
    mock_client.post.assert_called_once()
    posted_data = mock_client.post.call_args[1]["data"]
    assert posted_data["username"] == "admin"
    assert posted_data["password"] == "secretpassword"
    assert posted_data["_csrf"] == "csrf_token_secret_xyz"


@pytest.mark.asyncio
async def test_dast_auth_001_cleartext_login():
    mgr = AuthSessionManager(
        target_url="http://insecure.example.com",
        config=AuthConfig(
            auth_type=AuthType.FORM_LOGIN,
            login_url="http://insecure.example.com/login",
            username="admin",
            password="password",
        ),
        client=AsyncMock(),
    )

    findings = await mgr.audit_auth_and_forms(
        discovered_endpoints=[],
        html_contents={},
    )

    check_ids = [f.check_id for f in findings]
    assert "DAST-AUTH-001" in check_ids
    auth_finding = next(f for f in findings if f.check_id == "DAST-AUTH-001")
    assert auth_finding.severity == Severity.HIGH
    assert "insecure.example.com" in auth_finding.evidence.location


@pytest.mark.asyncio
async def test_dast_auth_002_insecure_session_cookies():
    client = httpx.AsyncClient()
    # Set mock cookie without HttpOnly and without Secure
    client.cookies.set("auth_session", "session_token_12345", domain="example.com", path="/")

    mgr = AuthSessionManager(
        target_url="https://example.com",
        config=AuthConfig(auth_type=AuthType.COOKIE),
        client=client,
    )
    mgr.is_authenticated = True

    findings = await mgr.audit_auth_and_forms(
        discovered_endpoints=[],
        html_contents={},
    )

    check_ids = [f.check_id for f in findings]
    assert "DAST-AUTH-002" in check_ids


@pytest.mark.asyncio
async def test_dast_auth_003_broken_access_control():
    mock_unauth_resp = MagicMock(spec=httpx.Response)
    mock_unauth_resp.status_code = 200
    mock_unauth_resp.text = """
    <!DOCTYPE html>
    <html lang="en">
      <head><title>Admin Executive Dashboard</title></head>
      <body>
        <h1>Admin Control Panel & System Metrics</h1>
        <p>Confidential corporate user management records and financial transactions.</p>
        <div class="stats-panel">Active Sessions: 4,812</div>
      </body>
    </html>
    """

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_unauth_resp):
        mgr = AuthSessionManager(
            target_url="https://example.com",
            config=AuthConfig(auth_type=AuthType.HEADER, headers={"Authorization": "Bearer token"}),
            client=AsyncMock(),
        )

        endpoints = [
            DiscoveredEndpoint(url="https://example.com/admin/dashboard", depth=1, is_authenticated=True),
        ]

        findings = await mgr.audit_auth_and_forms(
            discovered_endpoints=endpoints,
            html_contents={},
        )

        check_ids = [f.check_id for f in findings]
        assert "DAST-AUTH-003" in check_ids


@pytest.mark.asyncio
async def test_dast_auth_004_sensitive_query_strings():
    mgr = AuthSessionManager(
        target_url="https://example.com",
        config=AuthConfig(auth_type=AuthType.NONE),
        client=AsyncMock(),
    )

    endpoints = [
        DiscoveredEndpoint(url="https://example.com/api/data?token=supersecretjwttoken123456&user=alice", depth=1),
    ]

    findings = await mgr.audit_auth_and_forms(
        discovered_endpoints=endpoints,
        html_contents={},
    )

    check_ids = [f.check_id for f in findings]
    assert "DAST-AUTH-004" in check_ids
    f = next(f for f in findings if f.check_id == "DAST-AUTH-004")
    # Verify secret is masked in evidence
    assert "supersecretjwttoken123456" not in f.evidence.observed_value
    assert "*" in f.evidence.observed_value


@pytest.mark.asyncio
async def test_dast_form_001_cleartext_form_action():
    mgr = AuthSessionManager(
        target_url="https://example.com",
        config=AuthConfig(auth_type=AuthType.NONE),
        client=AsyncMock(),
    )

    html_content = {
        "https://example.com/checkout": """
        <html>
          <body>
            <form action="http://payment.example.com/process" method="POST">
              <input type="text" name="cc">
            </form>
          </body>
        </html>
        """
    }

    findings = await mgr.audit_auth_and_forms(
        discovered_endpoints=[],
        html_contents=html_content,
    )

    check_ids = [f.check_id for f in findings]
    assert "DAST-FORM-001" in check_ids


@pytest.mark.asyncio
async def test_dast_form_002_missing_csrf_token():
    mgr = AuthSessionManager(
        target_url="https://example.com",
        config=AuthConfig(auth_type=AuthType.NONE),
        client=AsyncMock(),
    )

    html_content = {
        "https://example.com/profile": """
        <html>
          <body>
            <form action="/update-email" method="POST">
              <input type="text" name="email">
              <button type="submit">Update</button>
            </form>
          </body>
        </html>
        """
    }

    findings = await mgr.audit_auth_and_forms(
        discovered_endpoints=[],
        html_contents=html_content,
    )

    check_ids = [f.check_id for f in findings]
    assert "DAST-FORM-002" in check_ids
