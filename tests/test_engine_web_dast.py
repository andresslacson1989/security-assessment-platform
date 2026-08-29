"""
Unit tests for Engine 2: Web Application & API DAST.
"""

from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest

from app.core.models import Target, TargetType, ScanConfig, Severity
from app.engines.web_dast.headers_cookies import audit_security_headers_and_cookies
from app.engines.web_dast.cors_analyzer import audit_cors_policies
from app.engines.web_dast.api_inspector import audit_sensitive_exposure_and_methods
from app.engines.web_dast.browser_posture import audit_browser_posture
from app.engines.web_dast.graphql_auditor import audit_graphql_endpoints
from app.engines.web_dast.engine import WebDastAssessmentEngine


@pytest.mark.asyncio
async def test_headers_and_cookies_findings():
    # Mock HTTP response missing security headers and setting insecure cookies
    mock_client = AsyncMock()
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.headers = httpx.Headers({
        "server": "Apache/2.4.41 (Ubuntu)",
        "x-powered-by": "PHP/7.4.3",
        "set-cookie": "session_id=abc123xyz; Path=/",
    })
    mock_client.get.return_value = mock_response

    findings = await audit_security_headers_and_cookies("https://example.com", client=mock_client)
    check_ids = [f.check_id for f in findings]

    assert "DAST-HDR-001" in check_ids  # Missing CSP
    assert "DAST-HDR-002" in check_ids  # Missing HSTS
    assert "DAST-HDR-004" in check_ids  # Missing X-Frame-Options
    assert "DAST-HDR-005" in check_ids  # Missing X-Content-Type-Options
    assert "DAST-HDR-006" in check_ids  # Missing Referrer-Policy
    assert "DAST-HDR-007" in check_ids  # Server & Technology Disclosure
    assert "DAST-HDR-008" in check_ids  # Missing Permissions-Policy
    assert "DAST-HDR-009" in check_ids  # Missing COOP/COEP
    assert "DAST-COOKIE-001" in check_ids  # Cookie missing HttpOnly
    assert "DAST-COOKIE-002" in check_ids  # Cookie missing Secure
    assert "DAST-COOKIE-003" in check_ids  # Cookie missing SameSite
    assert "DAST-CCH-001" in check_ids  # Missing Cache-Control


@pytest.mark.asyncio
async def test_cors_analyzer_findings():
    mock_client = AsyncMock()

    # Case 1: Origin reflection with credentials
    mock_resp1 = MagicMock(spec=httpx.Response)
    mock_resp1.status_code = 200
    mock_resp1.headers = httpx.Headers({
        "access-control-allow-origin": "https://attacker-origin.com",
        "access-control-allow-credentials": "true",
    })

    # Case 2: Trust of null origin
    mock_resp2 = MagicMock(spec=httpx.Response)
    mock_resp2.status_code = 200
    mock_resp2.headers = httpx.Headers({
        "access-control-allow-origin": "null",
        "access-control-allow-credentials": "true",
    })

    mock_client.get.side_effect = [mock_resp1, mock_resp2]

    findings = await audit_cors_policies("https://example.com", client=mock_client)
    check_ids = [f.check_id for f in findings]

    assert "DAST-CORS-001" in check_ids
    assert "DAST-CORS-003" in check_ids


@pytest.mark.asyncio
async def test_api_inspector_findings():
    mock_client = AsyncMock()

    # Simulate .env file returning 200 with DB_PASSWORD
    mock_env_resp = MagicMock(spec=httpx.Response)
    mock_env_resp.status_code = 200
    mock_env_resp.text = "APP_KEY=base64:123\nDB_PASSWORD=secretpassword123\nDB_HOST=127.0.0.1"

    # Simulate .git/HEAD returning 200
    mock_git_resp = MagicMock(spec=httpx.Response)
    mock_git_resp.status_code = 200
    mock_git_resp.text = "ref: refs/heads/main\n"

    # Simulate Actuator returning 200
    mock_act_resp = MagicMock(spec=httpx.Response)
    mock_act_resp.status_code = 200
    mock_act_resp.headers = {"content-type": "application/json"}
    mock_act_resp.text = '{"status": "UP", "propertySources": []}'

    # Simulate Swagger returning 200
    mock_swag_resp = MagicMock(spec=httpx.Response)
    mock_swag_resp.status_code = 200
    mock_swag_resp.text = '{"openapi": "3.0.0", "paths": {}}'

    mock_client.get.side_effect = [
        mock_env_resp,
        mock_git_resp,
        mock_act_resp,
        mock_swag_resp,
    ]

    # TRACE method response
    mock_trace_resp = MagicMock(spec=httpx.Response)
    mock_trace_resp.status_code = 200
    mock_trace_resp.headers = {"content-type": "message/http"}
    mock_client.request.return_value = mock_trace_resp

    findings = await audit_sensitive_exposure_and_methods("https://example.com", client=mock_client)
    check_ids = [f.check_id for f in findings]

    assert "DAST-EXP-001" in check_ids  # Public .env (Critical)
    assert "DAST-EXP-002" in check_ids  # Exposed .git/HEAD (Critical)
    assert "DAST-EXP-003" in check_ids  # Exposed Actuator (High)
    assert "DAST-EXP-004" in check_ids  # Exposed OpenAPI (Low)
    assert "DAST-METH-001" in check_ids  # TRACE enabled (Medium)


@pytest.mark.asyncio
async def test_browser_posture_and_graphql():
    mock_client = AsyncMock()

    # HTML with external script lacking integrity and insecure http image
    html_content = """
    <!DOCTYPE html>
    <html>
      <head>
        <script src="https://cdn.thirdparty.com/analytics.js"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome.css">
      </head>
      <body>
        <img src="http://insecure-cdn.com/banner.jpg" alt="banner">
      </body>
    </html>
    """
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "text/html; charset=utf-8"}
    mock_resp.text = html_content
    mock_client.get.return_value = mock_resp

    browser_findings = await audit_browser_posture("https://example.com", client=mock_client)
    browser_check_ids = [f.check_id for f in browser_findings]

    assert "DAST-SRI-001" in browser_check_ids
    assert "DAST-MIX-001" in browser_check_ids

    # GraphQL introspection response
    mock_gql_resp = MagicMock(spec=httpx.Response)
    mock_gql_resp.status_code = 200
    mock_gql_resp.json.return_value = {
        "data": {
            "__schema": {
                "types": [{"name": "User"}, {"name": "Query"}, {"name": "Mutation"}]
            }
        }
    }
    mock_client.post.return_value = mock_gql_resp

    gql_findings = await audit_graphql_endpoints("https://example.com", client=mock_client)
    gql_check_ids = [f.check_id for f in gql_findings]
    assert "DAST-GQL-001" in gql_check_ids


@pytest.mark.asyncio
async def test_web_dast_engine_full_run():
    engine = WebDastAssessmentEngine()
    assert engine.name == "web_dast"
    assert engine.is_applicable(Target(name="Web Target", type=TargetType.URL, value="https://example.com")) is True
    assert engine.is_applicable(Target(name="Docker Target", type=TargetType.DOCKERFILE, value="./Dockerfile")) is False

    logs = []
    progress_updates = []
    findings_emitted = []

    async def log_cb(lvl, msg):
        logs.append((lvl, msg))

    async def prog_cb(pct, stg):
        progress_updates.append((pct, stg))

    async def find_cb(f):
        findings_emitted.append(f)

    with patch("app.engines.web_dast.engine.audit_security_headers_and_cookies", new_callable=AsyncMock) as mock_hdr, \
         patch("app.engines.web_dast.engine.audit_cors_policies", new_callable=AsyncMock) as mock_cors, \
         patch("app.engines.web_dast.engine.audit_sensitive_exposure_and_methods", new_callable=AsyncMock) as mock_exp, \
         patch("app.engines.web_dast.engine.audit_browser_posture", new_callable=AsyncMock) as mock_browser, \
         patch("app.engines.web_dast.engine.audit_graphql_endpoints", new_callable=AsyncMock) as mock_gql:

        mock_hdr.return_value = []
        mock_cors.return_value = []
        mock_exp.return_value = []
        mock_browser.return_value = []
        mock_gql.return_value = []

        target = Target(name="Web", type=TargetType.URL, value="https://example.com")
        config = ScanConfig()

        res = await engine.run(target, config, log_cb, prog_cb, find_cb)
        assert res == []
        assert len(progress_updates) >= 4
        assert progress_updates[-1][0] == 100
