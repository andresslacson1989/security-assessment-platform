"""
Unit tests for Engine 2: Web Application & API DAST (v3.1.0).
"""

from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path
import httpx
import pytest

from app.core.models import (
    Target,
    TargetType,
    ScanConfig,
    Severity,
    CrawlerConfig,
    AuthConfig,
    AuthType,
    FuzzingConfig,
    ToolAdapterConfig,
    DiscoveredEndpoint,
    NormalizedExecutionState,
)
from app.engines.web_dast.headers_cookies import audit_security_headers_and_cookies
from app.engines.web_dast.cors_analyzer import audit_cors_policies
from app.engines.web_dast.api_inspector import audit_sensitive_exposure_and_methods
from app.engines.web_dast.browser_posture import audit_browser_posture
from app.engines.web_dast.graphql_auditor import audit_graphql_endpoints
from app.engines.web_dast.engine import WebDastAssessmentEngine
from app.engines.web_dast.parameter_fuzzer import audit_parameter_fuzzing


@pytest.mark.asyncio
async def test_headers_and_cookies_findings():
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

    mock_resp1 = MagicMock(spec=httpx.Response)
    mock_resp1.status_code = 200
    mock_resp1.headers = httpx.Headers({
        "access-control-allow-origin": "https://attacker-origin.com",
        "access-control-allow-credentials": "true",
    })

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

    mock_env_resp = MagicMock(spec=httpx.Response)
    mock_env_resp.status_code = 200
    mock_env_resp.text = "APP_KEY=base64:123\nDB_PASSWORD=secretpassword123\nDB_HOST=127.0.0.1"

    mock_git_resp = MagicMock(spec=httpx.Response)
    mock_git_resp.status_code = 200
    mock_git_resp.text = "ref: refs/heads/main\n"

    mock_act_resp = MagicMock(spec=httpx.Response)
    mock_act_resp.status_code = 200
    mock_act_resp.headers = {"content-type": "application/json"}
    mock_act_resp.text = '{"status": "UP", "propertySources": []}'

    mock_swag_resp = MagicMock(spec=httpx.Response)
    mock_swag_resp.status_code = 200
    mock_swag_resp.text = '{"openapi": "3.0.0", "paths": {}}'

    mock_client.get.side_effect = [
        mock_env_resp,
        mock_git_resp,
        mock_act_resp,
        mock_swag_resp,
    ]

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
    auth_statuses = []
    discovered_endpoints = []

    async def log_cb(lvl, msg):
        logs.append((lvl, msg))

    async def prog_cb(pct, stg):
        progress_updates.append((pct, stg))

    async def find_cb(f):
        findings_emitted.append(f)

    async def auth_cb(data):
        auth_statuses.append(data)

    async def ep_cb(ep):
        discovered_endpoints.append(ep)

    with patch("app.engines.web_dast.engine.audit_security_headers_and_cookies", new_callable=AsyncMock) as mock_hdr, \
         patch("app.engines.web_dast.engine.audit_cors_policies", new_callable=AsyncMock) as mock_cors, \
         patch("app.engines.web_dast.engine.audit_sensitive_exposure_and_methods", new_callable=AsyncMock) as mock_exp, \
         patch("app.engines.web_dast.engine.audit_browser_posture", new_callable=AsyncMock) as mock_browser, \
         patch("app.engines.web_dast.engine.audit_graphql_endpoints", new_callable=AsyncMock) as mock_gql, \
         patch("app.engines.web_dast.engine.WebCrawler.crawl", new_callable=AsyncMock) as mock_crawl, \
         patch("app.engines.web_dast.engine.AuthSessionManager.authenticate", new_callable=AsyncMock) as mock_auth, \
         patch("app.engines.web_dast.engine.AuthSessionManager.audit_auth_and_forms", new_callable=AsyncMock) as mock_auth_audit:

        mock_hdr.return_value = []
        mock_cors.return_value = []
        mock_exp.return_value = []
        mock_browser.return_value = []
        mock_gql.return_value = []
        mock_crawl.return_value = [
            DiscoveredEndpoint(url="https://example.com/dashboard", method="GET", depth=1)
        ]
        mock_auth.return_value = True
        mock_auth_audit.return_value = []

        target = Target(name="Web", type=TargetType.URL, value="https://example.com")
        config = ScanConfig(
            crawler=CrawlerConfig(enabled=True, max_depth=2, max_pages=10),
            auth=AuthConfig(auth_type=AuthType.HEADER, headers={"Authorization": "Bearer test"}),
            fuzzing=FuzzingConfig(enabled=False),
            adapters=ToolAdapterConfig(
                enable_nuclei=False, enable_ffuf=False,
                enable_katana=False, enable_schemathesis=False,
            ),
        )

        res = await engine.run(
            target,
            config,
            log_cb,
            prog_cb,
            find_cb,
            emit_auth_status=auth_cb,
            emit_endpoint_discovered=ep_cb,
            organization_id="org-test",
        )
        assert res == []
        assert len(progress_updates) >= 4
        assert progress_updates[-1][0] == 100
        assert len(auth_statuses) == 1
        assert auth_statuses[0]["auth_type"] == "HEADER"
        assert auth_statuses[0]["authenticated"] is True


@pytest.mark.asyncio
async def test_web_dast_engine_reaches_bounded_sqlmap_path():
    """The active-fuzzing production path invokes sqlmap with a server workspace."""
    calls = {}

    class FakeSqlmap:
        last_execution_state = NormalizedExecutionState.COMPLETED_NO_FINDINGS

        async def is_available(self, custom_path=None):
            return True

        async def run(self, target, config, emit_log, emit_finding, **kwargs):
            calls["sqlmap"] = kwargs
            assert Path(kwargs["output_dir"]).is_absolute()
            assert kwargs["require_managed_binary"] is True
            assert kwargs["validated_target"].canonical_value == target.value
            return []

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    async def log_cb(level, message):
        pass

    async def progress_cb(percent, stage):
        pass

    async def finding_cb(finding):
        pass

    with patch("app.engines.web_dast.engine.SqlmapAdapter", FakeSqlmap), \
         patch("app.engines.web_dast.engine.httpx.AsyncClient", return_value=mock_client), \
         patch("app.engines.web_dast.engine.audit_security_headers_and_cookies", new_callable=AsyncMock, return_value=[]), \
         patch("app.engines.web_dast.engine.audit_cors_policies", new_callable=AsyncMock, return_value=[]), \
         patch("app.engines.web_dast.engine.audit_sensitive_exposure_and_methods", new_callable=AsyncMock, return_value=[]), \
         patch("app.engines.web_dast.engine.audit_browser_posture", new_callable=AsyncMock, return_value=[]), \
         patch("app.engines.web_dast.engine.audit_graphql_endpoints", new_callable=AsyncMock, return_value=[]), \
         patch("app.engines.web_dast.engine.audit_parameter_fuzzing", new_callable=AsyncMock, return_value=[]), \
         patch("app.engines.web_dast.engine.WebCrawler.crawl", new_callable=AsyncMock, return_value=[]), \
         patch("app.engines.web_dast.engine.AuthSessionManager.authenticate", new_callable=AsyncMock, return_value=False), \
         patch("app.engines.web_dast.engine.AuthSessionManager.audit_auth_and_forms", new_callable=AsyncMock, return_value=[]):
        config = ScanConfig(
            crawler=CrawlerConfig(enabled=False),
            fuzzing=FuzzingConfig(enabled=True),
            adapters=ToolAdapterConfig(
                enable_nuclei=False,
                enable_ffuf=False,
                enable_katana=False,
                enable_schemathesis=False,
                enable_sqlmap=True,
            ),
        )
        await WebDastAssessmentEngine().run(
            Target(name="Web", type=TargetType.URL, value="https://example.com/item?id=1"),
            config,
            log_cb,
            progress_cb,
            finding_cb,
            organization_id="org-test",
            asset_id="asset-test",
            active_probing_granted=True,
            scan_id="scan-sqlmap-runtime",
        )

    assert "sqlmap" in calls


@pytest.mark.asyncio
async def test_parameter_redirect_probe_reuses_validated_client():
    """Open-redirect probing must not create a second unvalidated HTTP client."""
    def handler(request):
        return httpx.Response(
            302,
            headers={"location": "https://attacker.invalid"},
            request=request,
        )

    config = ScanConfig(
        fuzzing=FuzzingConfig(
            enabled=True,
            fuzz_sqli=False,
            fuzz_xss=False,
            fuzz_lfi=False,
            fuzz_ssti=False,
            fuzz_redirect=True,
        )
    )
    target_url = "https://example.com/?next=home"
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with patch("app.engines.web_dast.parameter_fuzzer.httpx.AsyncClient", side_effect=AssertionError("new client not allowed")):
            findings = await audit_parameter_fuzzing(
                target_url,
                discovered_endpoints=[],
                client=client,
                config=config,
                scan_id="scan-redirect-binding",
            )

    assert any(f.check_id == "DAST-REDIR-001" for f in findings)


@pytest.mark.asyncio
async def test_web_dast_engine_audits_all_crawled_pages():
    """
    Verifies that WebDastEngine audits security headers, cookies, forms,
    and browser posture across all discovered/crawled endpoints.
    """
    engine = WebDastAssessmentEngine()

    mock_client = AsyncMock()

    async def mock_get(url, **kwargs):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.headers = {
            "content-type": "text/html; charset=utf-8",
            "server": "Apache/2.4.41",
        }
        if "dashboard" in url:
            resp.text = """
            <html>
              <body>
                <h1>Dashboard</h1>
                <script src="http://cdn.insecure.com/analytics.js"></script>
                <form action="http://insecure.example.com/update" method="POST">
                  <input type="text" name="data">
                </form>
              </body>
            </html>
            """
        else:
            resp.text = """
            <html>
              <body>
                <a href="/dashboard">Dashboard</a>
              </body>
            </html>
            """
        return resp

    mock_client.get = AsyncMock(side_effect=mock_get)
    mock_client.post = AsyncMock(return_value=MagicMock(status_code=404, json=lambda: {}))
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    target = Target(name="Web Target", type=TargetType.URL, value="https://example.com")
    config = ScanConfig(
        crawler=CrawlerConfig(enabled=True, max_depth=2, max_pages=10, parse_sitemap=False),
        auth=AuthConfig(auth_type=AuthType.NONE),
        fuzzing=FuzzingConfig(enabled=False),
        adapters=ToolAdapterConfig(
            enable_nuclei=False, enable_ffuf=False,
            enable_katana=False, enable_schemathesis=False,
        ),
    )

    findings = []
    async def log_cb(lvl, msg): pass
    async def prog_cb(pct, stg): pass
    async def find_cb(f): findings.append(f)

    # Use real crawler with mocked client
    with patch("httpx.AsyncClient", return_value=mock_client):
        res = await engine.run(
            target,
            config,
            log_cb,
            prog_cb,
            find_cb,
            organization_id="org-test",
        )

    check_ids = {f.check_id for f in res}
    # Root + dashboard security headers tested
    assert "DAST-HDR-001" in check_ids  # Missing CSP
    # Subresource integrity & form security tested on /dashboard
    assert "DAST-SRI-001" in check_ids  # Script from insecure cdn lacking integrity
    assert "DAST-FORM-001" in check_ids  # Form action http:// on https site
    assert "DAST-FORM-002" in check_ids  # Missing CSRF token on POST form
