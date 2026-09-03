"""
E13.4 — Adversarial Acceptance Tests for Evidence Truthfulness and Telemetry Closure.
Validates:
- No false assurance: missing, failing, or unparseable tool output emits zero findings and never asserts SAFE.
- Tool missing sets NOT_EXECUTED_PREREQUISITE_MISSING without synthetic findings.
- Tool failure (code != 0) sets FAILED state without synthetic findings.
- Malformed output never creates synthetic findings.
- Clean execution produces COMPLETED_NO_FINDINGS with empty findings list (not synthetic SAFE finding).
- Telemetry endpoint tracks success_count and failure_count accurately (never increments success for failures).
- Unexecuted endpoint tools are marked SKIPPED rather than falsely claiming SAFE.
"""

from unittest.mock import AsyncMock, MagicMock, patch
import json
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.adapters.sslyze_adapter import SslyzeAdapter
from app.core.models import (
    Target,
    TargetType,
    ScanConfig,
    ScanJob,
    ScanProfile,
    ScanStatus,
    Severity,
    Finding,
    Evidence,
    DiscoveredEndpoint,
    NormalizedExecutionState,
    EngineExecutionStatus,
    EndpointTestStatus,
)
from app.core.orchestrator import save_scan
from app.core.auth import create_access_token, UserProfile, UserRole, PrincipalType


@pytest.fixture
def auth_headers():
    admin = UserProfile(
        id="usr-telemetry-admin",
        username="admin_truth",
        email="admin@truth.local",
        role=UserRole.ADMIN,
        principal_type=PrincipalType.SYSTEM_PRINCIPAL,
        scopes=["*"],
    )
    token = create_access_token(admin)
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_sslyze_missing_binary_no_false_assurance():
    """When sslyze is missing, adapter reports prerequisite missing, emits zero findings, no SAFE claims."""
    adapter = SslyzeAdapter()
    target = Target(name="test", type=TargetType.DOMAIN, value="example.com")
    config = ScanConfig()

    logs = []
    findings = []

    async def log_cb(lvl, msg):
        logs.append((lvl, msg))

    async def find_cb(f):
        findings.append(f)

    with patch.object(adapter, "resolve_binary_path", return_value=None):
        res = await adapter.run(target, config, log_cb, find_cb)

    assert res == []
    assert findings == []
    assert adapter.last_execution_state in {
        NormalizedExecutionState.NOT_EXECUTED_PREREQUISITE_MISSING,
        NormalizedExecutionState.TOOL_EXECUTION_FAILED,
    }


@pytest.mark.asyncio
async def test_sslyze_execution_crash_no_false_assurance():
    """When sslyze exits non-zero, adapter reports failed state, zero findings, no SAFE claims."""
    adapter = SslyzeAdapter()
    target = Target(name="test", type=TargetType.DOMAIN, value="example.com")
    config = ScanConfig()

    logs = []
    findings = []

    async def log_cb(lvl, msg):
        logs.append(msg)

    async def find_cb(f):
        findings.append(f)

    with patch.object(adapter, "resolve_binary_path", return_value="/managed/bin/sslyze"), \
         patch.object(adapter, "verify_managed_binary", return_value=True), \
         patch.object(adapter, "get_version", new=AsyncMock(return_value="SSLyze 5.2.0")), \
         patch.object(adapter, "verify_version", return_value=(True, None)), \
         patch.object(adapter, "execute_command", new=AsyncMock(return_value=(1, "", "Fatal SSLyze crash error"))):
        res = await adapter.run(target, config, log_cb, find_cb)

    assert res == []
    assert findings == []
    assert adapter.last_execution_state in {
        NormalizedExecutionState.FAILED_NON_ZERO_EXIT,
        NormalizedExecutionState.TOOL_EXECUTION_FAILED,
    }


@pytest.mark.asyncio
async def test_sslyze_corrupt_json_no_synthetic_findings():
    """When sslyze returns corrupt output, parser returns empty findings without claiming SAFE."""
    adapter = SslyzeAdapter()
    findings, state, _ = adapter.parse_sslyze_json("{corrupt: json syntax error", "example.com", 443)
    assert findings == []
    assert state != NormalizedExecutionState.COMPLETED_NO_FINDINGS
    assert state != NormalizedExecutionState.COMPLETED_WITH_FINDINGS


@pytest.mark.asyncio
async def test_sslyze_clean_target_produces_empty_findings_not_synthetic_safe():
    """Clean scan target produces empty findings with COMPLETED_NO_FINDINGS state."""
    adapter = SslyzeAdapter()
    clean_json = {
        "server_scan_results": [
            {
                "scan_result": {
                    "ssl_2_0_cipher_suites": {"result": {"is_supported": False}},
                    "ssl_3_0_cipher_suites": {"result": {"is_supported": False}},
                    "tls_1_0_cipher_suites": {"result": {"is_supported": False}},
                    "tls_1_1_cipher_suites": {"result": {"is_supported": False}},
                    "tls_1_2_cipher_suites": {"result": {"is_supported": True, "accepted_cipher_suites": [{"cipher_suite": {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}}]}},
                    "tls_1_3_cipher_suites": {"result": {"is_supported": True, "accepted_cipher_suites": [{"cipher_suite": {"name": "TLS_AES_256_GCM_SHA384"}}]}},
                    "certificate_info": {"result": {"certificate_deployments": [{"received_certificate_chain": [{"signature_hash_algorithm": {"name": "sha256"}}], "path_validation_results": [{"is_valid_path": True}]}]}},
                }
            }
        ]
    }
    findings, state, _ = adapter.parse_sslyze_json(json.dumps(clean_json), "example.com", 443)
    assert findings == []
    assert state == NormalizedExecutionState.COMPLETED_NO_FINDINGS


@pytest.mark.asyncio
async def test_telemetry_accuracy_failed_vs_successful_runs(auth_headers):
    """Telemetry report must reflect success_count=0, failure_count=1 for failed tools, never incrementing success on failure."""
    job = ScanJob(
        id="scan-truth-telemetry-01",
        target=Target(name="test", type=TargetType.URL, value="https://target.local"),
        profile=ScanProfile.QUICK,
        organization_id="org-default",
        status=ScanStatus.COMPLETED,
        tool_execution_states={
            "sslyze": "TOOL_EXECUTION_FAILED",
            "nmap": "COMPLETED_NO_FINDINGS",
        },
        tool_execution_engines={
            "sslyze": "network",
            "nmap": "network",
        },
        discovered_endpoints=[
            DiscoveredEndpoint(
                url="https://target.local/test",
                method="GET",
                tools_executed=["nmap"],
            )
        ],
    )
    save_scan(job)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get(f"/api/scans/{job.id}/telemetry", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()

        tools = {t["tool_name"]: t for t in data["tools_executed"]}
        assert "sslyze" in tools
        assert "nmap" in tools

        # SSLyze failed: failure_count must be 1, success_count must be 0
        assert tools["sslyze"]["status"] == EngineExecutionStatus.FAILED.value
        assert tools["sslyze"]["failure_count"] == 1
        assert tools["sslyze"]["success_count"] == 0

        # Nmap passed: success_count must be 1, failure_count must be 0
        assert tools["nmap"]["status"] == EngineExecutionStatus.PASS.value
        assert tools["nmap"]["success_count"] == 1
        assert tools["nmap"]["failure_count"] == 0

        # Discovered endpoint tests: nuclei was not executed so its test must be SKIPPED, not SAFE
        ep = data["discovered_endpoints"][0]
        nuclei_tests = [t for t in ep["tests_performed"] if t["tool"] == "nuclei"]
        if nuclei_tests:
            assert nuclei_tests[0]["status"] == EndpointTestStatus.SKIPPED.value


@pytest.mark.asyncio
async def test_endpoint_with_empty_evidence_manufactures_no_tools_or_safe_checks(auth_headers):
    """
    R2.1 Invariant:
    Endpoint with tools_executed=[], tests_performed=[], findings=[]:
    => tools_executed remains empty []
    => no SAFE check is manufactured anywhere in the response.
    """
    job = ScanJob(
        id="scan-truth-empty-ep-01",
        target=Target(name="test", type=TargetType.URL, value="https://truth-target.local"),
        profile=ScanProfile.QUICK,
        organization_id="org-default",
        status=ScanStatus.COMPLETED,
        findings=[],
        discovered_endpoints=[
            DiscoveredEndpoint(
                url="https://truth-target.local/untested",
                method="GET",
                tools_executed=[],
                tests_performed=[],
                finding_ids=[],
            )
        ],
    )
    save_scan(job)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get(f"/api/scans/{job.id}/telemetry", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()

        ep = data["discovered_endpoints"][0]
        # tools_executed MUST remain empty
        assert ep["tools_executed"] == [], f"Expected empty tools_executed but got {ep['tools_executed']}"

        # No SAFE check may be manufactured
        safe_checks = [t for t in ep["tests_performed"] if t["status"] == "SAFE"]
        assert len(safe_checks) == 0, f"Manufactured unauthorized SAFE checks: {safe_checks}"

        # Recursive check across all discovered endpoints for any manufactured SAFE status
        for endpoint in data["discovered_endpoints"]:
            for test in endpoint.get("tests_performed", []):
                assert test.get("status") != "SAFE", f"Manufactured SAFE check on untested endpoint: {test}"


@pytest.mark.asyncio
async def test_failed_header_check_zero_findings_not_safe():
    """
    R2.1 Invariant:
    Failed/timed-out HTTP header probe with zero findings must raise or mark SKIPPED, NEVER SAFE.
    """
    from app.engines.web_dast.headers_cookies import audit_security_headers_and_cookies
    from app.engines.web_dast.engine import WebDastAssessmentEngine
    import httpx

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=httpx.ConnectTimeout("Connection timed out to header target"))

    # Direct check must raise rather than falsely returning empty findings
    with pytest.raises(RuntimeError):
        await audit_security_headers_and_cookies("https://timeout.local", client=mock_client)

    # In engine execution, the endpoint test must be recorded as SKIPPED, not SAFE
    engine = WebDastAssessmentEngine()
    target = Target(name="test", type=TargetType.URL, value="https://timeout.local")
    config = ScanConfig()
    config.fuzzing.enabled = False

    endpoints = []
    async def ep_cb(ep):
        endpoints.append(ep)

    findings = await engine.run(
        target,
        config,
        emit_log=AsyncMock(),
        emit_progress=AsyncMock(),
        emit_finding=AsyncMock(),
        emit_endpoint_discovered=ep_cb,
        client=mock_client,
    )

    # Discovered endpoints must not have SAFE security headers
    for ep in endpoints:
        for t in ep.tests_performed:
            if "Header" in t.test_name:
                assert t.status != EndpointTestStatus.SAFE
                assert t.status == EndpointTestStatus.SKIPPED


@pytest.mark.asyncio
async def test_timed_out_cors_check_zero_findings_not_safe():
    """
    R2.1 Invariant:
    Timed-out CORS probe with zero findings must raise or mark SKIPPED, NEVER SAFE.
    """
    from app.engines.web_dast.cors_analyzer import audit_cors_policies
    from app.engines.web_dast.engine import WebDastAssessmentEngine
    import httpx

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=httpx.ReadTimeout("CORS probe read timed out"))

    # Direct check must raise on network timeout rather than silently asserting clean CORS
    with pytest.raises(RuntimeError):
        await audit_cors_policies("https://cors-timeout.local", client=mock_client)

    # In engine execution, CORS test record must be SKIPPED, never SAFE
    engine = WebDastAssessmentEngine()
    target = Target(name="test", type=TargetType.URL, value="https://cors-timeout.local")
    config = ScanConfig()
    config.fuzzing.enabled = False

    endpoints = []
    async def ep_cb(ep):
        endpoints.append(ep)

    await engine.run(
        target,
        config,
        emit_log=AsyncMock(),
        emit_progress=AsyncMock(),
        emit_finding=AsyncMock(),
        emit_endpoint_discovered=ep_cb,
        client=mock_client,
    )

    for ep in endpoints:
        for t in ep.tests_performed:
            if "CORS" in t.test_name:
                assert t.status != EndpointTestStatus.SAFE
                assert t.status == EndpointTestStatus.SKIPPED


@pytest.mark.asyncio
async def test_missing_fuzzer_authorization_records_skipped_not_safe():
    """
    R2.1 Invariant:
    Missing active probing authorization must mark parameter injection as SKIPPED,
    must NOT assign 'parameter_fuzzer' to tools_executed, and must NEVER claim SAFE.
    """
    from app.engines.web_dast.engine import WebDastAssessmentEngine
    import httpx

    mock_resp = AsyncMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.text = "<html><body><p>Hello world</p></body></html>"
    mock_resp.headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
    }

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(return_value=mock_resp)

    engine = WebDastAssessmentEngine()
    target = Target(name="test", type=TargetType.URL, value="https://example.com")
    config = ScanConfig()
    config.crawler.enabled = False
    config.fuzzing.enabled = True  # Enabled in profile, but active_probing_granted=False

    endpoints = []
    async def ep_cb(ep):
        endpoints.append(ep)

    with patch("app.engines.web_dast.engine.httpx.AsyncClient") as mock_client_cls:
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        await engine.run(
            target,
            config,
            emit_log=AsyncMock(),
            emit_progress=AsyncMock(),
            emit_finding=AsyncMock(),
            emit_endpoint_discovered=ep_cb,
            organization_id="org-test",
            active_probing_granted=False,  # BLOCKED
        )

    assert len(endpoints) > 0
    for ep in endpoints:
        # parameter_fuzzer must NOT be in tools_executed
        assert "parameter_fuzzer" not in ep.tools_executed
        fuzz_tests = [t for t in ep.tests_performed if "Injection" in t.test_name or "parameter_fuzzer" in t.tool]
        assert len(fuzz_tests) > 0
        for ft in fuzz_tests:
            assert ft.status == EndpointTestStatus.SKIPPED
            assert ft.status != EndpointTestStatus.SAFE


@pytest.mark.asyncio
async def test_missing_coverage_fails_closed_as_not_fully_assessed(auth_headers):
    """
    R2.1 Invariant:
    Missing or empty coverage data must fail closed:
    is_fully_assessed=False, coverage_status='COVERAGE_DEGRADED', engines_executed=[].
    """
    from app.core.models import AssessmentCoverage, ScanJobSummary

    # 1. Model defaults fail closed
    cov = AssessmentCoverage()
    assert cov.is_fully_assessed is False
    assert cov.coverage_status == "COVERAGE_DEGRADED"

    # 2. Scans API telemetry endpoint fails closed when job has empty coverage
    job = ScanJob(
        id="scan-truth-no-cov-01",
        target=Target(name="test", type=TargetType.URL, value="https://truth-target.local"),
        profile=ScanProfile.QUICK,
        organization_id="org-default",
        status=ScanStatus.RUNNING,
        summary=ScanJobSummary(
            coverage=AssessmentCoverage(
                engines_requested=["web_dast", "network"],
                engines_executed=[],
                is_fully_assessed=False,
            )
        ),
    )
    save_scan(job)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get(f"/api/scans/{job.id}/telemetry", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()

        coverage = data["coverage"]
        assert coverage["is_fully_assessed"] is False
        assert coverage["coverage_status"] == "COVERAGE_DEGRADED"
        assert coverage["engines_executed"] == []


# ============================================================================
# R3.1 Invariants: Form/CSRF, Parameter Fuzzer, and CORS Truthful Accounting
# ============================================================================

@pytest.mark.asyncio
async def test_r3_1_csrf_finding_forces_vulnerable_never_safe():
    """
    R3.1 Invariant:
    When DAST-FORM-002 (missing CSRF token) is detected on an endpoint,
    the endpoint's 'HTML Form & CSRF Token Validation' record MUST be VULNERABLE,
    NEVER SAFE.
    """
    from app.engines.web_dast.auth_session import AuthSessionManager
    from app.engines.web_dast.engine import WebDastAssessmentEngine
    from unittest.mock import patch

    mock_client = AsyncMock()
    mock_client.cookies = MagicMock(jar=[])
    endpoint = DiscoveredEndpoint(
        url="https://csrf-vuln.local/transfer",
        method="GET",
        depth=1,
        status_code=200,
        content_type="text/html",
        has_forms=True,
        discovered_forms=1,
    )
    html_with_insecure_form = """
    <html><body>
      <form action="/transfer" method="POST">
        <input type="text" name="amount" value="100"/>
        <button type="submit">Submit</button>
      </form>
    </body></html>
    """

    engine = WebDastAssessmentEngine()
    target = Target(name="test", type=TargetType.URL, value="https://csrf-vuln.local")
    config = ScanConfig()
    config.fuzzing.enabled = False

    endpoints = []
    async def ep_cb(ep):
        endpoints.append(ep)

    def make_crawler(eps, html_dict=None):
        def _factory(*args, **kwargs):
            on_ep = kwargs.get("on_endpoint_discovered")
            async def _crawl():
                if on_ep:
                    for ep in eps:
                        await on_ep(ep)
                return eps
            c = MagicMock()
            c.crawl = AsyncMock(side_effect=_crawl)
            c.page_html = html_dict or {}
            c.page_responses = {}
            return c
        return _factory

    mock_vt = MagicMock()
    mock_vt.canonical_value = target.value

    with patch("app.engines.web_dast.engine.create_validated_target", return_value=mock_vt), \
         patch("app.engines.web_dast.engine.WebCrawler", side_effect=make_crawler([endpoint], {"https://csrf-vuln.local/transfer": html_with_insecure_form})), \
         patch("app.engines.web_dast.engine.audit_cors_policies", new=AsyncMock(return_value=[])):
        findings = await engine.run(
            target,
            config,
            emit_log=AsyncMock(),
            emit_progress=AsyncMock(),
            emit_finding=AsyncMock(),
            emit_endpoint_discovered=ep_cb,
            client=mock_client,
            organization_id="org-default",
        )

    # 1. DAST-FORM-002 must be generated
    csrf_findings = [f for f in findings if f.check_id == "DAST-FORM-002"]
    assert len(csrf_findings) >= 1

    # 2. Endpoint MUST be marked VULNERABLE, NEVER SAFE
    assert len(endpoints) == 1
    ep = endpoints[0]
    form_tests = [t for t in ep.tests_performed if "HTML Form" in t.test_name]
    assert len(form_tests) == 1
    assert form_tests[0].status == EndpointTestStatus.VULNERABLE
    assert form_tests[0].status != EndpointTestStatus.SAFE
    assert form_tests[0].findings_count >= 1


@pytest.mark.asyncio
async def test_r3_1_form_parser_failure_forces_skipped_never_safe():
    """
    R3.1 Invariant:
    When HTML form parsing fails on an endpoint, the record MUST be SKIPPED,
    NEVER SAFE.
    """
    from app.engines.web_dast.engine import WebDastAssessmentEngine
    from unittest.mock import patch

    mock_client = AsyncMock()
    mock_client.cookies = MagicMock(jar=[])
    endpoint = DiscoveredEndpoint(
        url="https://corrupt-html.local/bad",
        method="GET",
        depth=1,
        status_code=200,
        content_type="text/html",
        has_forms=True,
        discovered_forms=1,
    )

    engine = WebDastAssessmentEngine()
    target = Target(name="test", type=TargetType.URL, value="https://corrupt-html.local")
    config = ScanConfig()
    config.fuzzing.enabled = False

    endpoints = []
    async def ep_cb(ep):
        endpoints.append(ep)

    def make_crawler(eps, html_dict=None):
        def _factory(*args, **kwargs):
            on_ep = kwargs.get("on_endpoint_discovered")
            async def _crawl():
                if on_ep:
                    for ep in eps:
                        await on_ep(ep)
                return eps
            c = MagicMock()
            c.crawl = AsyncMock(side_effect=_crawl)
            c.page_html = html_dict or {}
            c.page_responses = {}
            return c
        return _factory

    mock_vt = MagicMock()
    mock_vt.canonical_value = target.value

    # Trigger parse failure by patching BeautifulSoup inside auth_session
    with patch("app.engines.web_dast.engine.create_validated_target", return_value=mock_vt), \
         patch("app.engines.web_dast.auth_session.BeautifulSoup", side_effect=ValueError("Corrupt markup")), \
         patch("app.engines.web_dast.engine.WebCrawler", side_effect=make_crawler([endpoint], {"https://corrupt-html.local/bad": "<broken>"})), \
         patch("app.engines.web_dast.engine.audit_cors_policies", new=AsyncMock(return_value=[])):
        await engine.run(
            target,
            config,
            emit_log=AsyncMock(),
            emit_progress=AsyncMock(),
            emit_finding=AsyncMock(),
            emit_endpoint_discovered=ep_cb,
            client=mock_client,
            organization_id="org-default",
        )

    assert len(endpoints) == 1
    ep = endpoints[0]
    form_tests = [t for t in ep.tests_performed if "HTML Form" in t.test_name]
    assert len(form_tests) == 1
    assert form_tests[0].status == EndpointTestStatus.SKIPPED
    assert form_tests[0].status != EndpointTestStatus.SAFE


@pytest.mark.asyncio
async def test_r3_1_all_form_checks_pass_records_safe():
    """
    R3.1 Invariant:
    When forms are inspected, have valid anti-CSRF tokens and HTTPS actions,
    and produce zero findings, the record is truthfully SAFE.
    """
    from app.engines.web_dast.engine import WebDastAssessmentEngine
    from unittest.mock import patch

    mock_client = AsyncMock()
    mock_client.cookies = MagicMock(jar=[])
    endpoint = DiscoveredEndpoint(
        url="https://secure-forms.local/login",
        method="GET",
        depth=1,
        status_code=200,
        content_type="text/html",
        has_forms=True,
        discovered_forms=1,
    )
    valid_form_html = """
    <html><body>
      <form action="/login" method="POST">
        <input type="hidden" name="csrf_token" value="abc123secret"/>
        <input type="text" name="user"/>
        <button type="submit">Log In</button>
      </form>
    </body></html>
    """

    engine = WebDastAssessmentEngine()
    target = Target(name="test", type=TargetType.URL, value="https://secure-forms.local")
    config = ScanConfig()
    config.fuzzing.enabled = False

    endpoints = []
    async def ep_cb(ep):
        endpoints.append(ep)

    def make_crawler(eps, html_dict=None):
        def _factory(*args, **kwargs):
            on_ep = kwargs.get("on_endpoint_discovered")
            async def _crawl():
                if on_ep:
                    for ep in eps:
                        await on_ep(ep)
                return eps
            c = MagicMock()
            c.crawl = AsyncMock(side_effect=_crawl)
            c.page_html = html_dict or {}
            c.page_responses = {}
            return c
        return _factory

    mock_vt = MagicMock()
    mock_vt.canonical_value = target.value

    with patch("app.engines.web_dast.engine.create_validated_target", return_value=mock_vt), \
         patch("app.engines.web_dast.engine.WebCrawler", side_effect=make_crawler([endpoint], {"https://secure-forms.local/login": valid_form_html})), \
         patch("app.engines.web_dast.engine.audit_cors_policies", new=AsyncMock(return_value=[])):
        findings = await engine.run(
            target,
            config,
            emit_log=AsyncMock(),
            emit_progress=AsyncMock(),
            emit_finding=AsyncMock(),
            emit_endpoint_discovered=ep_cb,
            client=mock_client,
            organization_id="org-default",
        )

    form_findings = [f for f in findings if f.check_id in ("DAST-FORM-001", "DAST-FORM-002")]
    assert len(form_findings) == 0

    assert len(endpoints) == 1
    ep = endpoints[0]
    form_tests = [t for t in ep.tests_performed if "HTML Form" in t.test_name]
    assert len(form_tests) == 1
    assert form_tests[0].status == EndpointTestStatus.SAFE


@pytest.mark.asyncio
async def test_r3_1_parameter_fuzzer_outbound_failures_never_safe():
    """
    R3.1 Invariant:
    When parameter fuzzing probes fail or time out on outbound requests,
    the endpoint record MUST be SKIPPED, NEVER SAFE.
    """
    from app.engines.web_dast.parameter_fuzzer import audit_parameter_fuzzing
    from app.engines.web_dast.engine import WebDastAssessmentEngine
    from unittest.mock import patch
    import httpx

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    # Simulate timeout on outbound fuzzing requests
    mock_client.get = AsyncMock(side_effect=httpx.ReadTimeout("Socket timeout during fuzz probe"))

    endpoint = DiscoveredEndpoint(
        url="https://fuzz-timeout.local/search?q=test",
        method="GET",
        depth=1,
        status_code=200,
        content_type="text/html",
    )
    config = ScanConfig()
    config.fuzzing.enabled = True

    # 1. Direct fuzzer execution must report failed probes
    result = await audit_parameter_fuzzing(
        "https://fuzz-timeout.local/search?q=test",
        discovered_endpoints=[endpoint],
        client=mock_client,
        config=config,
        scan_id="scan-fuzz-1",
    )
    assert len(result) == 0  # Zero findings
    assert result.executions["https://fuzz-timeout.local/search?q=test"].probes_failed > 0
    assert result.executions["https://fuzz-timeout.local/search?q=test"].is_fully_completed is False

    # 2. Engine execution must record SKIPPED, never SAFE
    engine = WebDastAssessmentEngine()
    target = Target(name="test", type=TargetType.URL, value="https://fuzz-timeout.local")

    endpoints = []
    async def ep_cb(ep):
        endpoints.append(ep)

    def make_crawler(eps, html_dict=None):
        def _factory(*args, **kwargs):
            on_ep = kwargs.get("on_endpoint_discovered")
            async def _crawl():
                if on_ep:
                    for ep in eps:
                        await on_ep(ep)
                return eps
            c = MagicMock()
            c.crawl = AsyncMock(side_effect=_crawl)
            c.page_html = html_dict or {}
            c.page_responses = {}
            return c
        return _factory

    mock_vt = MagicMock()
    mock_vt.canonical_value = target.value

    with patch("app.engines.web_dast.engine.create_validated_target", return_value=mock_vt), \
         patch("app.engines.web_dast.engine.WebCrawler", side_effect=make_crawler([endpoint], {})), \
         patch("app.engines.web_dast.engine.audit_cors_policies", new=AsyncMock(return_value=[])):
        await engine.run(
            target,
            config,
            emit_log=AsyncMock(),
            emit_progress=AsyncMock(),
            emit_finding=AsyncMock(),
            emit_endpoint_discovered=ep_cb,
            client=mock_client,
            active_probing_granted=True,
            organization_id="org-default",
        )

    assert len(endpoints) == 1
    ep = endpoints[0]
    fuzz_tests = [t for t in ep.tests_performed if "Parameter Injection" in t.test_name]
    assert len(fuzz_tests) == 1
    assert fuzz_tests[0].status == EndpointTestStatus.SKIPPED
    assert fuzz_tests[0].status != EndpointTestStatus.SAFE


@pytest.mark.asyncio
async def test_r3_1_endpoint_never_fuzzed_receives_no_safe_and_no_tool():
    """
    R3.1 Invariant:
    An endpoint without query parameters that was never fuzzed must NOT receive
    'parameter_fuzzer' in tools_executed and MUST NOT receive SAFE parameter fuzzing evidence.
    """
    from app.engines.web_dast.engine import WebDastAssessmentEngine
    from unittest.mock import patch

    mock_client = AsyncMock()
    # Mock normal response for baseline
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "OK"
    mock_resp.headers = {}
    mock_client.get = AsyncMock(return_value=mock_resp)

    # Endpoint 1: Has query parameter (fuzzed)
    ep_fuzzed = DiscoveredEndpoint(
        url="https://fuzz-candidates.local/items?id=42",
        method="GET",
        depth=1,
        status_code=200,
        content_type="application/json",
    )
    # Endpoint 2: Static endpoint without query parameter (never fuzzed)
    ep_static = DiscoveredEndpoint(
        url="https://fuzz-candidates.local/healthz",
        method="GET",
        depth=1,
        status_code=200,
        content_type="application/json",
    )

    engine = WebDastAssessmentEngine()
    target = Target(name="test", type=TargetType.URL, value="https://fuzz-candidates.local")
    config = ScanConfig()
    config.fuzzing.enabled = True

    endpoints = []
    async def ep_cb(ep):
        endpoints.append(ep)

    def make_crawler(eps, html_dict=None):
        def _factory(*args, **kwargs):
            on_ep = kwargs.get("on_endpoint_discovered")
            async def _crawl():
                if on_ep:
                    for ep in eps:
                        await on_ep(ep)
                return eps
            c = MagicMock()
            c.crawl = AsyncMock(side_effect=_crawl)
            c.page_html = html_dict or {}
            c.page_responses = {}
            return c
        return _factory

    mock_vt = MagicMock()
    mock_vt.canonical_value = target.value

    with patch("app.engines.web_dast.engine.create_validated_target", return_value=mock_vt), \
         patch("app.engines.web_dast.engine.WebCrawler", side_effect=make_crawler([ep_fuzzed, ep_static], {})), \
         patch("app.engines.web_dast.engine.audit_cors_policies", new=AsyncMock(return_value=[])):
        await engine.run(
            target,
            config,
            emit_log=AsyncMock(),
            emit_progress=AsyncMock(),
            emit_finding=AsyncMock(),
            emit_endpoint_discovered=ep_cb,
            client=mock_client,
            active_probing_granted=True,
            organization_id="org-default",
        )

    # ep_static was never a fuzzer candidate:
    # 1. parameter_fuzzer must NOT be in tools_executed
    assert "parameter_fuzzer" not in ep_static.tools_executed
    # 2. ep_static must NOT have SAFE parameter injection record
    static_fuzz_tests = [t for t in ep_static.tests_performed if "Parameter Injection" in t.test_name]
    assert all(t.status != EndpointTestStatus.SAFE for t in static_fuzz_tests)


@pytest.mark.asyncio
async def test_r3_1_cors_partial_failure_forces_skipped_never_safe():
    """
    R3.1 Invariant:
    If one CORS probe succeeds (arbitrary-origin) but another times out (null-origin),
    SAFE is forbidden; the record must be SKIPPED.
    """
    from app.engines.web_dast.cors_analyzer import audit_cors_policies
    from app.engines.web_dast.engine import WebDastAssessmentEngine
    from unittest.mock import patch
    import httpx

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    # Probe 1 (evil origin) returns 200 with no reflection
    evil_resp = MagicMock()
    evil_resp.status_code = 200
    evil_resp.headers = {"access-control-allow-origin": "https://trusted.local"}

    async def mock_get(url, headers=None, **kwargs):
        if headers and headers.get("Origin") == "null":
            raise httpx.ReadTimeout("Null-origin probe timeout")
        return evil_resp

    mock_client.get = AsyncMock(side_effect=mock_get)

    # 1. Direct check returns CorsAuditResult with is_partial=True, is_fully_completed=False
    cors_res = await audit_cors_policies("https://cors-partial.local", client=mock_client)
    assert len(cors_res) == 0  # Zero findings
    assert cors_res.is_fully_completed is False
    assert cors_res.is_partial is True
    assert cors_res.probes_failed == 1
    assert cors_res.probes_completed == 1

    # 2. In engine, record must be SKIPPED, never SAFE
    engine = WebDastAssessmentEngine()
    target = Target(name="test", type=TargetType.URL, value="https://cors-partial.local")
    config = ScanConfig()
    config.fuzzing.enabled = False

    ep = DiscoveredEndpoint(
        url="https://cors-partial.local/api/data",
        method="GET",
        depth=1,
        status_code=200,
        content_type="application/json",
    )

    endpoints = []
    async def ep_cb(e):
        endpoints.append(e)

    def make_crawler(eps, html_dict=None):
        def _factory(*args, **kwargs):
            on_ep = kwargs.get("on_endpoint_discovered")
            async def _crawl():
                if on_ep:
                    for ep in eps:
                        await on_ep(ep)
                return eps
            c = MagicMock()
            c.crawl = AsyncMock(side_effect=_crawl)
            c.page_html = html_dict or {}
            c.page_responses = {}
            return c
        return _factory

    mock_vt = MagicMock()
    mock_vt.canonical_value = target.value

    with patch("app.engines.web_dast.engine.create_validated_target", return_value=mock_vt), \
         patch("app.engines.web_dast.engine.WebCrawler", side_effect=make_crawler([ep], {})):
        await engine.run(
            target,
            config,
            emit_log=AsyncMock(),
            emit_progress=AsyncMock(),
            emit_finding=AsyncMock(),
            emit_endpoint_discovered=ep_cb,
            client=mock_client,
            organization_id="org-default",
        )

    assert len(endpoints) == 1
    cors_tests = [t for t in endpoints[0].tests_performed if "CORS" in t.test_name]
    assert len(cors_tests) == 1
    assert cors_tests[0].status == EndpointTestStatus.SKIPPED
    assert cors_tests[0].status != EndpointTestStatus.SAFE


@pytest.mark.asyncio
async def test_r4_1_sensitive_query_token_preserves_auth_finding_without_falsely_marking_form_csrf_vulnerable():
    """
    R4.1 Invariant:
    A generic authentication finding (e.g. DAST-AUTH-004 for sensitive query token)
    must remain present as a finding, but must NEVER cause the
    'HTML Form & CSRF Token Validation' test record to say
    'Insecure form or missing CSRF token detected' or be marked VULNERABLE.
    """
    from app.engines.web_dast.engine import WebDastAssessmentEngine

    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.text = '{"status": "ok"}'
    mock_client.get = AsyncMock(return_value=mock_resp)

    engine = WebDastAssessmentEngine()
    target = Target(name="test", type=TargetType.URL, value="https://app.local")
    config = ScanConfig()
    config.fuzzing.enabled = False

    # Endpoint contains sensitive token in query string, but no forms
    ep = DiscoveredEndpoint(
        url="https://app.local/api/v1/user?access_token=super_secret_jwt_token_12345",
        method="GET",
        depth=1,
        status_code=200,
        content_type="application/json",
    )

    endpoints = []
    async def ep_cb(e):
        endpoints.append(e)

    findings = []
    async def find_cb(f):
        findings.append(f)

    def make_crawler(eps):
        def _factory(*args, **kwargs):
            on_ep = kwargs.get("on_endpoint_discovered")
            async def _crawl():
                if on_ep:
                    for ep in eps:
                        await on_ep(ep)
                return eps
            c = MagicMock()
            c.crawl = AsyncMock(side_effect=_crawl)
            c.page_html = {}
            c.page_responses = {}
            return c
        return _factory

    mock_vt = MagicMock()
    mock_vt.canonical_value = target.value

    with patch("app.engines.web_dast.engine.create_validated_target", return_value=mock_vt), \
         patch("app.engines.web_dast.engine.WebCrawler", side_effect=make_crawler([ep])):
        result_findings = await engine.run(
            target,
            config,
            emit_log=AsyncMock(),
            emit_progress=AsyncMock(),
            emit_finding=find_cb,
            emit_endpoint_discovered=ep_cb,
            client=mock_client,
            organization_id="org-default",
        )

    # 1. DAST-AUTH-004 must be detected and present
    auth_finds = [f for f in result_findings if f.check_id == "DAST-AUTH-004"]
    assert len(auth_finds) == 1, f"Expected DAST-AUTH-004 finding, found: {[f.check_id for f in result_findings]}"
    assert "access_token" in auth_finds[0].title

    # 2. Form/CSRF test record must NOT be VULNERABLE and must NOT claim insecure form
    assert len(endpoints) == 1
    form_tests = [t for t in endpoints[0].tests_performed if "Form & CSRF" in t.test_name]
    assert len(form_tests) == 1
    assert form_tests[0].status != EndpointTestStatus.VULNERABLE, (
        f"DAST-AUTH-004 falsely contaminated form/CSRF record: {form_tests[0]}"
    )
    assert form_tests[0].status == EndpointTestStatus.NOT_EXECUTED
    assert "Insecure form" not in form_tests[0].details
    assert "missing CSRF token" not in form_tests[0].details


@pytest.mark.asyncio
async def test_r4_2_endpoint_with_no_discovered_parameters_never_receives_fuzzer_safe_result():
    """
    R4.2 Invariant:
    When no real fuzzing candidates exist (no query parameters on target or endpoints),
    parameter fuzzer must NOT invent '?id=1&search=test&redirect=home'.
    The endpoint must yield NOT_EXECUTED, never SAFE, and parameter_fuzzer must not be in tools_executed.
    """
    from app.engines.web_dast.engine import WebDastAssessmentEngine
    from app.engines.web_dast.parameter_fuzzer import audit_parameter_fuzzing

    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "text/html"}
    mock_resp.text = "<html><body><h1>Static Info Page</h1></body></html>"
    mock_client.get = AsyncMock(return_value=mock_resp)

    # 1. Direct unit test of audit_parameter_fuzzing: zero executions when no parameters exist
    config = ScanConfig()
    config.fuzzing.enabled = True
    config.fuzzing.fuzz_sqli = True

    static_ep = DiscoveredEndpoint(
        url="https://app.local/about",
        method="GET",
        depth=1,
        status_code=200,
        content_type="text/html",
    )

    res = await audit_parameter_fuzzing(
        target_url="https://app.local",
        discovered_endpoints=[static_ep],
        client=mock_client,
        config=config,
        scan_id="scan-fuzz-empty",
    )
    # Executions dict must be empty — no synthesized URLs!
    assert len(res.executions) == 0, f"Expected 0 executions, but found synthesized URLs: {list(res.executions.keys())}"
    assert len(res) == 0

    # 2. Integration test through engine: ep receives NOT_EXECUTED, never SAFE
    engine = WebDastAssessmentEngine()
    target = Target(name="test", type=TargetType.URL, value="https://app.local")

    endpoints = []
    async def ep_cb(e):
        endpoints.append(e)

    def make_crawler(eps):
        def _factory(*args, **kwargs):
            on_ep = kwargs.get("on_endpoint_discovered")
            async def _crawl():
                if on_ep:
                    for ep in eps:
                        await on_ep(ep)
                return eps
            c = MagicMock()
            c.crawl = AsyncMock(side_effect=_crawl)
            c.page_html = {"https://app.local/about": "<html><body><h1>Static Info</h1></body></html>"}
            c.page_responses = {}
            return c
        return _factory

    mock_vt = MagicMock()
    mock_vt.canonical_value = target.value

    with patch("app.engines.web_dast.engine.create_validated_target", return_value=mock_vt), \
         patch("app.engines.web_dast.engine.WebCrawler", side_effect=make_crawler([static_ep])):
        await engine.run(
            target,
            config,
            emit_log=AsyncMock(),
            emit_progress=AsyncMock(),
            emit_finding=AsyncMock(),
            emit_endpoint_discovered=ep_cb,
            client=mock_client,
            organization_id="org-default",
            active_probing_granted=True,
        )

    assert len(endpoints) == 1
    assert "parameter_fuzzer" not in endpoints[0].tools_executed

    fuzz_tests = [t for t in endpoints[0].tests_performed if "Active Parameter Injection" in t.test_name]
    assert len(fuzz_tests) == 1
    assert fuzz_tests[0].status == EndpointTestStatus.NOT_EXECUTED
    assert fuzz_tests[0].status != EndpointTestStatus.SAFE


@pytest.mark.asyncio
async def test_r4_3_form_transport_truthfulness_matrix():
    """
    R4.3 Invariant:
    - HTTPS page -> HTTPS form action = clean transport (SAFE)
    - HTTPS page -> HTTP form action = vulnerable (DAST-FORM-001 / VULNERABLE)
    - HTTP page -> HTTP POST form = vulnerable (DAST-FORM-001 / VULNERABLE, must not be called secure)
    """
    from app.core.models import AuthConfig
    from app.engines.web_dast.auth_session import AuthSessionManager

    mock_client = AsyncMock()

    # Case 1: HTTPS page -> HTTPS form (with valid CSRF token)
    mgr1 = AuthSessionManager(target_url="https://secure.local", config=AuthConfig(), client=mock_client, scan_id="s1")
    ep1 = DiscoveredEndpoint(url="https://secure.local/login", method="GET", depth=1, status_code=200, content_type="text/html")
    html1 = {
        "https://secure.local/login": """
        <html><body>
          <form action="https://secure.local/api/login" method="POST">
            <input type="hidden" name="csrf_token" value="valid_token_xyz" />
            <input type="text" name="user" />
          </form>
        </body></html>
        """
    }
    res1 = await mgr1.audit_auth_and_forms([ep1], html1)
    form_finds1 = [f for f in res1.findings if f.check_id in ("DAST-FORM-001", "DAST-FORM-002")]
    assert len(form_finds1) == 0, f"Expected 0 form findings on clean HTTPS form, got: {form_finds1}"
    exec1 = res1.form_executions.get("https://secure.local/login")
    assert exec1 is not None and len(exec1.findings) == 0
    assert exec1.forms_inspected == 1

    # Case 2: HTTPS page -> HTTP form action (mixed-content cleartext submission)
    mgr2 = AuthSessionManager(target_url="https://secure.local", config=AuthConfig(), client=mock_client, scan_id="s2")
    ep2 = DiscoveredEndpoint(url="https://secure.local/feedback", method="GET", depth=1, status_code=200, content_type="text/html")
    html2 = {
        "https://secure.local/feedback": """
        <html><body>
          <form action="http://insecure.local/submit" method="POST">
            <input type="hidden" name="_csrf" value="token123" />
            <input type="text" name="comment" />
          </form>
        </body></html>
        """
    }
    res2 = await mgr2.audit_auth_and_forms([ep2], html2)
    form_finds2 = [f for f in res2.findings if f.check_id == "DAST-FORM-001"]
    assert len(form_finds2) == 1, "Expected DAST-FORM-001 for HTTPS page -> HTTP form"
    assert "Insecure Cleartext Form Action on HTTPS Page" in form_finds2[0].title

    # Case 3: HTTP page -> HTTP POST form (cleartext state-changing form)
    mgr3 = AuthSessionManager(target_url="http://plain.local", config=AuthConfig(), client=mock_client, scan_id="s3")
    ep3 = DiscoveredEndpoint(url="http://plain.local/settings", method="GET", depth=1, status_code=200, content_type="text/html")
    html3 = {
        "http://plain.local/settings": """
        <html><body>
          <form action="http://plain.local/update" method="POST">
            <input type="hidden" name="csrf_token" value="token456" />
            <input type="text" name="email" />
          </form>
        </body></html>
        """
    }
    res3 = await mgr3.audit_auth_and_forms([ep3], html3)
    form_finds3 = [f for f in res3.findings if f.check_id == "DAST-FORM-001"]
    assert len(form_finds3) == 1, "Expected DAST-FORM-001 for HTTP POST form; must not be called secure"
    assert "Insecure Cleartext State-Changing Form Action" in form_finds3[0].title



