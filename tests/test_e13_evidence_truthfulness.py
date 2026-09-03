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

from unittest.mock import AsyncMock, patch
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

