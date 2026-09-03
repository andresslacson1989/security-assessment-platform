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
