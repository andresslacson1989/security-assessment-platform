"""Evidence-truth assurance for the 2026-09-03 audit closure."""

from __future__ import annotations

import pytest

from app.api import scans as scans_api
from app.core.models import (
    DiscoveredEndpoint,
    Finding,
    FindingVerificationStatus,
    PrincipalType,
    ScanJob,
    Severity,
    Target,
    TargetType,
    UserProfile,
    UserRole,
)


def _job() -> ScanJob:
    return ScanJob(
        id="scan-evidence-truth",
        organization_id="org-one",
        target=Target(name="example", type=TargetType.URL, value="https://example.com"),
        enabled_engines=["web_dast"],
    )


def test_no_execution_evidence_produces_no_tool_telemetry():
    assert scans_api._tool_telemetry_from_authoritative_evidence(_job()) == {}


def test_recorded_zero_finding_completion_is_required_for_pass():
    job = _job()
    job.tool_execution_states["nuclei"] = "COMPLETED_NO_FINDINGS"
    job.tool_execution_engines["nuclei"] = "web_dast"
    telemetry = scans_api._tool_telemetry_from_authoritative_evidence(job)["nuclei"]
    assert telemetry.status.value == "PASS"
    assert telemetry.normalized_state == "COMPLETED_NO_FINDINGS"


def test_finding_does_not_overwrite_recorded_failed_state():
    job = _job()
    job.tool_execution_states["nuclei"] = "TOOL_EXECUTION_FAILED"
    job.tool_execution_engines["nuclei"] = "web_dast"
    job.findings.append(Finding(
        check_id="DAST-CVE-TEST",
        category="Vulnerability",
        title="Partial finding before upstream failure",
        severity=Severity.MEDIUM,
        description="test",
        impact="test",
        remediation="test",
        source_tool="nuclei",
        engine="web_dast",
        verification_status=FindingVerificationStatus.DETECTED,
    ))
    telemetry = scans_api._tool_telemetry_from_authoritative_evidence(job)["nuclei"]
    assert telemetry.status.value == "FAILED"
    assert telemetry.findings_count == 1


@pytest.mark.asyncio
async def test_telemetry_endpoint_does_not_manufacture_endpoint_tools_or_safe_tests(monkeypatch):
    job = _job()
    job.discovered_endpoints.append(DiscoveredEndpoint(url="https://example.com/account"))
    monkeypatch.setattr(scans_api.orchestrator, "get_active_job", lambda *args, **kwargs: job)

    user = UserProfile(
        id="usr-analyst",
        username="analyst",
        email="analyst@example.test",
        role=UserRole.SECURITY_ANALYST,
        principal_type=PrincipalType.TENANT_PRINCIPAL,
        organization_id="org-one",
        scopes=["scan:read"],
    )
    report = await scans_api.get_scan_telemetry(
        scan_id=job.id,
        tool=None,
        engine=None,
        level=None,
        search=None,
        current_user=user,
    )
    endpoint = report.discovered_endpoints[0]
    assert endpoint.tools_executed == []
    assert endpoint.tests_performed == []
    assert report.coverage.is_fully_assessed is False
    assert report.coverage.coverage_status == "COVERAGE_DEGRADED"
