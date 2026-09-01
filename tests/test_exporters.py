"""
Unit tests for Compliance & Security Exporters (HTML, SARIF v2.1.0, JSON).
"""

import json
import pytest

from app.core.models import (
    Target,
    TargetType,
    ScanJob,
    ScanProfile,
    ScanStatus,
    Finding,
    Evidence,
    Severity,
    calculate_fingerprint,
)
from app.core.version import APP_VERSION
from app.core.grading import calculate_scan_grade
from app.exporters.html_exporter import export_scan_to_html
from app.exporters.sarif_exporter import export_scan_to_sarif, severity_to_sarif_level
from app.exporters.json_exporter import export_scan_to_json


def create_sample_job() -> ScanJob:
    target = Target(name="Production Web App", type=TargetType.URL, value="https://app.example.com")
    f1 = Finding(
        scan_id="00000000-0000-0000-0000-000000000000",
        engine="web_dast",
        check_id="DAST-EXP-001",
        category="Information Exposure",
        title="Publicly Exposed .env File",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_id="CWE-552",
        owasp_category="A01:2021-Broken Access Control",
        nist_control="AC-3",
        description="Public .env file accessible over HTTP",
        impact="Total compromise",
        remediation="Block access to dotfiles",
        remediation_code_snippet="location ~ /\\.(?!well-known).* { deny all; }",
        evidence=Evidence(
            location="https://app.example.com/.env",
            observed_value="DB_PASSWORD=***",
            expected_value="404 Not Found",
        ),
        fingerprint=calculate_fingerprint("DAST-EXP-001", "https://app.example.com/.env", "DB_PASSWORD=***"),
    )
    f2 = Finding(
        scan_id="00000000-0000-0000-0000-000000000000",
        engine="network",
        check_id="NET-TLS-003",
        category="SSL/TLS Infrastructure",
        title="Certificate Expiring in < 30 Days",
        severity=Severity.MEDIUM,
        cvss_score=5.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cwe_id="CWE-295",
        owasp_category="A02:2021-Cryptographic Failures",
        nist_control="SC-8",
        description="SSL cert expires in 15 days",
        impact="Service outage if not renewed",
        remediation="Renew certbot timer",
        evidence=Evidence(
            location="app.example.com:443",
            observed_value="15 days remaining",
            expected_value=">30 days",
        ),
        fingerprint=calculate_fingerprint("NET-TLS-003", "app.example.com:443", "15_days"),
    )

    job = ScanJob(
        target=target,
        profile=ScanProfile.FULL_STACK,
        status=ScanStatus.COMPLETED,
        progress_percent=100,
        findings=[f1, f2],
    )
    job.summary = calculate_scan_grade(job.findings, duration_seconds=12.5)
    return job


def test_html_exporter_offline_guarantee():
    job = create_sample_job()
    html_output = export_scan_to_html(job)

    # 1. Zero CDN dependencies verification
    assert "https://cdn." not in html_output
    assert "https://cdnjs." not in html_output
    assert "https://fonts.googleapis.com" not in html_output
    assert "<script src=" not in html_output  # No external script references

    # 2. Contains essential dark theme classes and elements
    assert "scorecard-panel" in html_output
    assert "finding-card" in html_output
    assert "DAST-EXP-001" in html_output
    assert "NET-TLS-003" in html_output
    assert "CVSS 9.8" in html_output
    assert "copySnippet" in html_output


def test_sarif_exporter_v210():
    job = create_sample_job()
    sarif = export_scan_to_sarif(job)

    # Validate SARIF root
    assert sarif["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in sarif["$schema"]
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "CyberAssess Security Scanner"
    assert len(driver["rules"]) == 2

    # Validate rules catalog
    rule_ids = [r["id"] for r in driver["rules"]]
    assert "DAST-EXP-001" in rule_ids
    assert "NET-TLS-003" in rule_ids

    # Validate results mapping
    results = run["results"]
    assert len(results) == 2
    assert results[0]["ruleId"] == "DAST-EXP-001"
    assert results[0]["level"] == "error"  # Critical -> error
    assert results[1]["ruleId"] == "NET-TLS-003"
    assert results[1]["level"] == "warning"  # Medium -> warning


def test_json_exporter_roundtrip():
    job = create_sample_job()
    json_str = export_scan_to_json(job)

    # Validate parseable JSON
    parsed = json.loads(json_str)
    assert parsed["id"] == job.id
    assert parsed["target"]["name"] == "Production Web App"
    assert len(parsed["findings"]) == 2

    # Validate ScanJob deserialization roundtrip
    restored_job = ScanJob.model_validate(parsed)
    assert restored_job.id == job.id
    assert restored_job.summary.overall_security_grade == "F"  # Critical finding forces F


def test_cyclonedx_sbom_exporter():
    from app.exporters.sbom_cyclonedx import export_cyclonedx_sbom
    from app.core.models import SBOMReport, SBOMComponent, SBOMExportFormat

    job = create_sample_job()
    job.sbom_report = SBOMReport(
        format=SBOMExportFormat.CYCLONEDX_JSON,
        components_count=2,
        components=[
            SBOMComponent(name="express", version="4.17.1", type="library", purl="pkg:npm/express@4.17.1", license="MIT"),
            SBOMComponent(name="lodash", version="4.17.20", type="library", purl="pkg:npm/lodash@4.17.20", license="MIT"),
        ],
    )
    cdx_str = export_cyclonedx_sbom(job)
    parsed = json.loads(cdx_str)

    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["metadata"]["tools"][0]["version"] == APP_VERSION
    assert parsed["specVersion"] == "1.5"
    assert len(parsed["components"]) == 2
    assert parsed["components"][0]["name"] == "express"
    assert parsed["components"][0]["version"] == "4.17.1"


def test_spdx_sbom_exporter():
    from app.exporters.sbom_spdx import export_spdx_sbom
    from app.core.models import SBOMReport, SBOMComponent, SBOMExportFormat

    job = create_sample_job()
    job.sbom_report = SBOMReport(
        format=SBOMExportFormat.SPDX_JSON,
        components_count=2,
        components=[
            SBOMComponent(name="requests", version="2.28.1", type="library", purl="pkg:pypi/requests@2.28.1", license="Apache-2.0"),
            SBOMComponent(name="cryptography", version="38.0.0", type="library", purl="pkg:pypi/cryptography@38.0.0", license="Apache-2.0"),
        ],
    )
    spdx_str = export_spdx_sbom(job)
    parsed = json.loads(spdx_str)

    assert parsed["spdxVersion"] == "SPDX-2.3"
    assert f"Tool: CyberAssess-{APP_VERSION}" in parsed["creationInfo"]["creators"]
    assert parsed["dataLicense"] == "CC0-1.0"
    # Root package + 2 component packages = 3 packages
    assert len(parsed["packages"]) == 3
    assert parsed["packages"][1]["name"] == "requests"
    assert len(parsed["relationships"]) == 2
