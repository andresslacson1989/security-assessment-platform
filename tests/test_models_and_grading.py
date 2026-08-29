"""
Test suite verifying Core Models, Deterministic Grading Engine, and Storage Layer.
"""

from datetime import datetime, timezone
import shutil
import tempfile
from pathlib import Path
import pytest

from app.core.models import (
    Severity,
    TargetType,
    ScanProfile,
    ScanStatus,
    LogLevel,
    Target,
    Evidence,
    Finding,
    ScanJobSummary,
    LogEntry,
    ScanConfig,
    ScanJob,
    calculate_fingerprint,
    mask_secret,
)
from app.core.grading import calculate_scan_grade
from app.core.storage import save_scan, get_scan, list_scans, delete_scan


def test_target_and_evidence_models():
    target = Target(
        name="Test Target",
        type=TargetType.URL,
        value="https://example.com",
    )
    assert target.id is not None
    assert target.name == "Test Target"
    assert target.type == TargetType.URL
    assert target.value == "https://example.com"

    evidence = Evidence(
        location="https://example.com",
        observed_value="Server: Apache/2.4.41",
        expected_value="Generic Server Banner",
    )
    assert evidence.location == "https://example.com"
    assert evidence.observed_value == "Server: Apache/2.4.41"


def test_fingerprint_and_secret_masking():
    # Fingerprint determinism
    fp1 = calculate_fingerprint("DAST-HDR-001", "https://example.com", "Missing CSP")
    fp2 = calculate_fingerprint("DAST-HDR-001", "https://example.com", "Missing CSP")
    fp3 = calculate_fingerprint("DAST-HDR-001", "https://example.com", "Different")
    assert fp1 == fp2
    assert fp1 != fp3
    assert len(fp1) == 64  # SHA256 hex length

    # Secret masking
    raw_key = "AKIAIOSFODNN7EXAMPLE"
    masked = mask_secret(raw_key)
    assert masked.startswith("AKIA")
    assert masked.endswith("PLE")
    assert "IOSFODNN7EXAM" not in masked
    assert "*" in masked

    short_secret = "secret1"
    assert mask_secret(short_secret) == "*******"


def create_sample_finding(severity: Severity, title: str, check_id: str = "TEST-001") -> Finding:
    return Finding(
        scan_id="00000000-0000-0000-0000-000000000000",
        engine="network",
        check_id=check_id,
        category="Test Category",
        title=title,
        severity=severity,
        cvss_score=9.1 if severity == Severity.CRITICAL else (7.5 if severity == Severity.HIGH else (5.0 if severity == Severity.MEDIUM else 3.0)),
        description="Test description",
        impact="Test impact",
        remediation="Test remediation",
        evidence=Evidence(
            location="https://example.com",
            observed_value="Observed Test",
            expected_value="Expected Test",
        ),
        fingerprint=calculate_fingerprint(check_id, "https://example.com", "Observed Test"),
    )


def test_grading_perfect_a_plus():
    findings = [
        Finding(
            scan_id="00000000-0000-0000-0000-000000000000",
            engine="network",
            check_id="NET-INFO-001",
            category="Information",
            title="TLS 1.3 Active",
            severity=Severity.INFO,
            cvss_score=0.0,
            description="Info note",
            impact="None",
            remediation="None",
            evidence=Evidence(location="443", observed_value="TLS 1.3", expected_value="TLS 1.3"),
            fingerprint=calculate_fingerprint("NET-INFO-001", "443", "TLS 1.3"),
        )
    ]
    summary = calculate_scan_grade(findings, total_checks_evaluated=20, passed_checks=19)
    assert summary.weighted_score == 100.0
    assert summary.overall_security_grade == "A+"
    assert summary.critical_count == 0
    assert summary.total_findings == 1


def test_grading_grade_a():
    findings = [
        create_sample_finding(Severity.LOW, "Server Header Leak", "DAST-HDR-007"),
        create_sample_finding(Severity.LOW, "Missing Referrer-Policy", "DAST-HDR-006"),
    ]
    summary = calculate_scan_grade(findings)
    # Score = 100 - 2 = 98.0, but with 2 low findings -> A
    assert summary.weighted_score == 98.0
    assert summary.overall_security_grade == "A"


def test_grading_grade_b():
    findings = [
        create_sample_finding(Severity.MEDIUM, "Missing CSP", "DAST-HDR-001"),
        create_sample_finding(Severity.LOW, "Server Header Leak", "DAST-HDR-007"),
    ]
    summary = calculate_scan_grade(findings)
    # Score = 100 - 5 - 1 = 94.0. Because 1 Medium present -> Grade B
    assert summary.weighted_score == 94.0
    assert summary.overall_security_grade == "B"


def test_grading_grade_c():
    findings = [
        create_sample_finding(Severity.MEDIUM, "Missing CSP", "DAST-HDR-001"),
        create_sample_finding(Severity.MEDIUM, "Missing HSTS", "DAST-HDR-002"),
        create_sample_finding(Severity.MEDIUM, "Missing X-Frame", "DAST-HDR-004"),
    ]
    summary = calculate_scan_grade(findings)
    # Score = 100 - 15 = 85.0. 3 Medium findings -> Grade C
    assert summary.weighted_score == 85.0
    assert summary.overall_security_grade == "C"


def test_grading_grade_d():
    findings = [
        create_sample_finding(Severity.HIGH, "Exposed Database Port", "NET-PORT-001"),
    ]
    summary = calculate_scan_grade(findings)
    # Score = 100 - 15 = 85.0. But 1 High finding present -> Grade D
    assert summary.weighted_score == 85.0
    assert summary.overall_security_grade == "D"


def test_grading_grade_f_critical_override():
    findings = [
        create_sample_finding(Severity.CRITICAL, "Exposed .env file", "DAST-EXP-001"),
    ]
    summary = calculate_scan_grade(findings)
    # Score = 100 - 35 = 65.0. But ANY Critical finding MUST FORCE Grade F
    assert summary.weighted_score == 65.0
    assert summary.overall_security_grade == "F"


def test_storage_lifecycle():
    temp_dir = Path(tempfile.mkdtemp())
    try:
        target = Target(name="Local App", type=TargetType.URL, value="http://localhost:3000")
        scan_job = ScanJob(
            target=target,
            profile=ScanProfile.FULL_STACK,
            status=ScanStatus.RUNNING,
            progress_percent=50,
            current_stage="Testing DAST...",
        )
        
        # Save scan
        save_scan(scan_job, storage_dir=temp_dir)
        
        # Retrieve scan
        retrieved = get_scan(scan_job.id, storage_dir=temp_dir)
        assert retrieved is not None
        assert retrieved.id == scan_job.id
        assert retrieved.target.name == "Local App"
        assert retrieved.status == ScanStatus.RUNNING
        assert retrieved.progress_percent == 50
        
        # List scans
        scans, total = list_scans(limit=10, offset=0, storage_dir=temp_dir)
        assert total == 1
        assert len(scans) == 1
        assert scans[0].id == scan_job.id
        
        # Delete scan
        deleted = delete_scan(scan_job.id, storage_dir=temp_dir)
        assert deleted is True
        
        # Verify deleted
        assert get_scan(scan_job.id, storage_dir=temp_dir) is None
        scans_after, total_after = list_scans(limit=10, offset=0, storage_dir=temp_dir)
        assert total_after == 0
    finally:
        shutil.rmtree(temp_dir)
