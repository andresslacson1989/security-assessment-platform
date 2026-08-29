"""
Test suite verifying Core Models, Deterministic Grading Engine, and Storage Layer (v4.1.0).
Authoritative Reference: contracts/02_DATA_SCHEMA_AND_MODELS_CONTRACT.md
"""

from datetime import datetime, timezone
import json
import shutil
import tempfile
from pathlib import Path
import pytest

from app.core.models import (
    Severity,
    TargetType,
    ScanProfile,
    ScanStatus,
    SecurityGrade,
    LogLevel,
    AuthType,
    ToolExecutionMode,
    CrawlerConfig,
    CrawlConfig,
    AuthConfig,
    FuzzingConfig,
    OSINTConfig,
    OsintConfig,
    ToolAdapterConfig,
    DiscoveredEndpoint,
    DiscoveredSubdomain,
    ToolStatus,
    SystemCapabilities,
    Target,
    Evidence,
    Finding,
    ScanJobSummary,
    LogEntry,
    ScanConfig,
    ScanJob,
    ScanCreateRequest,
    StartScanRequest,
    ScanStartResponse,
    RepeaterRequest,
    RepeaterResponse,
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
        request_details={"method": "GET", "url": "https://example.com"},
        response_details={"status_code": 200},
    )
    assert evidence.location == "https://example.com"
    assert evidence.observed_value == "Server: Apache/2.4.41"
    assert evidence.request_details["method"] == "GET"


def test_auth_and_crawler_models():
    # 1. AuthConfig defaults and customization
    auth = AuthConfig(
        auth_type=AuthType.HEADER,
        headers={"Authorization": "Bearer test-jwt-token"},
        cookies={"sessionid": "sess_12345"},
    )
    assert auth.auth_type == AuthType.HEADER
    assert auth.headers["Authorization"] == "Bearer test-jwt-token"
    assert "logout" in auth.logout_url_patterns

    # 2. Form Login AuthConfig
    form_auth = AuthConfig(
        auth_type=AuthType.FORM_LOGIN,
        login_url="https://example.com/login",
        username="admin",
        password="secretpassword",
        csrf_token_field="_csrf",
        logged_in_indicator="Welcome, admin",
    )
    assert form_auth.auth_type == AuthType.FORM_LOGIN
    assert form_auth.username == "admin"
    assert form_auth.password == "secretpassword"

    # 3. CrawlerConfig validation
    crawler = CrawlerConfig(
        enabled=True,
        max_depth=4,
        max_pages=100,
        exclude_patterns=["*logout*", "*signout*"],
        respect_robots=True,
    )
    assert crawler.max_depth == 4
    assert crawler.max_pages == 100
    assert crawler.follow_redirects is True
    assert crawler.parse_sitemap is True
    assert crawler.respect_robots is True
    assert CrawlConfig is CrawlerConfig

    # 4. DiscoveredEndpoint
    endpoint = DiscoveredEndpoint(
        url="https://example.com/dashboard",
        method="GET",
        depth=1,
        status_code=200,
        content_type="text/html",
        is_authenticated=True,
        has_forms=True,
        discovered_forms=2,
    )
    assert endpoint.url == "https://example.com/dashboard"
    assert endpoint.depth == 1
    assert endpoint.is_authenticated is True
    assert endpoint.has_forms is True
    assert endpoint.discovered_forms == 2

    # 5. ScanConfig with crawler, auth, fuzzing, osint, adapters
    cfg = ScanConfig(
        rate_limit_rps=10,
        crawler=crawler,
        auth=auth,
        fuzzing=FuzzingConfig(enabled=True, delay_seconds=3.0),
        osint=OSINTConfig(subdomain_enumeration=True),
        adapters=ToolAdapterConfig(enable_nmap=True, custom_nmap_path="/usr/bin/nmap"),
    )
    assert cfg.crawler.max_depth == 4
    assert cfg.auth.auth_type == AuthType.HEADER
    assert cfg.fuzzing.delay_seconds == 3.0
    assert cfg.osint.subdomain_enumeration is True
    assert cfg.adapters.nmap_path == "/usr/bin/nmap"
    assert cfg.adapters.custom_nmap_path == "/usr/bin/nmap"

    # 6. ScanJob serialization with discovered_endpoints, subdomains and summary
    subdomain = DiscoveredSubdomain(
        domain="api.example.com",
        ip_addresses=["93.184.216.34"],
        cname_targets=["api.example.com.cdn.cloudflare.net"],
        is_takeover_vulnerable=False,
        service_fingerprint="Cloudflare",
    )
    target = Target(name="Web Target", type=TargetType.URL, value="https://example.com")
    job = ScanJob(
        target=target,
        config=cfg,
        discovered_endpoints=[endpoint],
        discovered_subdomains=[subdomain],
        active_adapters=["nmap", "semgrep"],
    )
    job.summary.pages_crawled = 15
    job.summary.authenticated_session_active = True
    job.summary.subdomains_discovered = 1
    job.summary.active_adapters = ["nmap", "semgrep"]

    # JSON roundtrip validation
    json_data = json.loads(job.model_dump_json())
    assert len(json_data["discovered_endpoints"]) == 1
    assert json_data["discovered_endpoints"][0]["url"] == "https://example.com/dashboard"
    assert len(json_data["discovered_subdomains"]) == 1
    assert json_data["discovered_subdomains"][0]["domain"] == "api.example.com"
    assert json_data["summary"]["pages_crawled"] == 15
    assert json_data["summary"]["authenticated_session_active"] is True
    assert json_data["summary"]["subdomains_discovered"] == 1
    assert json_data["summary"]["active_adapters"] == ["nmap", "semgrep"]
    assert json_data["config"]["auth"]["auth_type"] == "HEADER"


def test_enums_completeness():
    # Severity
    assert [s.value for s in Severity] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    # TargetType
    assert set(t.value for t in TargetType) == {"URL", "DOMAIN", "IP", "LOCAL_PATH", "DOCKERFILE", "IAC_MANIFEST"}

    # ScanProfile
    expected_profiles = {
        "FULL_STACK", "QUICK", "QUICK_AUDIT", "DAST_ONLY", "SAST_ONLY",
        "NETWORK_ONLY", "NETWORK_TLS", "INFRA_ONLY", "INFRA_CONTAINER",
        "API_FOCUSED", "PASSIVE_OSINT", "CUSTOM"
    }
    for p in expected_profiles:
        assert ScanProfile(p) is not None

    # ScanStatus
    assert set(s.value for s in ScanStatus) == {"PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"}

    # SecurityGrade
    assert SecurityGrade.A_PLUS.value == "A+"
    assert SecurityGrade.A.value == "A"
    assert SecurityGrade.B.value == "B"
    assert SecurityGrade.C.value == "C"
    assert SecurityGrade.D.value == "D"
    assert SecurityGrade.F.value == "F"

    # LogLevel
    assert set(l.value for l in LogLevel) == {"INFO", "WARNING", "ERROR", "DEBUG"}

    # AuthType
    assert set(a.value for a in AuthType) == {"NO_AUTH", "NONE", "HEADER", "COOKIE", "FORM_LOGIN"}

    # ToolExecutionMode
    assert set(m.value for m in ToolExecutionMode) == {"ADAPTER_ACTIVE", "NATIVE_FALLBACK", "DISABLED"}


def test_tool_status_and_system_capabilities():
    tool = ToolStatus(
        name="nmap",
        available=True,
        version="Nmap 7.94",
        path="/usr/bin/nmap",
        execution_mode=ToolExecutionMode.ADAPTER_ACTIVE,
    )
    assert tool.name == "nmap"
    assert tool.available is True
    assert tool.execution_mode == ToolExecutionMode.ADAPTER_ACTIVE

    caps = SystemCapabilities(
        tools=[tool],
        native_engines_ready=True,
        os_platform="Windows 11",
    )
    assert len(caps.tools) == 1
    assert caps.native_engines_ready is True
    assert caps.os_platform == "Windows 11"


def test_api_models():
    # ScanCreateRequest
    req = ScanCreateRequest(
        target_type=TargetType.URL,
        target_value="https://example.com",
        target_name="Production Portal",
        profile=ScanProfile.FULL_STACK,
        enabled_engines=["network", "web_dast"],
    )
    assert req.target_type == TargetType.URL
    assert req.target_value == "https://example.com"
    assert StartScanRequest is ScanCreateRequest

    # ScanStartResponse
    res = ScanStartResponse(
        scan_id="c4b3f8e2-9d3a-4a61-9c88-123456789abc",
        status=ScanStatus.RUNNING,
        message="Scan launched.",
    )
    assert res.scan_id == "c4b3f8e2-9d3a-4a61-9c88-123456789abc"
    assert res.status == ScanStatus.RUNNING

    # RepeaterRequest & RepeaterResponse
    rep_req = RepeaterRequest(
        url="https://example.com/api/v1/user?id=1",
        method="GET",
        headers={"Authorization": "Bearer sample_token"},
        follow_redirects=False,
        timeout_seconds=10.0,
    )
    assert rep_req.url == "https://example.com/api/v1/user?id=1"
    assert rep_req.method == "GET"

    rep_res = RepeaterResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        body='{"id": 1, "name": "Admin"}',
        duration_ms=142.5,
        content_length=27,
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
    )
    assert rep_res.status_code == 200
    assert rep_res.duration_ms == 142.5
    assert rep_res.tls_version == "TLSv1.3"


def test_finding_model_extensions():
    finding = Finding(
        scan_id="00000000-0000-0000-0000-000000000000",
        engine="web_dast",
        source_tool="nuclei",
        check_id="DAST-INJ-001",
        category="Injection",
        title="Time-Based Blind SQL Injection",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        description="SQL injection vulnerability discovered in query param",
        impact="Full database compromise",
        remediation="Use parameterized queries",
        evidence=Evidence(
            location="https://example.com/items?id=1",
            observed_value="Response delayed by 5.2s",
            expected_value="Response returned in < 500ms",
        ),
        reproduction_curl="curl -X GET 'https://example.com/items?id=1%27%20WAITFOR%20DELAY%20%270:0:5%27--'",
        taint_trace=["request.GET['id']", "cursor.execute(query)"],
        fingerprint=calculate_fingerprint("DAST-INJ-001", "https://example.com/items?id=1", "Response delayed by 5.2s"),
    )
    assert finding.source_tool == "nuclei"
    assert finding.reproduction_curl.startswith("curl")
    assert finding.taint_trace == ["request.GET['id']", "cursor.execute(query)"]
    assert len(finding.fingerprint) == 64


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
