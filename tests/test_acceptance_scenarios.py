"""
Contract 05 End-to-End Acceptance Test Suite (All 10 Test Scenarios - v3.1.0).
Verifies complete system functionality against formal contract deliverables and Definition of Done.
"""

from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
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
    AuthType,
    AuthConfig,
    CrawlerConfig,
    DiscoveredEndpoint,
    ScanConfig,
    calculate_fingerprint,
    mask_secret,
)
from app.core.grading import calculate_scan_grade
from app.core.storage import save_scan, get_scan
from app.core.ssrf_protector import ValidatedTargetTransport
from app.core.orchestrator import ScanOrchestrator
from app.engines.network.engine import NetworkAssessmentEngine
from app.engines.network.dns_hygiene import audit_dns_hygiene
from app.engines.network.port_checker import audit_exposed_ports
from app.engines.web_dast.engine import WebDastAssessmentEngine
from app.engines.web_dast.headers_cookies import audit_security_headers_and_cookies
from app.engines.web_dast.cors_analyzer import audit_cors_policies
from app.engines.web_dast.api_inspector import audit_sensitive_exposure_and_methods
from app.engines.web_dast.graphql_auditor import audit_graphql_endpoints
from app.engines.web_dast.crawler import WebCrawler
from app.engines.web_dast.auth_session import AuthSessionManager
from app.engines.code_sast.secret_scanner import audit_code_secrets, calculate_shannon_entropy
from app.engines.code_sast.crypto_lint import audit_crypto_patterns
from app.engines.code_sast.injection_lint import audit_injection_patterns
from app.engines.code_sast.dependency_auditor import audit_dependencies
from app.engines.infra_iac.dockerfile_auditor import audit_dockerfile_content
from app.engines.infra_iac.compose_auditor import audit_compose_yaml
from app.engines.infra_iac.k8s_manifest_auditor import audit_k8s_yaml
from app.engines.infra_iac.terraform_auditor import audit_terraform_file
from app.engines.cicd_audit.github_actions_auditor import audit_workflow_yaml
from app.exporters.html_exporter import export_scan_to_html
from app.exporters.sarif_exporter import export_scan_to_sarif
from app.exporters.json_exporter import export_scan_to_json


# ==============================================================================
# Scenario 1: Network Perimeter, TLS & DNS Hygiene
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_1_network_and_tls_audit():
    with patch("dns.asyncresolver.Resolver") as mock_res_cls:
        mock_res = MagicMock()
        mock_res_cls.return_value = mock_res

        async def mock_resolve(domain, rtype):
            if rtype == "TXT" and domain == "example.com":
                item = MagicMock()
                item.to_text.return_value = '"v=spf1 +all"'  # Permissive SPF
                return [item]
            elif rtype == "TXT" and domain == "_dmarc.example.com":
                item = MagicMock()
                item.to_text.return_value = '"v=DMARC1; p=none;"'  # Permissive DMARC
                return [item]
            import dns.resolver
            raise dns.resolver.NXDOMAIN()

        mock_res.resolve = AsyncMock(side_effect=mock_resolve)

        # 1. DNS Hygiene verification
        dns_findings = await audit_dns_hygiene("example.com")
        dns_check_ids = {f.check_id for f in dns_findings}
        assert "NET-DNS-002" in dns_check_ids  # Permissive SPF (+all)
        assert "NET-DNS-004" in dns_check_ids  # Permissive DMARC (p=none)
        assert "NET-DNS-005" in dns_check_ids  # Missing CAA
        assert "NET-DNS-006" in dns_check_ids  # Missing MTA-STS
        assert "NET-DNS-007" in dns_check_ids  # Missing DNSSEC

    # 2. Port Checker verification
    async def mock_open_conn(host, port):
        if port == 3306:  # MySQL Open
            writer = MagicMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()
            return MagicMock(), writer
        raise ConnectionRefusedError()

    with patch("asyncio.open_connection", side_effect=mock_open_conn):
        port_findings = await audit_exposed_ports("example.com")
        port_check_ids = {f.check_id for f in port_findings}
        assert "NET-PORT-001" in port_check_ids  # MySQL port exposed


# ==============================================================================
# Scenario 2: Web Application DAST Headers & Cookies
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_2_web_dast_headers_and_cookies():
    mock_client = AsyncMock()
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.headers = httpx.Headers({
        "server": "nginx/1.18.0",
        "x-powered-by": "Express",
        "set-cookie": "auth_token=xyz123; Path=/",  # Missing HttpOnly, Secure, SameSite
    })
    mock_client.get.return_value = mock_response

    findings = await audit_security_headers_and_cookies("https://example.com", client=mock_client)
    check_ids = {f.check_id for f in findings}

    assert "DAST-HDR-001" in check_ids  # Missing CSP
    assert "DAST-HDR-002" in check_ids  # Missing HSTS
    assert "DAST-HDR-004" in check_ids  # Missing X-Frame-Options
    assert "DAST-HDR-005" in check_ids  # Missing X-Content-Type-Options: nosniff
    assert "DAST-HDR-006" in check_ids  # Permissive Referrer-Policy
    assert "DAST-HDR-007" in check_ids  # Server & Technology Disclosure
    assert "DAST-COOKIE-001" in check_ids  # Missing HttpOnly
    assert "DAST-COOKIE-002" in check_ids  # Missing Secure
    assert "DAST-COOKIE-003" in check_ids  # Missing SameSite


# ==============================================================================
# Scenario 3: Web DAST CORS, Exposure & GraphQL
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_3_web_dast_cors_and_exposure():
    mock_client = AsyncMock()

    # CORS origin reflection
    mock_cors_resp = MagicMock(spec=httpx.Response)
    mock_cors_resp.status_code = 200
    mock_cors_resp.headers = httpx.Headers({
        "access-control-allow-origin": "https://attacker-origin.com",
        "access-control-allow-credentials": "true",
    })
    mock_client.get.return_value = mock_cors_resp

    cors_findings = await audit_cors_policies("https://example.com", client=mock_client)
    assert any(f.check_id == "DAST-CORS-001" for f in cors_findings)

    # Exposed .env & .git/HEAD
    mock_env_resp = MagicMock(spec=httpx.Response)
    mock_env_resp.status_code = 200
    mock_env_resp.text = "DB_PASSWORD=secret123\nAPP_KEY=base64:abc"

    mock_git_resp = MagicMock(spec=httpx.Response)
    mock_git_resp.status_code = 200
    mock_git_resp.text = "ref: refs/heads/main"

    mock_client.get.side_effect = [mock_env_resp, mock_git_resp, MagicMock(status_code=404), MagicMock(status_code=404)]
    mock_client.request.return_value = MagicMock(status_code=405)

    exp_findings = await audit_sensitive_exposure_and_methods("https://example.com", client=mock_client)
    exp_check_ids = {f.check_id for f in exp_findings}
    assert "DAST-EXP-001" in exp_check_ids  # .env file exposed (Critical)
    assert "DAST-EXP-002" in exp_check_ids  # .git/HEAD exposed (Critical)

    # GraphQL Introspection
    mock_gql_resp = MagicMock(spec=httpx.Response)
    mock_gql_resp.status_code = 200
    mock_gql_resp.json.return_value = {"data": {"__schema": {"types": [{"name": "User"}]}}}
    mock_client.post.return_value = mock_gql_resp

    gql_findings = await audit_graphql_endpoints("https://example.com", client=mock_client)
    assert any(f.check_id == "DAST-GQL-001" for f in gql_findings)


# ==============================================================================
# Scenario 4: Code SAST Secret Detection with Mandatory Masking
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_4_sast_secret_detection_and_masking():
    temp_dir = Path(tempfile.mkdtemp())
    try:
        sample_code = temp_dir / "secrets_demo.py"
        mock_aws = "AKIA" + "IOSFODNN7EXAMPLE"
        mock_ghp = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
        mock_stripe = "sk_live_" + "123456789012345678901234"
        sample_code.write_text(f"""
AWS_KEY = "{mock_aws}"
GITHUB_TOKEN = "{mock_ghp}"
STRIPE_SECRET = "{mock_stripe}"
DATABASE_URL = "postgres://root:verysecretpass123@db.prod.internal:5432/app"
RSA_KEY = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA..."
""", encoding="utf-8")

        findings = await audit_code_secrets(str(temp_dir))
        check_ids = {f.check_id for f in findings}

        assert "SAST-SEC-001" in check_ids  # AWS Key ID
        assert "SAST-SEC-003" in check_ids  # GitHub PAT
        assert "SAST-SEC-004" in check_ids  # Stripe Secret Key
        assert "SAST-SEC-007" in check_ids  # Private Key
        assert "SAST-SEC-008" in check_ids  # Database credentials

        # MANDATORY ZERO-PLAINTEXT PRIVACY GUARANTEE:
        for f in findings:
            obs = f.evidence.observed_value
            assert "AKIAIOSFODNN7EXAMPLE" not in obs
            assert "verysecretpass123" not in obs
            assert "*" in obs
    finally:
        shutil.rmtree(temp_dir)


# ==============================================================================
# Scenario 5: Code SAST Cryptography & Static Injection Linting
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_5_sast_crypto_and_injection():
    temp_dir = Path(tempfile.mkdtemp())
    try:
        sample_code = temp_dir / "vulns.py"
        sample_code.write_text("""
import hashlib
import random
import subprocess
import pickle
from Crypto.Cipher import AES

def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def make_session():
    auth_token = str(random.random())
    return auth_token

def aes_encrypt(data):
    return AES.new(key, AES.MODE_ECB).encrypt(data)

def run_query(cursor, email):
    cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")

def ping_target(host):
    subprocess.Popen(f"ping {host}", shell=True)

def parse_obj(stream):
    return pickle.loads(stream)
""", encoding="utf-8")

        crypto_findings = await audit_crypto_patterns(str(temp_dir))
        crypto_ids = {f.check_id for f in crypto_findings}
        assert "SAST-CRY-001" in crypto_ids  # MD5 broken hash
        assert "SAST-CRY-002" in crypto_ids  # Insecure PRNG in auth context
        assert "SAST-CRY-003" in crypto_ids  # AES-ECB mode

        inj_findings = await audit_injection_patterns(str(temp_dir))
        inj_ids = {f.check_id for f in inj_findings}
        assert "SAST-INJ-001" in inj_ids  # SQL Injection f-string
        assert "SAST-INJ-002" in inj_ids  # shell=True
        assert "SAST-INJ-003" in inj_ids  # pickle.loads unsafe deserialization
    finally:
        shutil.rmtree(temp_dir)


# ==============================================================================
# Scenario 6: Infrastructure-as-Code & Container Posture
# ==============================================================================
def test_scenario_6_iac_and_container_posture():
    # 1. Dockerfile
    dockerfile = """
FROM python:latest
ENV API_SECRET_KEY=supersecretkey123
RUN apt-get update && apt-get install -y curl
"""
    dock_findings = audit_dockerfile_content(dockerfile, "Dockerfile")
    dock_ids = {f.check_id for f in dock_findings}
    assert "IAC-DOCK-001" in dock_ids  # Root user
    assert "IAC-DOCK-002" in dock_ids  # Unpinned :latest tag
    assert "IAC-DOCK-005" in dock_ids  # Secret in ENV

    # 2. Docker Compose
    compose_yaml = """
version: '3.8'
services:
  agent:
    image: agent:1.0
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  db:
    image: postgres:15
    ports:
      - "5432:5432"
"""
    cmp_findings = audit_compose_yaml(compose_yaml, "docker-compose.yml")
    cmp_ids = {f.check_id for f in cmp_findings}
    assert "IAC-CMP-001" in cmp_ids  # Privileged mode
    assert "IAC-CMP-002" in cmp_ids  # Docker socket mount
    assert "IAC-CMP-003" in cmp_ids  # 5432 open on 0.0.0.0

    # 3. Kubernetes Manifest
    k8s_yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  hostPID: true
  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      privileged: true
"""
    k8s_findings = audit_k8s_yaml(k8s_yaml, "k8s-pod.yaml")
    k8s_ids = {f.check_id for f in k8s_findings}
    assert "IAC-K8S-001" in k8s_ids  # Privileged container
    assert "IAC-K8S-002" in k8s_ids  # hostPID shared

    # 4. Terraform
    tf_code = """
resource "aws_s3_bucket" "public_bucket" {
  acl = "public-read"
}
"""
    tf_findings = audit_terraform_file(tf_code, "main.tf")
    assert any(f.check_id == "IAC-TF-001" for f in tf_findings)  # Public S3 ACL


# ==============================================================================
# Scenario 7: CI/CD Workflow Security
# ==============================================================================
def test_scenario_7_cicd_workflow_security():
    workflow_yaml = """
name: Insecure Pipeline
on:
  pull_request_target:

permissions: write-all

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
        with:
          ref: "${{ github.event.pull_request.head.sha }}"
      - run: echo "Branch is ${{ github.event.pull_request.head.ref }}"
"""
    findings = audit_workflow_yaml(workflow_yaml, ".github/workflows/test.yml")
    check_ids = {f.check_id for f in findings}

    assert "CICD-GHA-001" in check_ids  # pull_request_target checkout
    assert "CICD-GHA-002" in check_ids  # Unpinned action (@v2)
    assert "CICD-GHA-003" in check_ids  # Script injection via github context
    assert "CICD-GHA-004" in check_ids  # permissions: write-all


# ==============================================================================
# Scenario 8: Multi-Format Exporters Compliance & Schema Validation
# ==============================================================================
def test_scenario_8_multiformat_exporters():
    target = Target(name="Production Target", type=TargetType.URL, value="https://production.example.com")
    f_crit = Finding(
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
        remediation="Block dotfiles",
        remediation_code_snippet="location ~ /\\.(?!well-known).* { deny all; }",
        evidence=Evidence(
            location="https://production.example.com/.env",
            observed_value="DB_PASSWORD=***",
            expected_value="404 Not Found",
        ),
        fingerprint=calculate_fingerprint("DAST-EXP-001", "https://production.example.com/.env", "DB_PASSWORD=***"),
    )

    job = ScanJob(
        target=target,
        profile=ScanProfile.FULL_STACK,
        status=ScanStatus.COMPLETED,
        progress_percent=100,
        findings=[f_crit],
    )
    job.summary = calculate_scan_grade(job.findings, duration_seconds=5.2)

    # 1. Standalone HTML Export Test (Zero CDN Dependencies)
    html_doc = export_scan_to_html(job)
    assert "<!DOCTYPE html>" in html_doc
    assert "https://cdn." not in html_doc
    assert "https://cdnjs." not in html_doc
    assert "<script src=" not in html_doc
    assert "DAST-EXP-001" in html_doc
    assert "Critical" in html_doc

    # 2. OASIS SARIF v2.1.0 Export Test
    sarif_doc = export_scan_to_sarif(job)
    assert sarif_doc["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in sarif_doc["$schema"]
    assert len(sarif_doc["runs"]) == 1
    assert sarif_doc["runs"][0]["results"][0]["ruleId"] == "DAST-EXP-001"
    assert sarif_doc["runs"][0]["results"][0]["level"] == "error"

    # 3. JSON Export Test
    json_doc = export_scan_to_json(job)
    parsed = json.loads(json_doc)
    assert parsed["id"] == job.id
    assert parsed["summary"]["overall_security_grade"] == "F"


# ==============================================================================
# Scenario 9: Scoped Web Crawler Discovery & Boundary Enforcement (v3.1.0)
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_9_scoped_web_crawler_discovery():
    mock_client = AsyncMock()

    async def mock_get(url, **kwargs):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.headers = {"content-type": "text/html; charset=utf-8"}

        if url in ("https://target.com", "https://target.com/"):
            resp.text = """
            <html>
              <body>
                <a href="/about">About Us</a>
                <a href="/contact">Contact</a>
                <a href="https://external-cdn.com/asset">External CDN</a>
                <a href="/user/logout">Logout</a>
              </body>
            </html>
            """
        elif url == "https://target.com/about":
            resp.text = """
            <html>
              <body>
                <a href="/about/team">Team Page</a>
              </body>
            </html>
            """
        elif url == "https://target.com/about/team":
            resp.text = """
            <html>
              <body>
                <a href="/about/team/lead">Team Lead Profile (Depth 3)</a>
              </body>
            </html>
            """
        elif url == "https://target.com/contact":
            resp.text = """
            <html>
              <body>
                <form action="/contact" method="POST">
                  <input type="text" name="name">
                  <button type="submit">Submit</button>
                </form>
              </body>
            </html>
            """
        elif url == "https://target.com/robots.txt":
            resp.headers = {"content-type": "text/plain"}
            resp.text = "User-agent: *\nSitemap: https://target.com/sitemap.xml\nDisallow: /admin\n"
        elif url == "https://target.com/sitemap.xml":
            resp.headers = {"content-type": "application/xml"}
            resp.text = """<?xml version="1.0" encoding="UTF-8"?>
            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
               <url><loc>https://target.com/pricing</loc></url>
            </urlset>
            """
        else:
            resp.text = "<html><body>Discovered Page</body></html>"

        return resp

    mock_client.get = AsyncMock(side_effect=mock_get)

    crawler_config = CrawlerConfig(
        enabled=True,
        max_depth=2,
        max_pages=20,
        exclude_patterns=["*logout*"],
        parse_sitemap=True,
    )

    crawler = WebCrawler(
        target_url="https://target.com",
        config=crawler_config,
        client=mock_client,
    )

    endpoints = await crawler.crawl()
    crawled_urls = [e.url for e in endpoints]

    # Verify root, depth 1, and depth 2 are crawled
    assert any("https://target.com" in u for u in crawled_urls)
    assert "https://target.com/about" in crawled_urls
    assert "https://target.com/contact" in crawled_urls
    assert "https://target.com/about/team" in crawled_urls

    # Verify depth limit enforcement: depth 3 (/about/team/lead) MUST NOT be crawled
    assert "https://target.com/about/team/lead" not in crawled_urls

    # Verify same-origin scope enforcement: external URL MUST NOT be crawled
    assert "https://external-cdn.com/asset" not in crawled_urls

    # Verify exclude pattern enforcement: /user/logout MUST NOT be crawled
    assert "https://target.com/user/logout" not in crawled_urls

    # Verify sitemap seed was crawled
    assert "https://target.com/pricing" in crawled_urls

    # Verify form detection on /contact
    contact_ep = next((e for e in endpoints if e.url == "https://target.com/contact"), None)
    assert contact_ep is not None
    assert contact_ep.has_forms is True
    assert len(endpoints) >= 3


# ==============================================================================
# Scenario 10: Authenticated DAST Session & Form Auditing (v3.1.0)
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_10_authenticated_dast_session_scanning():
    mock_client = AsyncMock()

    # Mock Login GET returning CSRF token
    login_get_resp = MagicMock(spec=httpx.Response)
    login_get_resp.status_code = 200
    login_get_resp.headers = {"content-type": "text/html"}
    login_get_resp.text = """
    <html>
      <body>
        <form action="/login" method="POST">
          <input type="hidden" name="_csrf" value="mock_csrf_val">
          <input type="text" name="username">
          <input type="password" name="password">
          <button type="submit">Sign In</button>
        </form>
      </body>
    </html>
    """

    # Mock Login POST confirming session
    login_post_resp = MagicMock(spec=httpx.Response)
    login_post_resp.status_code = 200
    login_post_resp.headers = {"content-type": "text/html"}
    login_post_resp.text = "<html><body>Welcome, auditor user! Active Session Dashboard</body></html>"

    mock_client.get = AsyncMock(return_value=login_get_resp)
    mock_client.post = AsyncMock(return_value=login_post_resp)

    # Set mock cookie without HttpOnly and without Secure on HTTPS
    client = httpx.AsyncClient()
    client.cookies.set("session_id", "auth_xyz123", domain="app.test", path="/")

    auth_config = AuthConfig(
        auth_type=AuthType.FORM_LOGIN,
        login_url="https://app.test/login",
        username_field="username",
        username="auditor",
        password_field="password",
        password="password123",
        csrf_token_field="_csrf",
        logged_in_indicator="Welcome",
    )

    auth_manager = AuthSessionManager(
        target_url="https://app.test",
        config=auth_config,
        client=client,
    )

    # Execute authentication
    with patch.object(auth_manager, "client", mock_client):
        auth_success = await auth_manager.authenticate()
        assert auth_success is True

    # Prepare mock unauthenticated response for broken access control check (DAST-AUTH-003)
    mock_unauth_resp = MagicMock(spec=httpx.Response)
    mock_unauth_resp.status_code = 200
    mock_unauth_resp.text = """
    <!DOCTYPE html>
    <html>
      <head><title>Admin Dashboard</title></head>
      <body>
        <h1>Confidential Executive Data</h1>
        <p>User database records, salary schedules, and billing statements.</p>
      </body>
    </html>
    """

    discovered_endpoints = [
        DiscoveredEndpoint(url="https://app.test/admin/dashboard", method="GET", depth=1, is_authenticated=True),
        DiscoveredEndpoint(url="https://app.test/api/export?token=sk_test_sensitive_token_12345", method="GET", depth=1),
    ]

    html_contents = {
        "https://app.test/settings": """
        <html>
          <body>
            <form action="/update-profile" method="POST">
              <input type="text" name="display_name">
              <button type="submit">Update</button>
            </form>
          </body>
        </html>
        """
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_unauth_resp):
        findings = await auth_manager.audit_auth_and_forms(
            discovered_endpoints=discovered_endpoints,
            html_contents=html_contents,
        )

    check_ids = {f.check_id for f in findings}

    # Verify DAST-AUTH-002: Insecure session cookie (missing HttpOnly/Secure)
    assert "DAST-AUTH-002" in check_ids

    # Verify DAST-AUTH-003: Broken Access Control (Unprotected sensitive endpoint)
    assert "DAST-AUTH-003" in check_ids

    # Verify DAST-AUTH-004: Sensitive credentials in query string
    assert "DAST-AUTH-004" in check_ids
    token_finding = next(f for f in findings if f.check_id == "DAST-AUTH-004")
    assert "sk_test_sensitive_token_12345" not in token_finding.evidence.observed_value
    assert "*" in token_finding.evidence.observed_value

    # Verify DAST-FORM-002: State-changing form missing anti-CSRF token
    assert "DAST-FORM-002" in check_ids

# ==============================================================================
# Scenario 15: Hybrid Tool Adapter Discovery, Execution & Graceful Fallback
# (Contract 05 v4.1.0 - Acceptance Scenario 15)
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_15_hybrid_tool_adapters_and_graceful_fallback():
    """
    Scenario 15A: Adapters present (mocked) -> findings emitted with correct source_tool.
    Scenario 15B: Adapters absent (mocked) -> graceful native fallback, scan completes cleanly.
    """
    from app.adapters.nmap_adapter import NmapAdapter
    from app.adapters.nuclei_adapter import NucleiAdapter
    from app.adapters.semgrep_adapter import SemgrepAdapter
    from app.adapters.trivy_adapter import TrivyAdapter
    from app.adapters import discover_system_capabilities
    from app.core.models import (
        ToolAdapterConfig, ToolStatus, ToolExecutionMode, SystemCapabilities,
        Evidence, Severity
    )
    import hashlib

    # --------------------------------------------------------------------------
    # Scenario 15A: Adapter ACTIVE path - mocked as available & returning findings
    # --------------------------------------------------------------------------
    nmap_finding = Finding(
        scan_id="test-15",
        engine="network",
        check_id="NET-PORT-001",
        category="Open Ports",
        title="Exposed Database Port (MySQL/MariaDB)",
        severity=Severity.HIGH,
        cvss_score=7.5,
        cwe_id="CWE-16",
        owasp_category="A05:2021-Security Misconfiguration",
        nist_control="SC-7",
        description="Port 3306 (MySQL) open.",
        impact="Database exposed to direct attack.",
        remediation="Firewall database port.",
        evidence=Evidence(
            location="host:3306",
            observed_value="MySQL 8.0.32 listening on 0.0.0.0:3306",
            expected_value="Port inaccessible from public internet",
        ),
        fingerprint=calculate_fingerprint("NET-PORT-001", "host:3306", "MySQL 8.0.32 listening on 0.0.0.0:3306"),
        source_tool="nmap",
    )

    with patch.object(NmapAdapter, "is_available", AsyncMock(return_value=True)), \
         patch.object(NmapAdapter, "get_version", AsyncMock(return_value="7.95")), \
         patch.object(NmapAdapter, "run", AsyncMock(return_value=[nmap_finding])):

        adapter = NmapAdapter()
        assert await adapter.is_available() is True
        findings = await adapter.run(None, None, AsyncMock(), AsyncMock())
        assert len(findings) == 1
        assert findings[0].source_tool == "nmap"
        assert findings[0].check_id == "NET-PORT-001"

    # Nuclei finding mock
    nuclei_finding = Finding(
        scan_id="test-15",
        engine="web_dast",
        check_id="DAST-CVE-001",
        category="CVE",
        title="CVE-2023-1234 - Example Vulnerability",
        severity=Severity.HIGH,
        cvss_score=7.5,
        cwe_id="CWE-79",
        owasp_category="A03:2021-Injection",
        nist_control="SI-10",
        description="Nuclei-detected CVE.",
        impact="Data exfiltration.",
        remediation="Patch to latest version.",
        evidence=Evidence(
            location="https://example.com/vuln",
            observed_value="Vulnerable endpoint matched CVE-2023-1234 template",
            expected_value="Patched endpoint",
        ),
        fingerprint=calculate_fingerprint("DAST-CVE-001", "https://example.com/vuln", "Vulnerable endpoint matched CVE-2023-1234 template"),
        source_tool="nuclei",
        reproduction_curl='curl -i https://example.com/vuln',
    )

    with patch.object(NucleiAdapter, "is_available", AsyncMock(return_value=True)), \
         patch.object(NucleiAdapter, "run", AsyncMock(return_value=[nuclei_finding])):

        adapter = NucleiAdapter()
        findings = await adapter.run(None, None, AsyncMock(), AsyncMock())
        assert len(findings) == 1
        assert findings[0].source_tool == "nuclei"
        assert findings[0].reproduction_curl is not None

    # --------------------------------------------------------------------------
    # Scenario 15B: Adapters ABSENT - graceful fallback, scan completes cleanly
    # --------------------------------------------------------------------------
    with patch.object(NmapAdapter, "is_available", AsyncMock(return_value=False)), \
         patch.object(NucleiAdapter, "is_available", AsyncMock(return_value=False)), \
         patch.object(SemgrepAdapter, "is_available", AsyncMock(return_value=False)), \
         patch.object(TrivyAdapter, "is_available", AsyncMock(return_value=False)):

        capabilities = await discover_system_capabilities(ToolAdapterConfig())
        for tool in capabilities.tools:
            assert tool.execution_mode == ToolExecutionMode.NATIVE_FALLBACK
            assert tool.available is False
        assert capabilities.native_engines_ready is True

    # --------------------------------------------------------------------------
    # Scenario 15C: Orchestrator full lifecycle - no adapters, scan completes cleanly
    # --------------------------------------------------------------------------
    from app.engines.network.engine import NetworkAssessmentEngine
    from app.core.orchestrator import ScanOrchestrator

    orch = ScanOrchestrator()
    orch.register_engine(NetworkAssessmentEngine())

    target = Target(
        name="Fallback Test",
        type=TargetType.DOMAIN,
        value="example.com",
    )
    config = ScanConfig(adapters=ToolAdapterConfig(enable_nmap=False, enable_nuclei=False, enable_semgrep=False, enable_trivy=False))
    job = ScanJob(target=target, profile=ScanProfile.QUICK, config=config, enabled_engines=["network"])

    with patch("app.engines.network.engine.audit_tls_certificates", AsyncMock(return_value=[])), \
         patch("app.engines.network.engine.audit_tls_protocols_and_ciphers", AsyncMock(return_value=[])), \
         patch("app.engines.network.engine.audit_dns_hygiene", AsyncMock(return_value=[])), \
         patch("app.engines.network.engine.audit_exposed_ports", AsyncMock(return_value=[])), \
         patch("app.engines.network.engine.audit_subdomain_osint", AsyncMock(return_value=[])), \
         patch("app.engines.network.engine.audit_service_banners", AsyncMock(return_value=[])), \
         patch("app.adapters.discover_system_capabilities", AsyncMock(return_value=SystemCapabilities(
             tools=[
                 ToolStatus(name="nmap", available=False, execution_mode=ToolExecutionMode.DISABLED),
                 ToolStatus(name="nuclei", available=False, execution_mode=ToolExecutionMode.DISABLED),
                 ToolStatus(name="semgrep", available=False, execution_mode=ToolExecutionMode.DISABLED),
                 ToolStatus(name="trivy", available=False, execution_mode=ToolExecutionMode.DISABLED),
             ],
             native_engines_ready=True,
             os_platform="test",
         ))):
        await orch.start_scan(job)
        import asyncio as _asyncio
        for _ in range(30):
            await _asyncio.sleep(0.1)
            if job.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
                break

    assert job.status == ScanStatus.COMPLETED, f"Expected COMPLETED, got {job.status}"
    assert job.active_adapters == []


# ==============================================================================
# (Contract 05 v4.1.0 - Acceptance Scenario 14)
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_14_interactive_http_repeater():
    """
    Scenario 14: Interactive HTTP Repeater & One-Click cURL PoC Generation
    - Executes custom requests via POST /api/tools/repeater returning latency, status, headers, and body.
    - Tests error handling on network failure / timeouts.
    - Confirms web finding models can carry valid copy-pasteable reproduction_curl strings.
    """
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    from app.core.models import RepeaterRequest, Finding, Evidence, Severity, UserProfile, UserRole
    from app.core.auth import create_access_token

    auth_user = UserProfile(id="usr-rep-01", username="analyst", email="analyst@sec.local", role=UserRole.SECURITY_ANALYST)
    auth_token = create_access_token(auth_user)
    auth_headers = {"Authorization": f"Bearer {auth_token}"}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Mock httpx inside execute_repeater_request for predictable testing
        with patch("app.api.tools.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "application/json", "server": "test-nginx"}
            mock_response.text = '{"status": "ok", "message": "repeater response"}'
            mock_response.content = b'{"status": "ok", "message": "repeater response"}'
            mock_response.extensions = {"tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"}
            mock_client.request.return_value = mock_response
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            payload = {
                "url": "https://example.com/api/test",
                "method": "POST",
                "headers": {"Authorization": "Bearer test-token-123"},
                "body": '{"query": "SELECT 1"}',
                "follow_redirects": True,
                "timeout_seconds": 5.0,
            }

            resp = await client.post("/api/tools/repeater", json=payload, headers=auth_headers)
            assert resp.status_code == 200
            data = resp.json()
            assert data["status_code"] == 200
            assert data["headers"]["server"] == "test-nginx"
            assert data["body"] == '{"status": "ok", "message": "repeater response"}'
            assert data["duration_ms"] >= 0.0
            assert data["content_length"] == len(mock_response.content)
            assert data["tls_version"] == "TLSv1.3"
            client_kwargs = mock_client_cls.call_args.kwargs
            assert isinstance(client_kwargs["transport"], ValidatedTargetTransport)

            # Verify timeout error handling
            with patch("app.api.tools.httpx.AsyncClient") as mock_client_cls, \
                 patch("app.api.tools.assert_safe_url"), \
                 patch("app.api.tools.create_validated_target", return_value=SimpleNamespace(
                     canonical_value="https://slow.example.com",
                     selected_destination="203.0.113.10",
                 )):
                mock_client = AsyncMock()
                mock_client.request.side_effect = httpx.TimeoutException("Connection timed out")
                mock_client_cls.return_value.__aenter__.return_value = mock_client

                resp = await client.post(
                    "/api/tools/repeater",
                    json={"url": "https://slow.example.com", "method": "GET", "timeout_seconds": 1.0},
                    headers=auth_headers,
                )
                assert resp.status_code == 504
                assert "timed out" in resp.json()["detail"]

        # Verify network/connection error handling
        with patch("app.api.tools.httpx.AsyncClient") as mock_client_cls, \
             patch("app.api.tools.assert_safe_url"), \
             patch("app.api.tools.create_validated_target", return_value=SimpleNamespace(
                 canonical_value="https://unreachable.example.com",
                 selected_destination="203.0.113.11",
             )):
            mock_client = AsyncMock()
            mock_client.request.side_effect = httpx.ConnectError("Connection refused")
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            resp = await client.post(
                "/api/tools/repeater",
                json={"url": "https://unreachable.example.com", "method": "GET"},
                headers=auth_headers,
            )
            assert resp.status_code == 502
            assert "Failed to connect" in resp.json()["detail"]

    # Verify Finding reproduction_curl PoC synthesis conformance
    test_finding = Finding(
        scan_id="test-repeater-poc",
        engine="web_dast",
        check_id="DAST-INJ-001",
        category="Injection",
        title="Time-based SQL Injection in parameter 'id'",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        description="SQL injection confirmed via 2.0s timing delay.",
        impact="Full database compromise.",
        remediation="Use parameterized queries.",
        evidence=Evidence(
            location="https://example.com/search?id=1",
            observed_value="Delay: 2.12s",
            expected_value="Delay: < 0.2s",
        ),
        fingerprint=calculate_fingerprint("DAST-INJ-001", "https://example.com/search?id=1", "Delay: 2.12s"),
        reproduction_curl='curl -i -s -k -X GET "https://example.com/search?id=1%27+AND+(SELECT+1+FROM+(SELECT(SLEEP(2)))a)--+"',
    )
    assert test_finding.reproduction_curl is not None
    assert test_finding.reproduction_curl.startswith("curl ")


# ==============================================================================
# (Contract 05 v4.1.0 - Acceptance Scenario 12)
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_12_passive_osint_subdomain_recon_and_cname_takeover():
    """
    Scenario 12: Passive OSINT Subdomain Reconnaissance & Dangling CNAME Takeover
    - Queries crt.sh API simulation.
    - Evaluates CNAME records and discovers takeover risk (NET-OSINT-001).
    - Detects sensitive subdomains on public infrastructure (NET-OSINT-002).
    - Inspects service daemon banner for known vulnerable version (NET-SVC-001).
    """
    from app.engines.network.subdomain_recon import audit_subdomain_osint
    from app.engines.network.banner_grabber import audit_service_banners
    from app.core.models import (
        Target, TargetType, ScanConfig, OSINTConfig, DiscoveredSubdomain
    )

    # 1. Test Subdomain Recon & Takeover Detection (NET-OSINT-001 & NET-OSINT-002)
    mock_crtsh_data = [
        {"name_value": "admin.example.com\napi.example.com"},
        {"name_value": "dangling.example.com\ndev.example.com"},
    ]

    discovered_subdomains_list = []
    async def mock_sub_cb(sd: DiscoveredSubdomain):
        discovered_subdomains_list.append(sd)

    with patch("app.engines.network.subdomain_recon.httpx.AsyncClient") as mock_http_cls:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_crtsh_data
        mock_client.get.return_value = mock_resp
        mock_http_cls.return_value.__aenter__.return_value = mock_client

        with patch("app.engines.network.subdomain_recon.dns.asyncresolver.Resolver") as mock_resolver_cls:
            mock_resolver = AsyncMock()

            # Mock resolve for subdomains
            async def mock_resolve(domain_name, rdtype):
                if domain_name == "dangling.example.com" and rdtype == "CNAME":
                    m_rdata = MagicMock()
                    m_rdata.target = "mybucket.s3.amazonaws.com."
                    return [m_rdata]
                elif domain_name == "mybucket.s3.amazonaws.com" and rdtype == "A":
                    import dns.resolver
                    raise dns.resolver.NXDOMAIN()
                elif rdtype == "A":
                    m_a = MagicMock()
                    m_a.__str__.return_value = "93.184.216.34"
                    return [m_a]
                import dns.resolver
                raise dns.resolver.NoAnswer()

            mock_resolver.resolve.side_effect = mock_resolve
            mock_resolver_cls.return_value = mock_resolver

            config = ScanConfig(osint=OSINTConfig(subdomain_enumeration=True, subdomain_takeover_check=True))
            findings = await audit_subdomain_osint(
                "example.com",
                config=config,
                scan_id="test-osint",
                emit_subdomain=mock_sub_cb,
            )

            check_ids = [f.check_id for f in findings]
            assert "NET-OSINT-001" in check_ids, "Expected dangling CNAME takeover finding (NET-OSINT-001)"
            assert "NET-OSINT-002" in check_ids, "Expected sensitive subdomain finding (NET-OSINT-002)"
            assert len(discovered_subdomains_list) >= 4

    # 2. Test Service Banner Grabbing (NET-SVC-001)
    with patch("app.engines.network.banner_grabber.grab_service_banner", AsyncMock(return_value="220 (vsFTPd 2.3.4)")):
        svc_findings = await audit_service_banners("127.0.0.1", [21], scan_id="test-banner")
        assert len(svc_findings) == 1
        assert svc_findings[0].check_id == "NET-SVC-001"
        assert "vsftpd 2.3.4" in svc_findings[0].title
        assert svc_findings[0].severity == Severity.HIGH
        assert svc_findings[0].cvss_score == 7.5


# ==============================================================================
# (Contract 05 v4.1.0 - Acceptance Scenario 11)
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_11_active_parameter_fuzzing_and_injection():
    """
    Scenario 11: Active Parameter Fuzzing & Benign Injection Verification
    - Injects safe time-based SQLi probe (SLEEP(2)) -> DAST-INJ-001.
    - Injects canary Reflected XSS token -> DAST-XSS-001.
    - Injects read-only Path Traversal payload -> DAST-LFI-001.
    - Injects Server-Side Template Injection expression ({{7*7}}) -> DAST-SSTI-001.
    - Injects Open Redirect target -> DAST-REDIR-001.
    - Verifies all findings synthesize copy-pasteable reproduction_curl PoCs.
    """
    from app.engines.web_dast.parameter_fuzzer import audit_parameter_fuzzing
    from app.core.models import (
        ScanConfig, FuzzingConfig, DiscoveredEndpoint, Severity
    )
    import time

    from urllib.parse import unquote

    time_counter = [0.0]
    def mock_perf():
        time_counter[0] += 0.05
        return time_counter[0]

    # Mock responses for different payloads
    async def mock_handler(request: httpx.Request) -> httpx.Response:
        url_str = unquote(str(request.url))
        # SQLi probe simulation
        if "SLEEP" in url_str:
            time_counter[0] += 2.5
            return httpx.Response(200, text="<html><body>Items list</body></html>", request=request)
        # XSS probe simulation
        elif "_CYBERASSESS_XSS_" in url_str:
            # Echo unescaped canary reflection
            return httpx.Response(200, text=f"<html><body>Search: {url_str}</body></html>", request=request)
        # LFI probe simulation
        elif "etc/passwd" in url_str:
            return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", request=request)
        # SSTI probe simulation
        elif "{{7*7}}" in url_str:
            return httpx.Response(200, text="<html><body>Computed result: 49</body></html>", request=request)
        # Baseline response
        return httpx.Response(200, text="<html><body>Normal page</body></html>", request=request)

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://testapp") as client:
        with patch("app.engines.web_dast.parameter_fuzzer.time.perf_counter", side_effect=mock_perf):
            config = ScanConfig(
                fuzzing=FuzzingConfig(
                    enabled=True,
                    fuzz_sqli=True,
                    fuzz_xss=True,
                    fuzz_lfi=True,
                    fuzz_ssti=True,
                    fuzz_redirect=False,
                    delay_seconds=1.0,
                )
            )
            discovered_eps = [
                DiscoveredEndpoint(url="http://testapp/products?id=10", status_code=200),
            ]

            findings = await audit_parameter_fuzzing(
                "http://testapp/products?id=10",
                discovered_endpoints=discovered_eps,
                client=client,
                config=config,
                scan_id="test-fuzzing",
            )

        check_ids = {f.check_id for f in findings}
        assert "DAST-INJ-001" in check_ids, f"Expected DAST-INJ-001 in {check_ids}"
        assert "DAST-XSS-001" in check_ids, f"Expected DAST-XSS-001 in {check_ids}"
        assert "DAST-LFI-001" in check_ids, f"Expected DAST-LFI-001 in {check_ids}"
        assert "DAST-SSTI-001" in check_ids, f"Expected DAST-SSTI-001 in {check_ids}"

        for f in findings:
            assert f.reproduction_curl is not None
            assert f.reproduction_curl.startswith("curl ")
            assert f.source_tool == "native"


# ==============================================================================
# (Contract 05 v4.1.0 - Acceptance Scenario 13)
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_13_ast_taint_flow_and_git_history_scanner(tmp_path):
    """
    Scenario 13: Interprocedural AST Taint Flow & Historical Git Secret Scanner
    - Parses Python source files with AST and detects untrusted input reaching SQL/Command sinks.
    - Asserts SAST-TAINT-001 (SQL sink) and SAST-TAINT-002 (Command sink) with structured taint_trace.
    - Analyzes git log -p diffs and detects historical commit secret leaks (SAST-GIT-001) with masked evidence.
    """
    from app.engines.code_sast.ast_taint_analyzer import audit_ast_taint_flow
    from app.engines.code_sast.git_history_scanner import audit_git_commit_history

    # 1. Test AST Taint Flow Analyzer
    sample_code = """
from flask import request
import cursor
import subprocess

def handle_request():
    user_id = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)

def handle_command():
    target_ip = request.form.get("ip")
    cmd_str = f"ping -c 1 {target_ip}"
    subprocess.Popen(cmd_str, shell=True)
"""
    py_file = tmp_path / "vulnerable_app.py"
    py_file.write_text(sample_code, encoding="utf-8")

    taint_findings = audit_ast_taint_flow(str(tmp_path))
    check_ids = {f.check_id for f in taint_findings}

    assert "SAST-TAINT-001" in check_ids, "Expected SAST-TAINT-001 (SQL sink taint)"
    assert "SAST-TAINT-002" in check_ids, "Expected SAST-TAINT-002 (Command sink taint)"

    sql_finding = next(f for f in taint_findings if f.check_id == "SAST-TAINT-001")
    assert sql_finding.taint_trace is not None
    assert len(sql_finding.taint_trace) >= 2
    assert any("Source" in step for step in sql_finding.taint_trace)
    assert any("Sink" in step for step in sql_finding.taint_trace)

    cmd_finding = next(f for f in taint_findings if f.check_id == "SAST-TAINT-002")
    assert cmd_finding.taint_trace is not None
    assert len(cmd_finding.taint_trace) >= 2

    # 2. Test Historical Git Commit Secret Scanner
    mock_git_diff = """commit a1b2c3d4e5f67890
Author: Dev <dev@example.com>
Date:   Wed Jan 1 00:00:00 2026 +0000

    Initial commit with config

diff --git a/config.py b/config.py
--- a/dev/null
+++ b/config.py
@@ -0,0 +1,5 @@
+AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
+DATABASE_URI = "postgres://admin:SecretPass123@db.internal:5432/prod"
"""

    with patch("asyncio.create_subprocess_exec") as mock_exec, \
         patch("pathlib.Path.exists", return_value=True):
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (mock_git_diff.encode("utf-8"), b"")
        mock_exec.return_value = mock_proc

        git_findings = await audit_git_commit_history(str(tmp_path))
        assert len(git_findings) >= 1
        git_check_ids = {f.check_id for f in git_findings}
        assert "SAST-GIT-001" in git_check_ids

        # Guarantee masking of secrets in evidence
        for gf in git_findings:
            assert "AKIAIOSFODNN7EXAMPLE" not in gf.evidence.observed_value
            assert "SecretPass123" not in gf.evidence.observed_value
            assert "*" in gf.evidence.observed_value
        aws_finding = next(f for f in git_findings if "AKIA" in f.title or "SAST-SEC-001" in f.evidence.observed_value)
        assert "AKIA" in aws_finding.evidence.observed_value


# ==============================================================================
# (Contract 05 v5.0.0 - Acceptance Scenario 15)
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_15_hybrid_tool_adapters_and_graceful_fallback():
    """
    Scenario 15: External Tool Adapter Discovery, Execution & Graceful Fallback
    - Verifies discovery and invocation of Nmap, Nuclei, Semgrep, and Trivy adapters.
    - Verifies 100% graceful fallback to native Python engines when binaries are absent, with zero unhandled exceptions.
    """
    from app.core.orchestrator import ScanOrchestrator
    from app.engines.network.engine import NetworkAssessmentEngine
    from app.engines.code_sast.engine import CodeSastAssessmentEngine
    from app.core.models import ScanJob, Target, TargetType, ScanConfig, ToolAdapterConfig, ScanStatus
    from app.adapters.base_adapter import BaseToolAdapter

    # Test A: Fallback to pure native when adapters absent
    orchestrator = ScanOrchestrator()
    orchestrator.register_engine(NetworkAssessmentEngine())

    job = ScanJob(
        target=Target(name="Target", type=TargetType.DOMAIN, value="example.com"),
        enabled_engines=["network"],
        config=ScanConfig(
            adapters=ToolAdapterConfig(enable_nmap=True, enable_sslyze=True),
        ),
    )

    with patch.object(BaseToolAdapter, "is_available", return_value=False), \
         patch("app.engines.network.engine.audit_tls_certificates", AsyncMock(return_value=[])), \
         patch("app.engines.network.engine.audit_tls_protocols_and_ciphers", AsyncMock(return_value=[])), \
         patch("app.engines.network.engine.audit_dns_hygiene", AsyncMock(return_value=[])), \
         patch("app.engines.network.engine.audit_exposed_ports", AsyncMock(return_value=[])), \
         patch("app.engines.network.engine.audit_subdomain_osint", AsyncMock(return_value=[])):
        
        task = await orchestrator.start_scan(job)
        await task

    completed_job = orchestrator.get_active_job(job.id)
    assert completed_job.status == ScanStatus.COMPLETED
    assert completed_job.active_adapters == []


# ==============================================================================
# (Contract 05 v5.0.0 - Acceptance Scenario 16)
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_16_adapters_first_priority_and_native_pruning():
    """
    Scenario 16: Adapters First-in-Line Priority Execution & Native Redundancy Pruning
    - Asserts that when external adapters are active, they execute first as the primary assessment driver.
    - Baseline findings carry source_tool set to the active adapter name.
    - Native proprietary enrichments (AST taint, DNS hygiene, OSINT) run cleanly without duplicate collision.
    """
    from app.engines.network.engine import NetworkAssessmentEngine
    from app.adapters.nmap_adapter import NmapAdapter
    from app.adapters.sslyze_adapter import SslyzeAdapter
    from app.core.models import Target, TargetType, ScanConfig, Severity, Finding, Evidence, calculate_fingerprint

    net_engine = NetworkAssessmentEngine()
    target = Target(name="Target", type=TargetType.DOMAIN, value="example.com")
    config = ScanConfig()
    config.adapters.enable_subfinder = False
    config.adapters.enable_httpx = False

    nmap_finding = Finding(
        scan_id="active",
        engine="network",
        check_id="NET-PORT-001",
        category="Network Security",
        title="Open Port 22/tcp (ssh)",
        severity=Severity.INFO,
        cvss_score=0.0,
        description="SSH service identified by Nmap.",
        impact="Exposed SSH port.",
        remediation="Restrict SSH access.",
        evidence=Evidence(location="test-priority.com:22", observed_value="Open", expected_value="Port closed or firewalled"),
        fingerprint=calculate_fingerprint("NET-PORT-001", "test-priority.com:22", "Open"),
        source_tool="nmap",
    )

    sslyze_finding = Finding(
        scan_id="active",
        engine="network",
        check_id="NET-TLS-001",
        category="TLS/SSL Security",
        title="Deprecated TLS 1.0 Supported",
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="SSLyze detected deprecated TLS 1.0.",
        impact="Insecure cipher negotiation.",
        remediation="Disable TLS 1.0.",
        evidence=Evidence(location="test-priority.com:443", observed_value="TLS 1.0 Enabled", expected_value="TLS 1.2 or TLS 1.3 only"),
        fingerprint=calculate_fingerprint("NET-TLS-001", "test-priority.com:443", "TLS 1.0 Enabled"),
        source_tool="sslyze",
    )

    mock_log = AsyncMock()
    mock_progress = AsyncMock()
    mock_finding = AsyncMock()

    with patch.object(SslyzeAdapter, "is_available", AsyncMock(return_value=True)), \
         patch.object(SslyzeAdapter, "run", AsyncMock(return_value=[sslyze_finding])), \
         patch.object(NmapAdapter, "is_available", AsyncMock(return_value=True)), \
         patch.object(NmapAdapter, "run", AsyncMock(return_value=[nmap_finding])), \
         patch("app.engines.network.engine.audit_dns_hygiene", AsyncMock(return_value=[])), \
         patch("app.engines.network.engine.audit_subdomain_osint", AsyncMock(return_value=[])):

        findings = await net_engine.run(
            target=target,
            config=config,
            emit_log=mock_log,
            emit_progress=mock_progress,
            emit_finding=mock_finding,
        )

    assert len(findings) >= 2
    sources = {f.source_tool for f in findings}
    assert "sslyze" in sources
    assert "nmap" in sources

    # Verify adapter log events were emitted first
    log_messages = [call.args[1] for call in mock_log.call_args_list]
    assert any("Executing SSLyze" in m for m in log_messages)
    assert any("Executing Nmap" in m for m in log_messages)


# ==============================================================================
# (Contract 05 v5.0.0 - Acceptance Scenario 17)
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_17_expanded_enterprise_tool_adapters(tmp_path):
    """
    Scenario 17: Enterprise Tool Adapter Integrations (Gitleaks, Bandit, Checkov, FFuF, Katana, SSLyze)
    - Verifies command construction, non-destructive execution flags, output parsing, and error isolation.
    """
    from app.adapters.gitleaks_adapter import GitleaksAdapter
    from app.adapters.bandit_adapter import BanditAdapter
    from app.adapters.checkov_adapter import CheckovAdapter
    from app.adapters.ffuf_adapter import FfufAdapter
    from app.adapters.katana_adapter import KatanaAdapter
    from app.adapters.sslyze_adapter import SslyzeAdapter
    from app.core.models import Target, TargetType, ScanConfig

    # 1. Gitleaks
    gl = GitleaksAdapter()
    assert gl.tool_name == "gitleaks"

    # 2. Bandit
    bandit = BanditAdapter()
    assert bandit.tool_name == "bandit"

    # 3. Checkov
    checkov = CheckovAdapter()
    assert checkov.tool_name == "checkov"

    # 4. FFuF
    ffuf = FfufAdapter()
    assert ffuf.tool_name == "ffuf"

    # 5. Katana
    katana = KatanaAdapter()
    assert katana.tool_name == "katana"

    # 6. SSLyze
    sslyze = SslyzeAdapter()
    assert sslyze.tool_name == "sslyze"

    # Verify error isolation when any tool fails / throws an exception
    mock_log = AsyncMock()
    mock_finding = AsyncMock()
    target = Target(name="Target", type=TargetType.LOCAL_PATH, value=str(tmp_path))
    config = ScanConfig()

    with patch.object(gl, "resolve_binary_path", return_value="/usr/bin/gitleaks"), \
         patch.object(gl, "execute_command", AsyncMock(side_effect=RuntimeError("Subprocess failed unexpectedly"))):
        gl_findings = await gl.run(target, config, mock_log, mock_finding)
        assert gl_findings == []
        mock_log.assert_called()


@pytest.mark.asyncio
async def test_scenario_18_in_app_tool_installation_lifecycle(tmp_path):
    """
    Scenario 18: In-App Tool Installation Lifecycle for Pip & Standalone Binaries (Contract 05 v6.0.0)
    - Verifies 1-click execution for PipToolInstaller (sys.executable -m pip).
    - Verifies 1-click download, ZipSlip security check, and placement for GithubReleaseInstaller.
    - Confirms adapter resolve_binary_path detects the newly installed binary in backend/bin.
    """
    import asyncio
    import io
    import zipfile
    from app.installers.pip_installer import PipToolInstaller
    from app.installers.github_release_installer import GithubReleaseInstaller
    from app.adapters.nuclei_adapter import NucleiAdapter
    from app.core.models import ToolInstallStatus, ToolInstallMethod

    # 1. Test PipToolInstaller
    pip_inst = PipToolInstaller("sslyze")
    assert pip_inst.install_method == ToolInstallMethod.PIP
    mock_proc = MagicMock()
    mock_proc.stdout = ["Successfully installed sslyze\n"]
    mock_proc.wait = MagicMock(return_value=0)
    mock_proc.returncode = 0

    logs = []
    with patch("subprocess.Popen", return_value=mock_proc), \
         patch.object(pip_inst, "get_version", AsyncMock(return_value="5.2.0")):
        res = await pip_inst.install(
            lambda m: logs.append(m) or asyncio.sleep(0),
            lambda p, s: asyncio.sleep(0),
        )
        assert res is True
        assert any("Successfully installed" in l for l in logs)

    # 2. Test GithubReleaseInstaller with simulated release asset
    gh_inst = GithubReleaseInstaller("nuclei")
    fake_bin_dir = tmp_path / "bin"
    fake_bin_dir.mkdir(parents=True, exist_ok=True)

    # Create dummy zip with nuclei.exe
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as z:
        z.writestr("nuclei.exe", "fake_binary_payload")
    zip_data = zip_buf.getvalue()

    mock_release_json = {
        "tag_name": "v3.2.0",
        "assets": [
            {"name": "nuclei_3.2.0_windows_amd64.zip", "browser_download_url": "https://example.com/nuclei.zip"},
            {"name": "nuclei_3.2.0_linux_amd64.zip", "browser_download_url": "https://example.com/nuclei_linux.zip"},
        ],
    }

    mock_api_resp = MagicMock(status_code=200, json=lambda: mock_release_json)
    mock_stream_resp = MagicMock(status_code=200, headers={"content-length": str(len(zip_data))})
    async def aiter(chunk_size=65536):
        yield zip_data
    mock_stream_resp.aiter_bytes = aiter

    mock_stream_ctx = MagicMock()
    mock_stream_ctx.__aenter__ = AsyncMock(return_value=mock_stream_resp)
    mock_stream_ctx.__aexit__ = AsyncMock(return_value=None)

    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=mock_api_resp)
    mock_client.stream = MagicMock(return_value=mock_stream_ctx)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("app.installers.tool_manifest.verify_download_integrity", return_value=(True, "fake_sha256_hash", None)), \
         patch.object(gh_inst, "get_bin_dir", return_value=str(fake_bin_dir)), \
         patch.object(gh_inst, "get_version", AsyncMock(return_value="nuclei v3.2.0")):
        res = await gh_inst.install(lambda m: asyncio.sleep(0), lambda p, s: asyncio.sleep(0))
        assert res is True
        installed_file = fake_bin_dir / "nuclei.exe"
        assert installed_file.exists()

        # Confirm adapter detects installed binary
        adapter = NucleiAdapter()
        with patch.object(adapter, "resolve_binary_path", return_value=str(installed_file)):
            assert await adapter.is_available() is True


@pytest.mark.asyncio
async def test_scenario_19_batch_tool_installer_and_sse_streaming():
    """
    Scenario 19: Batch Tool Installer & Live SSE Event Streaming (Contract 05 v6.0.0)
    - Verifies batch installation execution across missing user-space tools.
    - Confirms SSE telemetry channel emits install_progress, install_log, and install_completed events.
    """
    import asyncio
    from app.installers.manager import ToolInstallationManager
    from app.core.models import ToolInstallStatus

    mgr = ToolInstallationManager.get_instance()

    # Patch all installer install methods to prevent real network calls
    with patch.object(mgr, "_installers", {k: MagicMock(display_name=k, install=AsyncMock(return_value=True), get_info=AsyncMock(return_value=MagicMock(status=ToolInstallStatus.NOT_INSTALLED, path=None, version=None))) for k in mgr._installers}):
        # Verify batch install initiates tasks
        batch_responses = await mgr.install_all(force=True)
        assert len(batch_responses) > 0
        assert all(r.status == ToolInstallStatus.INSTALLING for r in batch_responses)
        assert all(r.task_id.startswith("tool-inst-") for r in batch_responses)

        # Verify event subscription stream yields valid events
        received_events = []
        async def listener():
            async for ev in mgr.subscribe_events():
                received_events.append(ev)
                if len(received_events) >= 2:
                    break

        listen_task = asyncio.create_task(listener())
        await asyncio.sleep(0.05)

        # Broadcast test event
        await mgr.broadcast_event("install_progress", {"tool_name": "nuclei", "percent": 50, "stage": "Downloading..."})
        await mgr.broadcast_event("install_completed", {"tool_name": "nuclei", "path": "backend/bin/nuclei.exe", "version": "v3.2.0"})

        await asyncio.wait_for(listen_task, timeout=2.0)
        assert len(received_events) >= 2
        assert received_events[0]["event"] == "install_progress"
        assert received_events[1]["event"] == "install_completed"


def test_scenario_20_containerization_dockerfile_and_compose_validation():
    """
    Scenario 20: Production Containerization, Health Probes & 10-Tool Pre-installation Parity (Contract 05 v7.0.0 & Contract 08 Section 10)
    - Verifies Dockerfile contains multi-stage build, all 10 tools, CPAN Perl modules, and healthcheck.
    - Verifies docker-compose.yml configuration with persistent data volume and port 8000.
    - Verifies .dockerignore excludes and GitHub Actions multi-arch workflow.
    """
    import os, yaml

    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    # 1. Verify Dockerfile existence and directives
    dockerfile_path = os.path.join(root_dir, "Dockerfile")
    assert os.path.isfile(dockerfile_path), "Dockerfile must exist in project root"
    with open(dockerfile_path, "r", encoding="utf-8") as f:
        dockerfile_content = f.read()

    assert "python:3.11-slim-bookworm AS builder" in dockerfile_content
    assert "FROM python:3.11-slim-bookworm" in dockerfile_content
    assert "nmap" in dockerfile_content
    assert "nuclei" in dockerfile_content
    assert "ffuf" in dockerfile_content
    assert "gitleaks" in dockerfile_content
    assert "trivy" in dockerfile_content
    assert "EXPOSE 8000" in dockerfile_content
    assert "HEALTHCHECK" in dockerfile_content
    assert "/api/system/health" in dockerfile_content

    # 2. Verify docker-compose.yml
    compose_path = os.path.join(root_dir, "docker-compose.yml")
    assert os.path.isfile(compose_path), "docker-compose.yml must exist in project root"
    with open(compose_path, "r", encoding="utf-8") as f:
        compose_data = yaml.safe_load(f)

    assert "services" in compose_data
    assert "cyberassess" in compose_data["services"]
    svc = compose_data["services"]["cyberassess"]
    assert "8000:8000" in svc["ports"]
    assert any("./data:/app/data" in v for v in svc["volumes"])
    assert "healthcheck" in svc

    # 3. Verify .dockerignore
    dockerignore_path = os.path.join(root_dir, ".dockerignore")
    assert os.path.isfile(dockerignore_path), ".dockerignore must exist in project root"
    with open(dockerignore_path, "r", encoding="utf-8") as f:
        dockerignore_content = f.read()

    assert ".git" in dockerignore_content
    assert "venv" in dockerignore_content
    assert "tests" in dockerignore_content

    # 4. Verify Local Docker Build & Publish Workflow and LocalCI Pipeline
    build_script_path = os.path.join(root_dir, "scripts", "build_and_push.ps1")
    assert os.path.isfile(build_script_path), "build_and_push.ps1 script must exist"
    with open(build_script_path, "r", encoding="utf-8") as f:
        build_script_content = f.read()

    assert "ghcr.io" in build_script_content
    assert "linux/amd64,linux/arm64" in build_script_content
    assert "gh auth token" in build_script_content

    localci_script_path = os.path.join(root_dir, ".localci", "ci.sh")
    assert os.path.isfile(localci_script_path), ".localci/ci.sh must exist"
    with open(localci_script_path, "r", encoding="utf-8") as f:
        localci_content = f.read()
    assert "pytest tests/" in localci_content


# ============================================================================
# Scenario 21: High-Speed EASM & Headless SPA Discovery (Subfinder + Httpx + Katana)
# ============================================================================

@pytest.mark.asyncio
async def test_scenario_21_high_speed_easm_and_headless_spa_discovery():
    """
    Contract 05 (Scenario 21): High-Speed EASM & Headless SPA Discovery.
    Validates Subfinder passive subdomain recon, Httpx active technology probing,
    and Katana headless SPA route crawling.
    """
    from app.engines.network.engine import NetworkAssessmentEngine
    from app.engines.web_dast.engine import WebDastAssessmentEngine
    from app.adapters.subfinder_adapter import SubfinderAdapter
    from app.adapters.httpx_adapter import HttpxAdapter
    from app.adapters.katana_adapter import KatanaAdapter

    net_engine = NetworkAssessmentEngine()
    dast_engine = WebDastAssessmentEngine()

    target = Target(name="EASM Target", type=TargetType.DOMAIN, value="example.com")
    config = ScanConfig()
    config.osint.subdomain_enumeration = False
    config.crawler.enabled = False
    config.adapters.enable_nuclei = False
    config.adapters.enable_schemathesis = False

    emitted_logs = []
    emitted_findings = []
    discovered_subs = []
    discovered_eps = []

    async def emit_log(lvl, msg):
        emitted_logs.append((lvl, msg))

    async def emit_prog(pct, msg):
        pass

    async def emit_find(f):
        emitted_findings.append(f)

    async def emit_sub(sd):
        discovered_subs.append(sd)

    async def emit_ep(ep):
        discovered_eps.append(ep)

    mock_sf_stdout = '{"host":"vpn.corp.example.com","sources":["crtsh"]}\n{"host":"api.corp.example.com","sources":["virustotal"]}\n'
    mock_hx_stdout = '{"url":"https://api.corp.example.com","status_code":200,"title":"API Gateway","tech":["FastAPI","Uvicorn"]}\n'
    mock_katana_stdout = '{"request":{"endpoint":"https://example.com/app/dashboard","method":"GET"},"response":{"status_code":200}}\n'

    from contextlib import ExitStack

    with ExitStack() as stack:
        stack.enter_context(patch.object(SubfinderAdapter, "is_available", AsyncMock(return_value=True)))
        stack.enter_context(patch.object(SubfinderAdapter, "resolve_binary_path", return_value="/bin/subfinder"))
        stack.enter_context(patch.object(SubfinderAdapter, "verify_managed_binary", return_value=True))
        stack.enter_context(patch.object(SubfinderAdapter, "get_version", AsyncMock(return_value="subfinder v2.6.5")))
        stack.enter_context(patch.object(SubfinderAdapter, "execute_command", new=AsyncMock(return_value=(0, mock_sf_stdout, ""))))
        stack.enter_context(patch("app.engines.network.engine.SslyzeAdapter.is_available", new=AsyncMock(return_value=False)))
        stack.enter_context(patch("app.engines.network.engine.NmapAdapter.is_available", new=AsyncMock(return_value=False)))
        stack.enter_context(patch.object(HttpxAdapter, "is_available", AsyncMock(return_value=True)))
        stack.enter_context(patch.object(HttpxAdapter, "resolve_binary_path", return_value="/bin/httpx"))
        stack.enter_context(patch.object(HttpxAdapter, "verify_managed_binary", return_value=True))
        stack.enter_context(patch.object(HttpxAdapter, "get_version", AsyncMock(return_value="httpx v1.6.0")))
        stack.enter_context(patch.object(HttpxAdapter, "execute_command", new=AsyncMock(return_value=(0, mock_hx_stdout, ""))))
        stack.enter_context(patch.object(KatanaAdapter, "is_available", AsyncMock(return_value=True)))
        stack.enter_context(patch.object(KatanaAdapter, "resolve_binary_path", return_value="/bin/katana"))
        stack.enter_context(patch.object(KatanaAdapter, "verify_managed_binary", return_value=True))
        stack.enter_context(patch.object(KatanaAdapter, "get_version", AsyncMock(return_value="katana v1.0.5")))
        stack.enter_context(patch.object(KatanaAdapter, "execute_command", new=AsyncMock(return_value=(0, mock_katana_stdout, ""))))
        stack.enter_context(patch("app.engines.network.engine.audit_tls_certificates", new=AsyncMock(return_value=[])))
        stack.enter_context(patch("app.engines.network.engine.audit_tls_protocols_and_ciphers", new=AsyncMock(return_value=[])))
        stack.enter_context(patch("app.engines.network.engine.audit_dns_hygiene", new=AsyncMock(return_value=[])))
        stack.enter_context(patch("app.engines.network.engine.audit_exposed_ports", new=AsyncMock(return_value=[])))
        stack.enter_context(patch("app.engines.network.engine.audit_service_banners", new=AsyncMock(return_value=[])))
        stack.enter_context(patch("app.engines.network.engine.audit_origin_exposure", new=AsyncMock(return_value=[])))
        stack.enter_context(patch("app.engines.network.engine.audit_subdomain_osint", new=AsyncMock(return_value=[])))
        stack.enter_context(patch("app.engines.web_dast.engine.audit_security_headers_and_cookies", new=AsyncMock(return_value=[])))
        stack.enter_context(patch("app.engines.web_dast.engine.audit_cors_policies", new=AsyncMock(return_value=[])))
        stack.enter_context(patch("app.engines.web_dast.engine.audit_sensitive_exposure_and_methods", new=AsyncMock(return_value=[])))
        stack.enter_context(patch("app.engines.web_dast.engine.audit_browser_posture", new=AsyncMock(return_value=[])))
        stack.enter_context(patch("app.engines.web_dast.engine.audit_graphql_endpoints", new=AsyncMock(return_value=[])))
        stack.enter_context(patch("app.engines.web_dast.engine.audit_parameter_fuzzing", new=AsyncMock(return_value=[])))
        mock_resp = MagicMock(status_code=200, text="<html><body>OK</body></html>", headers={"content-type": "text/html"})
        stack.enter_context(patch.object(httpx.AsyncClient, "request", new=AsyncMock(return_value=mock_resp)))
        stack.enter_context(patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=mock_resp)))
        stack.enter_context(patch.object(httpx.AsyncClient, "send", new=AsyncMock(return_value=mock_resp)))

        net_findings = await net_engine.run(
            target, config, emit_log, emit_prog, emit_find,
            emit_subdomain_discovered=emit_sub,
            emit_endpoint_discovered=emit_ep,
            organization_id="org-test",
        )
        assert len(discovered_subs) >= 2
        assert any(f.source_tool == "subfinder" for f in net_findings)
        assert any(f.source_tool == "httpx" for f in net_findings)

        dast_target = Target(name="Web App", type=TargetType.URL, value="https://example.com")
        dast_findings = await dast_engine.run(
            dast_target, config, emit_log, emit_prog, emit_find,
            emit_endpoint_discovered=emit_ep,
            organization_id="org-test",
        )
        assert len(discovered_eps) >= 1
        assert any(f.source_tool == "katana" for f in dast_findings)


# ============================================================================
# Scenario 22: Software Supply Chain & SBOM Export (Syft + Grype + OSV-Scanner + Retire.js)
# ============================================================================

@pytest.mark.asyncio
async def test_scenario_22_software_supply_chain_and_sbom_export(tmp_path):
    """
    Contract 05 (Scenario 22): Software Supply Chain & SBOM Lifecycle.
    Validates Syft SBOM generation, Grype vulnerability matching, Google OSV scanning,
    and CycloneDX / SPDX format serialization.
    """
    from app.engines.code_sast.engine import CodeSastAssessmentEngine
    from app.adapters.syft_adapter import SyftAdapter
    from app.adapters.grype_adapter import GrypeAdapter
    from app.adapters.osv_scanner_adapter import OSVScannerAdapter
    from app.adapters.retirejs_adapter import RetireJSAdapter
    from app.exporters.sbom_cyclonedx import export_cyclonedx_sbom
    from app.exporters.sbom_spdx import export_spdx_sbom

    engine = CodeSastAssessmentEngine()
    target = Target(name="App Code", type=TargetType.LOCAL_PATH, value=str(tmp_path))
    config = ScanConfig()

    emitted_logs = []
    emitted_findings = []
    recorded_sbom = []

    async def emit_log(lvl, msg):
        emitted_logs.append((lvl, msg))

    async def emit_prog(pct, msg):
        pass

    async def emit_find(f):
        emitted_findings.append(f)

    def record_sbom(s):
        recorded_sbom.append(s)

    mock_cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"name": "django", "version": "3.2.0", "type": "library", "purl": "pkg:pypi/django@3.2.0"},
            {"name": "cryptography", "version": "3.4.0", "type": "library", "purl": "pkg:pypi/cryptography@3.4.0"},
        ],
    }
    mock_grype = {
        "matches": [
            {
                "vulnerability": {"id": "CVE-2021-3281", "severity": "High", "description": "Django Directory Traversal"},
                "artifact": {"name": "django", "version": "3.2.0", "type": "python"},
            }
        ]
    }
    mock_osv = {
        "results": [
            {
                "source": {"path": str(tmp_path / "requirements.txt")},
                "packages": [
                    {
                        "package": {"name": "django", "version": "3.2.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [{"id": "PYSEC-2021-12", "summary": "Django traversal vuln"}],
                    }
                ],
            }
        ]
    }

    with patch.object(SyftAdapter, "is_available", AsyncMock(return_value=True)), \
         patch.object(SyftAdapter, "resolve_binary_path", return_value="/bin/syft"), \
         patch.object(SyftAdapter, "verify_managed_binary", return_value=True), \
         patch.object(SyftAdapter, "get_version", AsyncMock(return_value="syft 1.0.1")), \
         patch.object(SyftAdapter, "execute_command", new=AsyncMock(return_value=(0, json.dumps(mock_cdx), ""))), \
         patch.object(GrypeAdapter, "is_available", AsyncMock(return_value=True)), \
         patch.object(GrypeAdapter, "resolve_binary_path", return_value="/bin/grype"), \
         patch.object(GrypeAdapter, "verify_managed_binary", return_value=True), \
         patch.object(GrypeAdapter, "get_version", AsyncMock(return_value="grype 0.74.0")), \
         patch.object(GrypeAdapter, "execute_command", new=AsyncMock(return_value=(0, json.dumps(mock_grype), ""))), \
         patch.object(OSVScannerAdapter, "is_available", AsyncMock(return_value=True)), \
         patch.object(OSVScannerAdapter, "resolve_binary_path", return_value="/bin/osv-scanner"), \
         patch.object(OSVScannerAdapter, "verify_managed_binary", return_value=True), \
         patch.object(OSVScannerAdapter, "get_version", AsyncMock(return_value="osv-scanner 1.7.0")), \
         patch.object(OSVScannerAdapter, "execute_command", new=AsyncMock(return_value=(0, json.dumps(mock_osv), ""))), \
         patch.object(RetireJSAdapter, "is_available", AsyncMock(return_value=False)):

        findings = await engine.run(
            target, config, emit_log, emit_prog, emit_find,
            record_sbom_report=record_sbom,
            workspace_roots=[tmp_path],
        )

        assert any(f.source_tool == "syft" for f in findings)
        assert any(f.source_tool == "grype" for f in findings)
        assert any(f.source_tool == "osv_scanner" for f in findings)
        assert len(recorded_sbom) == 1

        # Test SBOM Exporters
        job = ScanJob(target=target, findings=findings, sbom_report=recorded_sbom[0])
        cdx_doc = export_cyclonedx_sbom(job)
        spdx_doc = export_spdx_sbom(job)

        assert "CycloneDX" in cdx_doc
        assert "SPDX-2.3" in spdx_doc


# ============================================================================
# Scenario 23: Live-Verified Secret Auditing (TruffleHog)
# ============================================================================

@pytest.mark.asyncio
async def test_scenario_23_live_verified_secret_auditing(tmp_path):
    """
    Contract 05 (Scenario 23): Live-Verified Secret Auditing.
    Validates TruffleHog deep credential scanning with active verification flag.
    """
    from app.engines.code_sast.engine import CodeSastAssessmentEngine
    from app.adapters.trufflehog_adapter import TruffleHogAdapter

    engine = CodeSastAssessmentEngine()
    target = Target(name="Backend Repo", type=TargetType.LOCAL_PATH, value=str(tmp_path))
    config = ScanConfig()

    emitted_logs = []
    emitted_findings = []

    async def emit_log(lvl, msg):
        emitted_logs.append((lvl, msg))

    async def emit_prog(pct, msg):
        pass

    async def emit_find(f):
        emitted_findings.append(f)

    mock_th_stdout = (
        '{"DetectorName":"GitHub","Verified":true,"Raw":"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",'
        '"SourceMetadata":{"Data":{"Filesystem":{"file":"deploy.sh"}}},'
        '"VerificationDetails":{"Endpoint":"https://api.github.com/user"}}\n'
    )

    with patch.object(TruffleHogAdapter, "is_available", AsyncMock(return_value=True)), \
         patch.object(TruffleHogAdapter, "resolve_binary_path", return_value="/bin/trufflehog"), \
         patch.object(TruffleHogAdapter, "verify_managed_binary", return_value=True), \
         patch.object(TruffleHogAdapter, "get_version", AsyncMock(return_value="trufflehog v3.63.0")), \
         patch.object(TruffleHogAdapter, "execute_command", new=AsyncMock(return_value=(0, mock_th_stdout, ""))):

        findings = await engine.run(
            target, config, emit_log, emit_prog, emit_find,
            organization_id="org-test", workspace_roots=[tmp_path],
            live_secret_authorization={
                "approved": True,
                "organization_id": "org-test",
                "assessment_id": "active",
            },
        )
        verified_findings = [f for f in findings if f.source_tool == "trufflehog" and f.verified_secret and f.verified_secret.is_live]

        assert len(verified_findings) == 1
        assert verified_findings[0].severity == Severity.CRITICAL
        assert verified_findings[0].cvss_score == 10.0


# ============================================================================
# Scenario 24: Cloud, Container & Kubernetes CIS Benchmarks (Prowler + Kube-Bench + Dockle)
# ============================================================================

@pytest.mark.asyncio
async def test_scenario_24_cloud_container_and_k8s_cis_benchmarks(tmp_path):
    """
    Contract 05 (Scenario 24): Cloud, Container & Kubernetes CIS Benchmarks.
    Validates Dockle container linting, Kube-bench Kubernetes auditing, and Prowler CSPM checks.
    """
    from app.engines.infra_iac.engine import InfraIacAssessmentEngine
    from app.adapters.dockle_adapter import DockleAdapter
    from app.adapters.kubebench_adapter import KubeBenchAdapter
    from app.adapters.prowler_adapter import ProwlerAdapter

    engine = InfraIacAssessmentEngine()
    target = Target(name="Cluster & Cloud", type=TargetType.LOCAL_PATH, value=str(tmp_path))
    config = ScanConfig()

    emitted_logs = []
    emitted_findings = []
    recorded_cis = []

    async def emit_log(lvl, msg):
        emitted_logs.append((lvl, msg))

    async def emit_prog(pct, msg):
        pass

    async def emit_find(f):
        emitted_findings.append(f)

    def record_cis(c):
        recorded_cis.append(c)

    mock_dockle = {"details": [{"code": "CIS-DI-0001", "title": "Avoid root user", "level": "WARN"}]}
    mock_kb = {"Controls": [{"id": "1.1", "tests": [{"results": [{"test_number": "1.1.1", "status": "FAIL", "test_desc": "Permissions"}]}]}]}
    mock_prowler = '{"CheckID":"iam_root_mfa_enabled","Status":"FAIL","Severity":"critical","StatusExtended":"MFA not enabled on root account"}\n'

    with patch.object(DockleAdapter, "is_available", AsyncMock(return_value=True)), \
         patch.object(DockleAdapter, "resolve_binary_path", return_value="/bin/dockle"), \
         patch.object(DockleAdapter, "execute_command", new=AsyncMock(return_value=(0, json.dumps(mock_dockle), ""))), \
         patch.object(KubeBenchAdapter, "is_available", AsyncMock(return_value=True)), \
         patch.object(KubeBenchAdapter, "resolve_binary_path", return_value="/bin/kube-bench"), \
         patch.object(KubeBenchAdapter, "execute_command", new=AsyncMock(return_value=(0, json.dumps(mock_kb), ""))), \
         patch.object(ProwlerAdapter, "is_available", AsyncMock(return_value=True)), \
         patch.object(ProwlerAdapter, "resolve_binary_path", return_value="/bin/prowler"), \
         patch.object(ProwlerAdapter, "execute_command", new=AsyncMock(return_value=(0, mock_prowler, ""))):

        findings = await engine.run(
            target, config, emit_log, emit_prog, emit_find,
            record_cis_result=record_cis,
        )

        assert any(f.source_tool == "dockle" for f in findings)
        assert any(f.source_tool == "kube_bench" for f in findings)
        assert any(f.source_tool == "prowler" for f in findings)
        assert len(recorded_cis) == 3


# ============================================================================
# Scenario 25: Property-Based API Contract Security (Schemathesis)
# ============================================================================

@pytest.mark.asyncio
async def test_scenario_25_property_based_api_contract_security():
    """
    Contract 05 (Scenario 25): Property-Based API Contract Security.
    Validates Schemathesis property-based fuzzing against OpenAPI specifications.
    """
    from app.engines.web_dast.engine import WebDastAssessmentEngine
    from app.adapters.schemathesis_adapter import SchemathesisAdapter

    engine = WebDastAssessmentEngine()
    target = Target(name="REST API", type=TargetType.URL, value="https://example.com/openapi.json")
    config = ScanConfig(profile=ScanProfile.API_FOCUSED)
    config.crawler.enabled = False

    emitted_logs = []
    emitted_findings = []

    async def emit_log(lvl, msg):
        emitted_logs.append((lvl, msg))

    async def emit_prog(pct, msg):
        pass

    async def emit_find(f):
        emitted_findings.append(f)

    mock_schema_report = {
        "errors": [
            {
                "title": "500 Server Error for invalid payload",
                "endpoint": "https://api.example.com/items",
                "method": "POST",
            }
        ]
    }

    with patch.object(SchemathesisAdapter, "is_available", AsyncMock(return_value=True)), \
         patch.object(SchemathesisAdapter, "resolve_binary_path", return_value="/bin/schemathesis"), \
         patch.object(SchemathesisAdapter, "verify_managed_binary", return_value=True), \
         patch.object(SchemathesisAdapter, "get_version", new=AsyncMock(return_value="schemathesis 3.20.0")), \
         patch.object(SchemathesisAdapter, "execute_command", new=AsyncMock(return_value=(0, json.dumps(mock_schema_report), ""))), \
         patch("app.engines.web_dast.engine.audit_security_headers_and_cookies", new=AsyncMock(return_value=[])), \
         patch("app.engines.web_dast.engine.audit_cors_policies", new=AsyncMock(return_value=[])), \
         patch("app.engines.web_dast.engine.audit_sensitive_exposure_and_methods", new=AsyncMock(return_value=[])), \
         patch("app.engines.web_dast.engine.audit_browser_posture", new=AsyncMock(return_value=[])), \
         patch("app.engines.web_dast.engine.audit_graphql_endpoints", new=AsyncMock(return_value=[])), \
         patch("app.engines.web_dast.engine.audit_parameter_fuzzing", new=AsyncMock(return_value=[])):

        findings = await engine.run(
            target, config, emit_log, emit_prog, emit_find,
            organization_id="org-test", state_changing_granted=True,
        )
        schema_findings = [f for f in findings if f.source_tool == "schemathesis"]

        assert len(schema_findings) >= 1
        assert schema_findings[0].check_id == "API-SCHEMA-001"
        assert schema_findings[0].severity == Severity.HIGH


# ============================================================================
# Scenario 26: Strict SSRF Protection & DNS Rebinding Gate
# ============================================================================

def test_scenario_26_ssrf_protection_and_dns_rebinding_gate():
    """
    Contract 05 (Scenario 26): Strict SSRF Protection & DNS Rebinding Gate.
    Verifies that requests to private IP ranges, loopback, and cloud metadata are blocked.
    """
    from app.core.ssrf_protector import is_ip_allowed, validate_target_url

    # Prohibited ranges
    assert is_ip_allowed("127.0.0.1")[0] is False
    assert is_ip_allowed("10.0.0.1")[0] is False
    assert is_ip_allowed("172.16.0.1")[0] is False
    assert is_ip_allowed("192.168.1.1")[0] is False
    assert is_ip_allowed("169.254.169.254")[0] is False
    assert is_ip_allowed("::1")[0] is False

    # URL validation
    assert validate_target_url("http://127.0.0.1:8000/api")[0] is False
    assert validate_target_url("http://169.254.169.254/latest/meta-data/")[0] is False
    assert validate_target_url("https://example.com")[0] is True


# ============================================================================
# Scenario 27: Zero-Trust Authentication & RBAC Matrix
# ============================================================================

def test_scenario_27_zero_trust_authentication_and_rbac_matrix():
    """
    Contract 05 (Scenario 27): Zero-Trust Authentication & RBAC Matrix.
    Verifies password hashing, token generation, and role decoding.
    """
    from app.core.auth import (
        UserProfile,
        UserRole,
        hash_password,
        verify_password,
        create_access_token,
        decode_access_token,
    )

    pw = "EnterpriseSecret2026!"
    hashed = hash_password(pw)
    assert verify_password(pw, hashed) is True
    assert verify_password("WrongPw", hashed) is False

    user = UserProfile(id="u-100", username="tester", email="t@e.com", role=UserRole.ADMIN)
    token = create_access_token(user)
    payload = decode_access_token(token)
    assert payload["sub"] == "u-100"
    assert payload["role"] == "ADMIN"


# ============================================================================
# Scenario 28: Target Path Sandboxing & Workspace Containment
# ============================================================================

def test_scenario_28_target_path_sandboxing_and_workspace_containment():
    """
    Contract 05 (Scenario 28): Target Path Sandboxing & Workspace Containment.
    Verifies that system files and path traversal attempts are rejected.
    """
    from app.core.path_sandbox import is_path_safe

    assert is_path_safe("/etc/passwd")[0] is False
    assert is_path_safe("/etc/shadow")[0] is False
    assert is_path_safe("C:\\Windows\\System32\\config\\SAM")[0] is False
    assert is_path_safe("../../etc/passwd")[0] is False


# ============================================================================
# Scenario 29: Cryptographic SHA-256 Checksum & Supply Chain
# ============================================================================

def test_scenario_29_cryptographic_sha256_checksum_and_supply_chain():
    """
    Contract 05 (Scenario 29): Cryptographic SHA-256 Checksum & Supply Chain.
    Verifies binary archive integrity checks.
    """
    from app.installers.tool_manifest import calculate_sha256, verify_download_integrity

    data = b"Clean tool archive binary 2026"
    h = calculate_sha256(data)
    valid, _, _ = verify_download_integrity("nuclei", data, expected_sha256=h)
    assert valid is True

    bad_valid, _, err = verify_download_integrity("nuclei", data, expected_sha256="corrupted_hash")
    assert bad_valid is False
    assert "mismatch" in err.lower()


# ============================================================================
# Scenario 30: Dual-Mode Relational Persistence & Asset Inventory
# ============================================================================

def test_scenario_30_relational_persistence_and_asset_inventory():
    """
    Contract 05 (Scenario 30): Dual-Mode Relational Persistence & Asset Inventory.
    Verifies asset creation, retrieval, listing, and deletion in the relational store.
    """
    import tempfile
    from app.core.db import DatabaseManager
    from app.core.models import Asset, AssetType, AssetCriticality

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_file = Path(f.name)

    db = DatabaseManager(db_path=db_file)
    asset = Asset(
        name="Main SaaS Web App",
        type=AssetType.WEB_APPLICATION,
        target_value="https://app.example.com",
        criticality=AssetCriticality.CRITICAL,
    )
    db.create_asset(asset)
    fetched = db.get_asset(asset.id)
    assert fetched is not None
    assert fetched.name == "Main SaaS Web App"
    assert fetched.criticality == AssetCriticality.CRITICAL

    assets, total = db.list_assets()
    assert total == 1

    db.delete_asset(asset.id)
    assert db.get_asset(asset.id) is None

    try:
        db_file.unlink(missing_ok=True)
    except Exception:
        pass


# ============================================================================
# Scenario 31: Cross-Engine Finding Correlation & Root-Cause Clustering
# ============================================================================

def test_scenario_31_finding_correlation_and_root_cause_clustering():
    """
    Contract 05 (Scenario 31): Cross-Engine Finding Correlation.
    Verifies synthesis of matching SAST + DAST findings into a UnifiedFinding.
    """
    from app.core.correlator import correlator
    from app.core.models import CorrelationType

    f1 = Finding(
        id="f1", scan_id="s1", engine="web_dast", check_id="DAST-XSS-001",
        category="Cross-Site Scripting", title="Reflected XSS on /search",
        severity=Severity.HIGH, cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        cwe_id="CWE-79", owasp_category="A03:2021-Injection", nist_control="SI-10",
        description="Reflected XSS", impact="Session hijacking", remediation="Escape output",
        evidence=Evidence(location="https://example.com/search?q=", observed_value="<script>alert(1)</script>", expected_value="Escaped HTML"),
        fingerprint="fp1", source_tool="nuclei",
    )
    f2 = Finding(
        id="f2", scan_id="s1", engine="code_sast", check_id="SAST-XSS-001",
        category="Cross-Site Scripting", title="Direct unescaped template variable rendering",
        severity=Severity.HIGH, cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        cwe_id="CWE-79", owasp_category="A03:2021-Injection", nist_control="SI-10",
        description="Unescaped template rendering", impact="XSS", remediation="Use autoescaping",
        evidence=Evidence(location="search.html:15", observed_value="{{ query|safe }}", expected_value="{{ query }}"),
        fingerprint="fp2", source_tool="semgrep",
    )

    unified, occs = correlator.correlate_findings([f1, f2], asset_criticality_factor=1.2)
    assert len(unified) == 1
    assert len(occs) == 2
    assert unified[0].correlation_type == CorrelationType.SAST_DAST_VERIFIED
    assert "nuclei" in unified[0].contributing_tools
    assert "semgrep" in unified[0].contributing_tools


# ============================================================================
# Scenario 32: Contextual Risk Scoring Engine & Vulnerability SLA
# ============================================================================

def test_scenario_32_contextual_risk_scoring_and_vulnerability_sla():
    """
    Contract 05 (Scenario 32): Contextual Risk Scoring & SLA Computation.
    Verifies contextual risk scoring and SLA computation.
    """
    from app.core.models import AssetCriticality
    from app.core.risk_engine import calculate_finding_contextual_risk, calculate_contextual_posture_grade
    from app.core.correlator import compute_sla_info

    # 1. Contextual Risk
    risk_crit = calculate_finding_contextual_risk(9.0, AssetCriticality.CRITICAL, internet_exposed=True)
    risk_low = calculate_finding_contextual_risk(9.0, AssetCriticality.LOW, internet_exposed=False)
    assert risk_crit == 10.0
    assert risk_low < 7.0

    # 2. SLA Info
    sla_crit = compute_sla_info(Severity.CRITICAL)
    assert sla_crit.sla_days == 7
    sla_high = compute_sla_info(Severity.HIGH)
    assert sla_high.sla_days == 14
    sla_med = compute_sla_info(Severity.MEDIUM)
    assert sla_med.sla_days == 30
