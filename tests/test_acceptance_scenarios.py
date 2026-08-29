"""
Contract 05 End-to-End Acceptance Test Suite (All 8 Test Scenarios).
Verifies complete system functionality against formal contract deliverables and Definition of Done.
"""

from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import shutil
import tempfile
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
    calculate_fingerprint,
    mask_secret,
)
from app.core.grading import calculate_scan_grade
from app.core.storage import save_scan, get_scan
from app.engines.network.engine import NetworkAssessmentEngine
from app.engines.network.dns_hygiene import audit_dns_hygiene
from app.engines.network.port_checker import audit_exposed_ports
from app.engines.web_dast.engine import WebDastAssessmentEngine
from app.engines.web_dast.headers_cookies import audit_security_headers_and_cookies
from app.engines.web_dast.cors_analyzer import audit_cors_policies
from app.engines.web_dast.api_inspector import audit_sensitive_exposure_and_methods
from app.engines.web_dast.graphql_auditor import audit_graphql_endpoints
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
