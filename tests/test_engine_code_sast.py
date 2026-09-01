"""
Unit tests for Engine 3: Static Code Analysis, Secrets & Dependency SCA.
"""

import shutil
import tempfile
from pathlib import Path
import pytest

from app.core.models import Target, TargetType, ScanConfig, Severity, ToolAdapterConfig
from app.engines.code_sast.secret_scanner import (
    calculate_shannon_entropy,
    audit_code_secrets,
)
from app.engines.code_sast.crypto_lint import audit_crypto_patterns
from app.engines.code_sast.injection_lint import audit_injection_patterns
from app.engines.code_sast.dependency_auditor import audit_dependencies
from app.engines.code_sast.engine import CodeSastAssessmentEngine


def test_shannon_entropy():
    # Low entropy: repeating characters
    assert calculate_shannon_entropy("aaaaaaaaaa") == 0.0
    # High entropy: random alphanumeric token
    high_ent = calculate_shannon_entropy("c2hhMjU2OmRmMjM4YWZlYzRjYjhi")
    assert high_ent > 3.5


@pytest.mark.asyncio
async def test_secret_scanner_detection_and_masking():
    temp_dir = Path(tempfile.mkdtemp())
    try:
        sample_code = temp_dir / "config.py"
        mock_aws = "AKIA" + "IOSFODNN7EXAMPLE"
        mock_ghp = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
        mock_stripe = "sk_live_" + "123456789012345678901234"
        sample_code.write_text(f"""
# AWS credentials
AWS_ACCESS_KEY = "{mock_aws}"
GITHUB_TOKEN = "{mock_ghp}"
STRIPE_KEY = "{mock_stripe}"
DB_URI = "postgres://admin:supersecretpassword@localhost:5432/production"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA..."
""", encoding="utf-8")

        findings = await audit_code_secrets(str(temp_dir))
        check_ids = [f.check_id for f in findings]

        assert "SAST-SEC-001" in check_ids  # AWS Access Key
        assert "SAST-SEC-003" in check_ids  # GitHub PAT
        assert "SAST-SEC-004" in check_ids  # Stripe Secret Key
        assert "SAST-SEC-007" in check_ids  # Private Key
        assert "SAST-SEC-008" in check_ids  # Database URI

        # Verify zero unmasked plaintext secrets in evidence
        for f in findings:
            assert "AKIAIOSFODNN7EXAMPLE" not in f.evidence.observed_value
            assert "supersecretpassword" not in f.evidence.observed_value
            assert "*" in f.evidence.observed_value
    finally:
        shutil.rmtree(temp_dir)


@pytest.mark.asyncio
async def test_crypto_lint_findings():
    temp_dir = Path(tempfile.mkdtemp())
    try:
        sample_code = temp_dir / "crypto_utils.py"
        sample_code.write_text("""
import hashlib
import random
from Crypto.Cipher import AES

def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

def generate_session_token():
    auth_token = str(random.random())
    return auth_token

def encrypt_data(data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)
""", encoding="utf-8")

        findings = await audit_crypto_patterns(str(temp_dir))
        check_ids = [f.check_id for f in findings]

        assert "SAST-CRY-001" in check_ids  # MD5
        assert "SAST-CRY-002" in check_ids  # random.random() in auth token
        assert "SAST-CRY-003" in check_ids  # AES-ECB
    finally:
        shutil.rmtree(temp_dir)


@pytest.mark.asyncio
async def test_injection_lint_findings():
    temp_dir = Path(tempfile.mkdtemp())
    try:
        sample_code = temp_dir / "app_logic.py"
        sample_code.write_text("""
import subprocess
import pickle
import os

def query_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

def ping_host(host):
    subprocess.Popen(f"ping {host}", shell=True)

def load_payload(raw_data):
    return pickle.loads(raw_data)
""", encoding="utf-8")

        findings = await audit_injection_patterns(str(temp_dir))
        check_ids = [f.check_id for f in findings]

        assert "SAST-INJ-001" in check_ids  # SQL Injection f-string
        assert "SAST-INJ-002" in check_ids  # shell=True
        assert "SAST-INJ-003" in check_ids  # pickle.loads
    finally:
        shutil.rmtree(temp_dir)


@pytest.mark.asyncio
async def test_dependency_auditor_findings():
    temp_dir = Path(tempfile.mkdtemp())
    try:
        req_file = temp_dir / "requirements.txt"
        req_file.write_text("""
requests==2.28.0
urllib3==1.26.15
unpinned-pkg>=0.0.0
""", encoding="utf-8")

        pkg_json = temp_dir / "package.json"
        pkg_json.write_text("""{
  "dependencies": {
    "lodash": "4.17.19",
    "wildcard-lib": "*"
  }
}""", encoding="utf-8")

        findings = await audit_dependencies(str(temp_dir))
        check_ids = [f.check_id for f in findings]

        assert "SAST-DEP-001" in check_ids  # Vulnerable requests/urllib3/lodash
        assert "SAST-DEP-002" in check_ids  # Wildcard dependencies
    finally:
        shutil.rmtree(temp_dir)


@pytest.mark.asyncio
async def test_code_sast_engine_full_run():
    engine = CodeSastAssessmentEngine()
    assert engine.name == "code_sast"
    assert engine.is_applicable(Target(name="Code", type=TargetType.LOCAL_PATH, value=".")) is True
    assert engine.is_applicable(Target(name="URL", type=TargetType.URL, value="https://example.com")) is False

    temp_dir = Path(tempfile.mkdtemp())
    try:
        target = Target(name="Local Repo", type=TargetType.LOCAL_PATH, value=str(temp_dir))
        config = ScanConfig(adapters=ToolAdapterConfig(enable_semgrep=False, enable_bandit=False, enable_gitleaks=False, enable_checkov=False, enable_trivy=False))

        logs = []
        progress_updates = []
        findings_emitted = []

        async def log_cb(lvl, msg):
            logs.append((lvl, msg))

        async def prog_cb(pct, stg):
            progress_updates.append((pct, stg))

        async def find_cb(f):
            findings_emitted.append(f)

        findings = await engine.run(target, config, log_cb, prog_cb, find_cb, workspace_roots=[temp_dir])
        assert findings == []
        assert len(progress_updates) >= 4
        assert progress_updates[-1][0] == 100
    finally:
        shutil.rmtree(temp_dir)
