"""
Unit Tests for Pluggable Hybrid External Tool Adapters Layer (Chunk 2).
Contracts: 03 (Section 4), 06 (Section 2), 08 (Section 8).
"""

import asyncio
import json
import os
import shutil
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.core.models import (
    Target,
    TargetType,
    ScanConfig,
    LogLevel,
    Severity,
    ToolAdapterConfig,
    ToolExecutionMode,
)
from app.adapters.base_adapter import BaseToolAdapter
from app.adapters.nmap_adapter import NmapAdapter, extract_host
from app.adapters.sslyze_adapter import SslyzeAdapter
from app.adapters.nuclei_adapter import NucleiAdapter, normalize_target_url
from app.adapters.ffuf_adapter import FfufAdapter
from app.adapters.nikto_adapter import NiktoAdapter
from app.adapters.semgrep_adapter import SemgrepAdapter
from app.adapters.gitleaks_adapter import GitleaksAdapter
from app.adapters.bandit_adapter import BanditAdapter
from app.adapters.trivy_adapter import TrivyAdapter
from app.adapters.checkov_adapter import CheckovAdapter
from app.adapters import get_adapter_registry, discover_system_capabilities


# ============================================================================
# Dummy Concrete Adapter for Base Class Testing
# ============================================================================

class DummyAdapter(BaseToolAdapter):
    @property
    def tool_name(self) -> str:
        return "dummy_tool"

    async def get_version(self, custom_path=None):
        return "dummy 1.0.0"

    async def run(self, target, config, emit_log, emit_finding, **kwargs):
        return []


# ============================================================================
# 1. BaseToolAdapter Tests
# ============================================================================

class TestBaseToolAdapter:
    def test_resolve_binary_path(self, tmp_path):
        adapter = DummyAdapter()

        # Fallback to system PATH
        with patch("shutil.which", return_value="/usr/bin/dummy_tool"):
            resolved = adapter.resolve_binary_path()
            assert resolved == "/usr/bin/dummy_tool"

        # Custom path directly pointing to an existing file
        dummy_file = tmp_path / "dummy_tool.exe"
        dummy_file.write_text("binary content")
        resolved_custom = adapter.resolve_binary_path(str(dummy_file))
        assert resolved_custom == str(dummy_file.resolve())

        # Custom path as command name found via shutil.which
        with patch("shutil.which", side_effect=lambda name: f"/opt/bin/{name}" if name == "custom_bin" else None):
            resolved_which = adapter.resolve_binary_path("custom_bin")
            assert resolved_which == "/opt/bin/custom_bin"

    @pytest.mark.asyncio
    async def test_is_available(self, tmp_path):
        adapter = DummyAdapter()
        dummy_file = tmp_path / "dummy_bin"
        dummy_file.write_text("dummy")

        assert await adapter.is_available(str(dummy_file)) is True

        with patch("shutil.which", return_value=None):
            assert await adapter.is_available(None) is False

    @pytest.mark.asyncio
    async def test_execute_command_success(self):
        adapter = DummyAdapter()
        code, stdout, stderr = await adapter.execute_command(
            ["python", "-c", "import sys; print('hello'); sys.stderr.write('warn')"],
            timeout=5.0,
        )
        assert code == 0
        assert "hello" in stdout
        assert "warn" in stderr

    @pytest.mark.asyncio
    async def test_execute_command_empty(self):
        adapter = DummyAdapter()
        code, stdout, stderr = await adapter.execute_command([], timeout=5.0)
        assert code == -1
        assert "Empty" in stderr

    @pytest.mark.asyncio
    async def test_execute_command_timeout(self):
        adapter = DummyAdapter()
        logs = []
        async def mock_log(lvl, msg):
            logs.append((lvl, msg))

        code, stdout, stderr = await adapter.execute_command(
            ["python", "-c", "import time; time.sleep(10)"],
            timeout=0.2,
            emit_log=mock_log,
        )
        assert code == -1
        assert "timed out" in stderr
        assert any(l[0] == LogLevel.WARNING for l in logs)

    @pytest.mark.asyncio
    async def test_execute_command_nonexistent_binary(self):
        adapter = DummyAdapter()
        code, stdout, stderr = await adapter.execute_command(
            ["non_existent_binary_xyz_12345"],
            timeout=2.0,
        )
        assert code in (127, -1)


# ============================================================================
# 2. NmapAdapter Tests
# ============================================================================

NMAP_SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
<host>
    <status state="up"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <ports>
        <port protocol="tcp" portid="21">
            <state state="open"/>
            <service name="ftp" product="vsftpd" version="3.0.3"/>
        </port>
        <port protocol="tcp" portid="80">
            <state state="closed"/>
        </port>
        <port protocol="tcp" portid="3306">
            <state state="open"/>
            <service name="mysql" product="MySQL" version="8.0.35"/>
        </port>
        <port protocol="tcp" portid="6379">
            <state state="open"/>
            <service name="redis" product="Redis key-value store" version="7.0.12"/>
        </port>
        <port protocol="tcp" portid="8080">
            <state state="open"/>
            <service name="http" product="Apache Tomcat" version="9.0.50"/>
            <script id="http-title" output="Apache Tomcat/9.0.50 Error Report"/>
        </port>
    </ports>
</host>
</nmaprun>
"""

class TestNmapAdapter:
    def test_extract_host(self):
        assert extract_host("https://example.com:8443/test") == "example.com"
        assert extract_host("192.168.1.1:8080") == "192.168.1.1"
        assert extract_host("scanme.nmap.org") == "scanme.nmap.org"

    @pytest.mark.asyncio
    async def test_get_version(self):
        adapter = NmapAdapter()
        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/nmap"):
            with patch.object(adapter, "execute_command", return_value=(0, "Nmap version 7.94 ( https://nmap.org )\nPlatform: x86_64", "")):
                ver = await adapter.get_version()
                assert ver == "Nmap 7.94"

    @pytest.mark.asyncio
    async def test_run_parsing_and_findings(self):
        adapter = NmapAdapter()
        target = Target(name="Test Target", type=TargetType.DOMAIN, value="192.168.1.50")
        config = ScanConfig(port_list=[21, 80, 3306, 6379, 8080])

        logs = []
        findings = []

        async def mock_log(lvl, msg):
            logs.append((lvl, msg))

        async def mock_finding(f):
            findings.append(f)

        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/nmap"):
            with patch.object(adapter, "execute_command", return_value=(0, NMAP_SAMPLE_XML, "")):
                res = await adapter.run(target, config, mock_log, mock_finding)

        assert len(res) == 4  # Port 80 was closed, so 4 open ports
        assert len(findings) == 4

        check_ids = [f.check_id for f in res]
        assert "NET-PORT-003" in check_ids  # FTP 21
        assert "NET-PORT-001" in check_ids  # MySQL 3306
        assert "NET-PORT-002" in check_ids  # Redis 6379
        assert "NET-SVC-001" in check_ids   # Tomcat 8080

        ftp_finding = next(f for f in res if f.check_id == "NET-PORT-003")
        assert ftp_finding.source_tool == "nmap"
        assert ftp_finding.severity == Severity.HIGH
        assert ftp_finding.cvss_score == 7.5
        assert "192.168.1.50:21" in ftp_finding.evidence.location

        tomcat_finding = next(f for f in res if f.check_id == "NET-SVC-001")
        assert "Apache Tomcat" in tomcat_finding.evidence.observed_value
        assert "http-title" in tomcat_finding.evidence.raw_response_snippet

    @pytest.mark.asyncio
    async def test_run_missing_binary(self):
        adapter = NmapAdapter()
        target = Target(name="Test Target", type=TargetType.DOMAIN, value="example.com")
        config = ScanConfig()

        logs = []
        async def mock_log(lvl, msg): logs.append((lvl, msg))
        async def mock_finding(f): pass

        with patch.object(adapter, "resolve_binary_path", return_value=None):
            res = await adapter.run(target, config, mock_log, mock_finding)
            assert res == []
            assert any("not found" in l[1] for l in logs)

    @pytest.mark.asyncio
    async def test_run_invalid_xml(self):
        adapter = NmapAdapter()
        target = Target(name="Test Target", type=TargetType.DOMAIN, value="example.com")
        config = ScanConfig()

        logs = []
        async def mock_log(lvl, msg): logs.append((lvl, msg))
        async def mock_finding(f): pass

        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/nmap"):
            with patch.object(adapter, "execute_command", return_value=(0, "MALFORMED XML <><>", "")):
                res = await adapter.run(target, config, mock_log, mock_finding)
                assert res == []
                assert any("Failed to parse" in l[1] for l in logs)


# ============================================================================
# 3. NucleiAdapter Tests
# ============================================================================

NUCLEI_SAMPLE_JSONL = """
{"template-id":"cve-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical","classification":{"cwe-id":["CWE-502"]},"description":"Apache Log4j2 JNDI RCE vulnerability"},"matched-at":"https://target.example.com/login","curl-command":"curl -X POST https://target.example.com/login -H 'X-Api-Version: ${jndi:ldap://test}'"}
{"template-id":"sql-injection-error-based","info":{"name":"SQL Injection Error Based","severity":"high","classification":{"cwe-id":["CWE-89"]}},"matched-at":"https://target.example.com/items?id=1'"}
{"template-id":"cors-misconfig","info":{"name":"CORS Arbitrary Origin","severity":"medium","classification":{"cwe-id":["CWE-942"]}},"matched-at":"https://target.example.com/api"}
{"template-id":"env-file-exposure","info":{"name":"Environment Variable File Exposure","severity":"critical","classification":{"cwe-id":["CWE-552"]}},"matched-at":"https://target.example.com/.env"}
"""

class TestNucleiAdapter:
    def test_normalize_target_url(self):
        assert normalize_target_url("http://example.com") == "http://example.com"
        assert normalize_target_url("https://example.com") == "https://example.com"
        assert normalize_target_url("example.com") == "https://example.com"

    @pytest.mark.asyncio
    async def test_get_version(self):
        adapter = NucleiAdapter()
        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/nuclei"):
            with patch.object(adapter, "execute_command", return_value=(0, "[INF] Current Version: v3.2.0", "")):
                ver = await adapter.get_version()
                assert ver == "nuclei v3.2.0"

    @pytest.mark.asyncio
    async def test_run_parsing_and_findings(self):
        adapter = NucleiAdapter()
        target = Target(name="Web Target", type=TargetType.URL, value="https://target.example.com")
        config = ScanConfig()

        findings = []
        async def mock_log(lvl, msg): pass
        async def mock_finding(f): findings.append(f)

        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/nuclei"):
            with patch.object(adapter, "execute_command", return_value=(0, NUCLEI_SAMPLE_JSONL.strip(), "")):
                res = await adapter.run(target, config, mock_log, mock_finding)

        assert len(res) == 4
        assert len(findings) == 4

        sqli = next(f for f in res if f.check_id == "DAST-INJ-001")
        assert sqli.severity == Severity.HIGH
        assert sqli.cvss_score == 7.5
        assert sqli.source_tool == "nuclei"
        assert sqli.cwe_id == "CWE-89"

        log4j = next(f for f in res if "cve-2021-44228" in f.title)
        assert log4j.severity == Severity.CRITICAL
        assert log4j.cvss_score == 9.8
        assert log4j.reproduction_curl is not None
        assert "jndi:ldap" in log4j.reproduction_curl

        env_exp = next(f for f in res if "env-file-exposure" in f.title)
        assert env_exp.severity == Severity.CRITICAL
        assert "https://target.example.com/.env" in env_exp.evidence.location


# ============================================================================
# 4. SemgrepAdapter Tests
# ============================================================================

SEMGREP_SAMPLE_JSON = {
    "results": [
        {
            "check_id": "python.lang.security.injection.sql.formatted-sql-query",
            "path": "backend/app/db.py",
            "start": {"line": 42, "col": 5},
            "extra": {
                "message": "User input directly formatted into raw SQL query execution.",
                "severity": "ERROR",
                "lines": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
                "metadata": {"cwe": ["CWE-89: SQL Injection"]},
            },
        },
        {
            "check_id": "python.lang.security.audit.dangerous-subprocess-use",
            "path": "backend/app/runner.py",
            "start": {"line": 15, "col": 1},
            "extra": {
                "message": "subprocess called with shell=True and dynamic arguments.",
                "severity": "ERROR",
                "lines": "subprocess.Popen(cmd, shell=True)",
                "metadata": {"cwe": ["CWE-78: OS Command Injection"]},
            },
        },
        {
            "check_id": "generic.secrets.security.hardcoded-aws-secret-key",
            "path": "config/settings.py",
            "start": {"line": 8, "col": 10},
            "extra": {
                "message": "Hardcoded AWS secret key detected.",
                "severity": "WARNING",
                "lines": "AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
                "metadata": {"cwe": ["CWE-798: Hard-coded Credentials"]},
            },
        },
        {
            "check_id": "python.cryptography.security.insecure-hash-md5",
            "path": "backend/app/auth.py",
            "start": {"line": 88, "col": 4},
            "extra": {
                "message": "Insecure MD5 hashing used.",
                "severity": "WARNING",
                "lines": "hashlib.md5(password.encode()).hexdigest()",
                "metadata": {"cwe": ["CWE-327: Use of a Broken or Risky Cryptographic Algorithm"]},
            },
        },
    ]
}

class TestSemgrepAdapter:
    @pytest.mark.asyncio
    async def test_get_version(self):
        adapter = SemgrepAdapter()
        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/semgrep"):
            with patch.object(adapter, "execute_command", return_value=(0, "1.60.0\n", "")):
                ver = await adapter.get_version()
                assert ver == "semgrep 1.60.0"

    @pytest.mark.asyncio
    async def test_run_parsing_and_findings(self):
        adapter = SemgrepAdapter()
        target = Target(name="Code Repo", type=TargetType.LOCAL_PATH, value="./src")
        config = ScanConfig()

        findings = []
        async def mock_log(lvl, msg): pass
        async def mock_finding(f): findings.append(f)

        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/semgrep"):
            with patch.object(adapter, "execute_command", return_value=(0, json.dumps(SEMGREP_SAMPLE_JSON), "")):
                res = await adapter.run(target, config, mock_log, mock_finding)

        assert len(res) == 4
        assert len(findings) == 4

        sqli = next(f for f in res if f.check_id == "SAST-TAINT-001")
        assert sqli.source_tool == "semgrep"
        assert sqli.severity == Severity.CRITICAL
        assert sqli.cvss_score == 9.8
        assert sqli.evidence.line_number == 42
        assert "backend/app/db.py:42" in sqli.evidence.location

        cmd_inj = next(f for f in res if f.check_id == "SAST-TAINT-002")
        assert cmd_inj.severity == Severity.CRITICAL
        assert cmd_inj.cwe_id == "CWE-78"

        secret = next(f for f in res if f.check_id == "SAST-SEC-001")
        assert secret.severity == Severity.HIGH
        assert secret.cwe_id == "CWE-798"

        crypto = next(f for f in res if f.check_id == "SAST-CRY-001")
        assert crypto.severity == Severity.MEDIUM
        assert crypto.cwe_id == "CWE-327"


# ============================================================================
# 5. TrivyAdapter Tests
# ============================================================================

TRIVY_SAMPLE_JSON = {
    "Results": [
        {
            "Target": "requirements.txt",
            "Class": "lang-pkgs",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-32681",
                    "PkgName": "requests",
                    "InstalledVersion": "2.28.0",
                    "FixedVersion": "2.31.0",
                    "Severity": "HIGH",
                    "Title": "Unintended leak of Proxy-Authorization header in requests",
                    "Description": "Requests forwards Proxy-Authorization header to destination.",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-32681",
                    "CweIDs": ["CWE-200"],
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                }
            ],
        },
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Image user should not be 'root'",
                    "Severity": "HIGH",
                    "Description": "Running containers as root poses privilege escalation risks.",
                    "Resolution": "Specify USER nonroot in Dockerfile.",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
                }
            ],
        },
    ]
}

class TestTrivyAdapter:
    @pytest.mark.asyncio
    async def test_get_version(self):
        adapter = TrivyAdapter()
        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/trivy"):
            with patch.object(adapter, "execute_command", return_value=(0, "Version: 0.50.0\n", "")):
                ver = await adapter.get_version()
                assert ver == "trivy 0.50.0"

    @pytest.mark.asyncio
    async def test_run_parsing_and_findings(self):
        adapter = TrivyAdapter()
        target = Target(name="Project Files", type=TargetType.LOCAL_PATH, value=".")
        config = ScanConfig()

        findings = []
        async def mock_log(lvl, msg): pass
        async def mock_finding(f): findings.append(f)

        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/trivy"):
            with patch.object(adapter, "execute_command", return_value=(0, json.dumps(TRIVY_SAMPLE_JSON), "")):
                res = await adapter.run(target, config, mock_log, mock_finding)

        assert len(res) == 2
        assert len(findings) == 2

        sca = next(f for f in res if f.check_id == "SAST-DEP-001")
        assert sca.source_tool == "trivy"
        assert sca.severity == Severity.HIGH
        assert sca.cvss_score == 7.5
        assert "requests@2.28.0" in sca.evidence.location
        assert "2.31.0" in sca.remediation

        dock = next(f for f in res if f.check_id == "IAC-DOCK-001")
        assert dock.source_tool == "trivy"
        assert dock.engine == "infra_iac"
        assert dock.severity == Severity.HIGH
        assert "root" in dock.title.lower()


# ============================================================================
# 6. SSLyze Adapter Tests
# ============================================================================

class TestSslyzeAdapter:
    def test_tool_name(self):
        adapter = SslyzeAdapter()
        assert adapter.tool_name == "sslyze"

    @pytest.mark.asyncio
    async def test_get_version(self):
        adapter = SslyzeAdapter()
        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/sslyze"):
            with patch.object(adapter, "execute_command", return_value=(0, "SSLyze v5.2.0\n", "")):
                ver = await adapter.get_version()
                assert "5.2.0" in ver

    @pytest.mark.asyncio
    async def test_run_sslyze_json_findings(self):
        adapter = SslyzeAdapter()
        sample_json = {
            "server_scan_results": [
                {
                    "scan_result": {
                        "ssl_2_0_cipher_suites": {"result": {"is_supported": True}},
                        "ssl_3_0_cipher_suites": {"result": {"is_supported": False}},
                        "tls_1_0_cipher_suites": {"result": {"is_supported": True}},
                        "tls_1_1_cipher_suites": {"result": {"is_supported": False}},
                        "certificate_info": {
                            "result": {
                                "certificate_deployments": [
                                    {
                                        "received_certificate_chain": [
                                            {
                                                "subject": {"rfc4514_string": "CN=example.com"},
                                                "signature_hash_algorithm": {"name": "sha1"},
                                                "not_valid_after": "2020-01-01T00:00:00",
                                            }
                                        ]
                                    }
                                ]
                            }
                        },
                        "heartbleed": {"result": {"is_vulnerable_to_heartbleed": True}},
                    }
                }
            ]
        }

        mock_log = AsyncMock()
        mock_finding = AsyncMock()
        target = Target(name="Target", type=TargetType.URL, value="https://example.com")
        config = ScanConfig()

        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/sslyze"):
            with patch.object(adapter, "execute_command", return_value=(0, json.dumps(sample_json), "")):
                findings = await adapter.run(target, config, mock_log, mock_finding)

        assert len(findings) >= 3
        check_ids = {f.check_id for f in findings}
        assert "NET-TLS-001" in check_ids  # Deprecated TLS 1.0 / SSL 2.0
        assert "NET-TLS-003" in check_ids  # Expired / weak cert
        assert "NET-TLS-006" in check_ids  # Heartbleed


# ============================================================================
# 7. FFuF Adapter Tests
# ============================================================================

class TestFfufAdapter:
    def test_tool_name(self):
        adapter = FfufAdapter()
        assert adapter.tool_name == "ffuf"

    @pytest.mark.asyncio
    async def test_get_version(self):
        adapter = FfufAdapter()
        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/ffuf"):
            with patch.object(adapter, "execute_command", return_value=(0, "ffuf version: 2.1.0-dev", "")):
                ver = await adapter.get_version()
                assert "2.1.0" in ver

    @pytest.mark.asyncio
    async def test_run_ffuf_json_findings(self):
        adapter = FfufAdapter()
        sample_json = {
            "results": [
                {
                    "input": {"FUZZ": ".env"},
                    "url": "https://example.com/.env",
                    "status": 200,
                    "length": 512,
                    "words": 40,
                    "lines": 12,
                },
                {
                    "input": {"FUZZ": "admin/backup.sql"},
                    "url": "https://example.com/admin/backup.sql",
                    "status": 200,
                    "length": 20480,
                    "words": 500,
                    "lines": 120,
                },
            ]
        }

        mock_log = AsyncMock()
        mock_finding = AsyncMock()
        mock_endpoint = AsyncMock()
        target = Target(name="Target", type=TargetType.URL, value="https://example.com")
        config = ScanConfig()

        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/ffuf"):
            with patch.object(adapter, "execute_command", return_value=(0, json.dumps(sample_json), "")):
                findings = await adapter.run(target, config, mock_log, mock_finding, emit_endpoint=mock_endpoint)

        assert len(findings) == 2
        assert mock_endpoint.call_count == 2
        env_f = next(f for f in findings if ".env" in f.evidence.location)
        assert env_f.severity == Severity.CRITICAL
        assert env_f.check_id == "DAST-EXP-001"
        assert env_f.source_tool == "ffuf"


# ============================================================================
# 8. Nikto Adapter Tests
# ============================================================================

class TestNiktoAdapter:
    def test_tool_name(self):
        adapter = NiktoAdapter()
        assert adapter.tool_name == "nikto"

    @pytest.mark.asyncio
    async def test_get_version(self):
        adapter = NiktoAdapter()
        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/nikto"):
            with patch.object(adapter, "execute_command", return_value=(0, "Nikto 2.5.0", "")):
                ver = await adapter.get_version()
                assert "2.5.0" in ver

    @pytest.mark.asyncio
    async def test_run_nikto_json_findings(self):
        adapter = NiktoAdapter()
        sample_json = {
            "vulnerabilities": [
                {
                    "id": "999996",
                    "OSVDB": "0",
                    "url": "/cgi-bin/test.cgi",
                    "msg": "The anti-clickjacking X-Frame-Options header is not present.",
                },
                {
                    "id": "000001",
                    "OSVDB": "3092",
                    "url": "/phpmyadmin/",
                    "msg": "Found phpmyadmin directory which may expose database credentials.",
                },
            ]
        }

        mock_log = AsyncMock()
        mock_finding = AsyncMock()
        target = Target(name="Target", type=TargetType.URL, value="https://example.com")
        config = ScanConfig()

        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/nikto"):
            with patch.object(adapter, "execute_command", return_value=(0, json.dumps(sample_json), "")):
                findings = await adapter.run(target, config, mock_log, mock_finding)

        assert len(findings) == 2
        hdr_f = next(f for f in findings if "X-Frame-Options" in f.title)
        assert hdr_f.check_id == "DAST-HDR-002"
        assert hdr_f.source_tool == "nikto"


# ============================================================================
# 9. Gitleaks Adapter Tests
# ============================================================================

class TestGitleaksAdapter:
    def test_tool_name(self):
        adapter = GitleaksAdapter()
        assert adapter.tool_name == "gitleaks"

    @pytest.mark.asyncio
    async def test_get_version(self):
        adapter = GitleaksAdapter()
        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/gitleaks"):
            with patch.object(adapter, "execute_command", return_value=(0, "8.18.2\n", "")):
                ver = await adapter.get_version()
                assert "8.18.2" in ver

    @pytest.mark.asyncio
    async def test_run_gitleaks_json_findings(self):
        adapter = GitleaksAdapter()
        sample_json = [
            {
                "Description": "AWS Access Key",
                "StartLine": 14,
                "EndLine": 14,
                "StartColumn": 1,
                "EndColumn": 21,
                "Match": "AKIAIOSFODNN7EXAMPLE",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "File": "config/aws.py",
                "Commit": "abc1234def5678",
                "Author": "dev@example.com",
                "Date": "2026-01-01T00:00:00Z",
                "Message": "Add aws config",
                "RuleID": "aws-access-token",
                "Fingerprint": "aws-key-fp",
            }
        ]

        mock_log = AsyncMock()
        mock_finding = AsyncMock()
        target = Target(name="Target", type=TargetType.LOCAL_PATH, value=".")
        config = ScanConfig()

        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/gitleaks"):
            with patch.object(adapter, "execute_command", return_value=(1, json.dumps(sample_json), "")):
                findings = await adapter.run(target, config, mock_log, mock_finding)

        assert len(findings) == 1
        aws_f = findings[0]
        assert aws_f.check_id == "SAST-SEC-001"
        assert aws_f.severity == Severity.CRITICAL
        assert aws_f.source_tool == "gitleaks"
        assert "AKIA" in aws_f.evidence.observed_value
        # Ensure secret masking
        assert aws_f.evidence.observed_value != "AKIAIOSFODNN7EXAMPLE"


# ============================================================================
# 10. Bandit Adapter Tests
# ============================================================================

class TestBanditAdapter:
    def test_tool_name(self):
        adapter = BanditAdapter()
        assert adapter.tool_name == "bandit"

    @pytest.mark.asyncio
    async def test_get_version(self):
        adapter = BanditAdapter()
        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/bandit"):
            with patch.object(adapter, "execute_command", return_value=(0, "bandit 1.7.8\n", "")):
                ver = await adapter.get_version()
                assert "1.7.8" in ver

    @pytest.mark.asyncio
    async def test_run_bandit_json_findings(self):
        adapter = BanditAdapter()
        sample_json = {
            "results": [
                {
                    "test_id": "B303",
                    "test_name": "blacklist_md5",
                    "issue_severity": "MEDIUM",
                    "issue_confidence": "HIGH",
                    "issue_text": "Use of insecure MD5 hash function.",
                    "line_number": 42,
                    "line_range": [42],
                    "filename": "app/auth.py",
                    "code": "hashlib.md5(pwd.encode()).hexdigest()\n",
                    "more_info": "https://bandit.readthedocs.io/en/1.7.8/plugins/b303_blacklist.html",
                },
                {
                    "test_id": "B602",
                    "test_name": "subprocess_popen_with_shell_equals_true",
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "issue_text": "subprocess call with shell=True identified, security issue.",
                    "line_number": 88,
                    "line_range": [88],
                    "filename": "app/utils.py",
                    "code": "subprocess.Popen(cmd, shell=True)\n",
                    "more_info": "https://bandit.readthedocs.io/en/1.7.8/plugins/b602_subprocess_popen_with_shell_equals_true.html",
                },
            ]
        }

        mock_log = AsyncMock()
        mock_finding = AsyncMock()
        target = Target(name="Target", type=TargetType.LOCAL_PATH, value=".")
        config = ScanConfig()

        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/bandit"):
            with patch.object(adapter, "execute_command", return_value=(1, json.dumps(sample_json), "")):
                findings = await adapter.run(target, config, mock_log, mock_finding)

        assert len(findings) == 2
        md5_f = next(f for f in findings if f.check_id == "SAST-CRY-001")
        assert md5_f.severity == Severity.MEDIUM
        assert md5_f.source_tool == "bandit"

        sh_f = next(f for f in findings if f.check_id == "SAST-INJ-002")
        assert sh_f.severity == Severity.HIGH
        assert sh_f.source_tool == "bandit"


# ============================================================================
# 11. Checkov Adapter Tests
# ============================================================================

class TestCheckovAdapter:
    def test_tool_name(self):
        adapter = CheckovAdapter()
        assert adapter.tool_name == "checkov"

    @pytest.mark.asyncio
    async def test_get_version(self):
        adapter = CheckovAdapter()
        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/checkov"):
            with patch.object(adapter, "execute_command", return_value=(0, "3.2.50\n", "")):
                ver = await adapter.get_version()
                assert "3.2.50" in ver

    @pytest.mark.asyncio
    async def test_run_checkov_json_findings(self):
        adapter = CheckovAdapter()
        sample_json = {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_DOCKER_1",
                        "bc_check_id": None,
                        "check_name": "Ensure container does not run as root",
                        "check_result": {"result": "FAILED"},
                        "code_block": [["1", "FROM python:3.11\n"]],
                        "file_path": "/Dockerfile",
                        "file_line_range": [1, 2],
                        "resource": "Dockerfile",
                        "guideline": "https://docs.bridgecrew.io/docs/ensure-container-does-not-run-as-root",
                        "severity": "HIGH",
                    },
                    {
                        "check_id": "CKV_AWS_20",
                        "bc_check_id": None,
                        "check_name": "Ensure S3 bucket has an ACL defined granting public READ access",
                        "check_result": {"result": "FAILED"},
                        "code_block": [["10", "resource \"aws_s3_bucket\" \"data\" {\n"], ["11", "  acl = \"public-read\"\n"]],
                        "file_path": "/main.tf",
                        "file_line_range": [10, 15],
                        "resource": "aws_s3_bucket.data",
                        "guideline": "https://docs.bridgecrew.io/docs/s3_1-acl-read-permissions-everyone",
                        "severity": "HIGH",
                    }
                ]
            }
        }

        mock_log = AsyncMock()
        mock_finding = AsyncMock()
        target = Target(name="Target", type=TargetType.LOCAL_PATH, value=".")
        config = ScanConfig()

        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/checkov"):
            with patch.object(adapter, "execute_command", return_value=(1, json.dumps(sample_json), "")):
                findings = await adapter.run(target, config, mock_log, mock_finding)

        assert len(findings) == 2
        dock_f = next(f for f in findings if f.check_id == "IAC-DOCK-001")
        assert dock_f.severity == Severity.HIGH
        assert dock_f.source_tool == "checkov"

        tf_f = next(f for f in findings if f.check_id == "IAC-TF-001")
        assert tf_f.severity == Severity.HIGH
        assert tf_f.source_tool == "checkov"


# ============================================================================
# 12. Adapter Registry & Capabilities Discovery Tests (10 Adapters Suite)
# ============================================================================

class TestCapabilitiesAndRegistry:
    def test_adapter_registry(self):
        registry = get_adapter_registry()
        expected_tools = {
            "nmap", "sslyze", "subfinder", "httpx",
            "nuclei", "ffuf", "nikto", "katana", "schemathesis",
            "semgrep", "bandit", "gitleaks", "trufflehog", "retire",
            "trivy", "syft", "grype", "osv-scanner",
            "checkov", "prowler", "kube-bench", "dockle",
        }
        assert set(registry.keys()) == expected_tools
        assert len(registry) == 22

    @pytest.mark.asyncio
    async def test_discover_system_capabilities_fallback(self):
        # All tools missing -> NATIVE_FALLBACK for all 22 tools
        with patch.object(BaseToolAdapter, "resolve_binary_path", return_value=None):
            with patch.object(BaseToolAdapter, "is_available", return_value=False):
                caps = await discover_system_capabilities()
                assert len(caps.tools) == 22
                assert caps.native_engines_ready is True
                for t in caps.tools:
                    assert t.available is False
                    if t.name == "nikto":
                        assert t.execution_mode in (ToolExecutionMode.DISABLED, ToolExecutionMode.NATIVE_FALLBACK)
                    else:
                        assert t.execution_mode == ToolExecutionMode.NATIVE_FALLBACK

    @pytest.mark.asyncio
    async def test_discover_system_capabilities_active(self):
        # Mock active tools
        mock_nmap = MagicMock(spec=NmapAdapter)
        mock_nmap.tool_name = "nmap"
        mock_nmap.resolve_binary_path.return_value = "/usr/bin/nmap"
        mock_nmap.is_available = AsyncMock(return_value=True)
        mock_nmap.get_version = AsyncMock(return_value="Nmap 7.94")

        mock_semgrep = MagicMock(spec=SemgrepAdapter)
        mock_semgrep.tool_name = "semgrep"
        mock_semgrep.resolve_binary_path.return_value = "/usr/bin/semgrep"
        mock_semgrep.is_available = AsyncMock(return_value=True)
        mock_semgrep.get_version = AsyncMock(return_value="semgrep 1.60.0")

        all_tools = [
            "nmap", "sslyze", "subfinder", "httpx",
            "nuclei", "ffuf", "nikto", "katana", "schemathesis",
            "semgrep", "bandit", "gitleaks", "trufflehog", "retire",
            "trivy", "syft", "grype", "osv-scanner",
            "checkov", "prowler", "kube-bench", "dockle",
        ]
        mock_registry = {
            tool: MagicMock(
                tool_name=tool,
                resolve_binary_path=MagicMock(return_value=None),
                is_available=AsyncMock(return_value=False),
                get_version=AsyncMock(return_value=None),
            )
            for tool in all_tools if tool not in ("nmap", "semgrep")
        }
        mock_registry["nmap"] = mock_nmap
        mock_registry["semgrep"] = mock_semgrep

        with patch("app.adapters.get_adapter_registry", return_value=mock_registry):
            caps = await discover_system_capabilities()
            tool_map = {t.name: t for t in caps.tools}

            assert tool_map["nmap"].available is True
            assert tool_map["nmap"].execution_mode == ToolExecutionMode.ADAPTER_ACTIVE
            assert tool_map["nmap"].version == "Nmap 7.94"

            assert tool_map["semgrep"].available is True
            assert tool_map["semgrep"].execution_mode == ToolExecutionMode.ADAPTER_ACTIVE
            assert tool_map["semgrep"].version == "semgrep 1.60.0"

            assert tool_map["nuclei"].available is False
            assert tool_map["nuclei"].execution_mode == ToolExecutionMode.NATIVE_FALLBACK

            assert tool_map["trivy"].available is False
            assert tool_map["trivy"].execution_mode == ToolExecutionMode.NATIVE_FALLBACK

    @pytest.mark.asyncio
    async def test_discover_system_capabilities_disabled(self):
        # Explicitly disable nmap and nuclei via config
        config = ToolAdapterConfig(
            enable_nmap=False,
            enable_nuclei=False,
            enable_semgrep=True,
            enable_trivy=True,
        )

        mock_nmap = MagicMock(spec=NmapAdapter)
        mock_nmap.tool_name = "nmap"
        mock_nmap.resolve_binary_path.return_value = "/usr/bin/nmap"
        mock_nmap.is_available = AsyncMock(return_value=True)
        mock_nmap.get_version = AsyncMock(return_value="Nmap 7.94")

        mock_nuclei = MagicMock(spec=NucleiAdapter)
        mock_nuclei.tool_name = "nuclei"
        mock_nuclei.resolve_binary_path.return_value = "/usr/bin/nuclei"
        mock_nuclei.is_available = AsyncMock(return_value=True)
        mock_nuclei.get_version = AsyncMock(return_value="nuclei v3.2.0")

        mock_semgrep = MagicMock(spec=SemgrepAdapter)
        mock_semgrep.tool_name = "semgrep"
        mock_semgrep.resolve_binary_path.return_value = "/usr/bin/semgrep"
        mock_semgrep.is_available = AsyncMock(return_value=True)
        mock_semgrep.get_version = AsyncMock(return_value="semgrep 1.60.0")

        mock_registry = {
            tool: MagicMock(
                tool_name=tool,
                resolve_binary_path=MagicMock(return_value=None),
                is_available=AsyncMock(return_value=False),
                get_version=AsyncMock(return_value=None),
            )
            for tool in ["sslyze", "ffuf", "nikto", "gitleaks", "bandit", "trivy", "checkov"]
        }
        mock_registry["nmap"] = mock_nmap
        mock_registry["nuclei"] = mock_nuclei
        mock_registry["semgrep"] = mock_semgrep

        with patch("app.adapters.get_adapter_registry", return_value=mock_registry):
            caps = await discover_system_capabilities(config=config)
            tool_map = {t.name: t for t in caps.tools}

            assert tool_map["nmap"].execution_mode == ToolExecutionMode.DISABLED
            assert tool_map["nmap"].available is False

            assert tool_map["nuclei"].execution_mode == ToolExecutionMode.DISABLED
            assert tool_map["nuclei"].available is False

            assert tool_map["semgrep"].execution_mode == ToolExecutionMode.ADAPTER_ACTIVE
            assert tool_map["semgrep"].available is True


# ============================================================================
# 12. SubfinderAdapter Tests
# ============================================================================

class TestSubfinderAdapter:
    @pytest.mark.asyncio
    async def test_subfinder_run_success(self):
        from app.adapters.subfinder_adapter import SubfinderAdapter
        adapter = SubfinderAdapter()
        target = Target(name="Domain", type=TargetType.DOMAIN, value="example.com")
        config = ScanConfig()
        emitted_logs = []
        emitted_findings = []
        discovered_subs = []

        async def emit_log(lvl, msg):
            emitted_logs.append((lvl, msg))

        async def emit_finding(f):
            emitted_findings.append(f)

        async def emit_subdomain(sd):
            discovered_subs.append(sd)

        mock_json_lines = (
            '{"host":"api.example.com","ip":"93.184.216.34","sources":["crtsh"]}\n'
            '{"host":"admin.example.com","ip":"93.184.216.35","sources":["virustotal"]}\n'
        )

        with patch.object(adapter, "resolve_binary_path", return_value="/bin/subfinder"), \
             patch.object(adapter, "safe_execute_subprocess", new=AsyncMock(return_value=(0, mock_json_lines, ""))):
            findings = await adapter.run(target, config, emit_log, emit_finding, emit_subdomain=emit_subdomain)
            assert len(findings) == 1
            assert len(discovered_subs) == 2
            assert discovered_subs[0].domain == "api.example.com"
            assert findings[0].check_id == "EASM-SUB-001"


# ============================================================================
# 13. HttpxAdapter Tests
# ============================================================================

class TestHttpxAdapter:
    @pytest.mark.asyncio
    async def test_httpx_run_success(self):
        from app.adapters.httpx_adapter import HttpxAdapter
        adapter = HttpxAdapter()
        target = Target(name="Web", type=TargetType.URL, value="https://example.com")
        config = ScanConfig()
        emitted_logs = []
        emitted_findings = []
        endpoints = []

        async def emit_log(lvl, msg):
            emitted_logs.append((lvl, msg))

        async def emit_finding(f):
            emitted_findings.append(f)

        async def emit_endpoint(ep):
            endpoints.append(ep)

        mock_json_lines = (
            '{"url":"https://example.com","status_code":200,"title":"Example","webserver":"nginx/1.24.0","tech":["Nginx","Cloudflare"]}\n'
        )

        with patch.object(adapter, "resolve_binary_path", return_value="/bin/httpx"), \
             patch.object(adapter, "safe_execute_subprocess", new=AsyncMock(return_value=(0, mock_json_lines, ""))):
            findings = await adapter.run(target, config, emit_log, emit_finding, emit_endpoint=emit_endpoint)
            assert len(findings) == 1
            assert len(endpoints) == 1
            assert endpoints[0].url == "https://example.com"
            assert findings[0].check_id == "EASM-EXPOSURE-001"


# ============================================================================
# 14. KatanaAdapter Tests
# ============================================================================

class TestKatanaAdapter:
    @pytest.mark.asyncio
    async def test_katana_run_success(self):
        from app.adapters.katana_adapter import KatanaAdapter
        adapter = KatanaAdapter()
        target = Target(name="SPA", type=TargetType.URL, value="https://spa.example.com")
        config = ScanConfig()
        emitted_logs = []
        emitted_findings = []
        endpoints = []

        async def emit_log(lvl, msg):
            emitted_logs.append((lvl, msg))

        async def emit_finding(f):
            emitted_findings.append(f)

        async def emit_endpoint(ep):
            endpoints.append(ep)

        mock_json_lines = (
            '{"request":{"endpoint":"https://spa.example.com/api/v1/users","method":"GET"},"response":{"status_code":200}}\n'
        )

        with patch.object(adapter, "resolve_binary_path", return_value="/bin/katana"), \
             patch.object(adapter, "safe_execute_subprocess", new=AsyncMock(return_value=(0, mock_json_lines, ""))):
            findings = await adapter.run(target, config, emit_log, emit_finding, emit_endpoint=emit_endpoint)
            assert len(findings) == 1
            assert len(endpoints) == 1
            assert endpoints[0].url == "https://spa.example.com/api/v1/users"
            assert findings[0].check_id == "DAST-SPA-001"


# ============================================================================
# 15. SchemathesisAdapter Tests
# ============================================================================

class TestSchemathesisAdapter:
    @pytest.mark.asyncio
    async def test_schemathesis_run_success(self):
        from app.adapters.schemathesis_adapter import SchemathesisAdapter
        adapter = SchemathesisAdapter()
        target = Target(name="API", type=TargetType.URL, value="https://api.example.com/openapi.json")
        config = ScanConfig()
        emitted_logs = []
        emitted_findings = []

        async def emit_log(lvl, msg):
            emitted_logs.append((lvl, msg))

        async def emit_finding(f):
            emitted_findings.append(f)

        mock_report = {
            "errors": [
                {
                    "title": "500 Internal Server Error returned for POST /users",
                    "endpoint": "https://api.example.com/users",
                    "method": "POST",
                }
            ]
        }

        with patch.object(adapter, "resolve_binary_path", return_value="/bin/schemathesis"), \
             patch.object(adapter, "safe_execute_subprocess", new=AsyncMock(return_value=(0, json.dumps(mock_report), ""))):
            findings = await adapter.run(target, config, emit_log, emit_finding)
            assert len(findings) == 1
            assert findings[0].check_id == "API-SCHEMA-001"
            assert findings[0].severity == Severity.HIGH


# ============================================================================
# 16. TruffleHogAdapter Tests
# ============================================================================

class TestTruffleHogAdapter:
    @pytest.mark.asyncio
    async def test_trufflehog_run_success(self, tmp_path):
        from app.adapters.trufflehog_adapter import TruffleHogAdapter
        adapter = TruffleHogAdapter()
        target = Target(name="Repo", type=TargetType.LOCAL_PATH, value=str(tmp_path))
        config = ScanConfig()
        emitted_logs = []
        emitted_findings = []

        async def emit_log(lvl, msg):
            emitted_logs.append((lvl, msg))

        async def emit_finding(f):
            emitted_findings.append(f)

        mock_json_lines = (
            '{"DetectorName":"AWS","Verified":true,"Raw":"AKIAIOSFODNN7EXAMPLE","SourceMetadata":{"Data":{"Filesystem":{"file":"config.py"}}},"VerificationDetails":{"Endpoint":"https://sts.amazonaws.com"}}\n'
        )

        with patch.object(adapter, "resolve_binary_path", return_value="/bin/trufflehog"), \
             patch.object(adapter, "safe_execute_subprocess", new=AsyncMock(return_value=(0, mock_json_lines, ""))):
            findings = await adapter.run(target, config, emit_log, emit_finding)
            assert len(findings) == 1
            assert findings[0].check_id == "SEC-VERIFIED-001"
            assert findings[0].severity == Severity.CRITICAL
            assert findings[0].verified_secret is not None
            assert findings[0].verified_secret.is_live is True


# ============================================================================
# 17. RetireJSAdapter Tests
# ============================================================================

class TestRetireJSAdapter:
    @pytest.mark.asyncio
    async def test_retirejs_run_success(self, tmp_path):
        from app.adapters.retirejs_adapter import RetireJSAdapter
        adapter = RetireJSAdapter()
        target = Target(name="Repo", type=TargetType.LOCAL_PATH, value=str(tmp_path))
        config = ScanConfig()
        emitted_logs = []
        emitted_findings = []

        async def emit_log(lvl, msg):
            emitted_logs.append((lvl, msg))

        async def emit_finding(f):
            emitted_findings.append(f)

        mock_report = {
            "data": [
                {
                    "file": str(tmp_path / "jquery.js"),
                    "results": [
                        {
                            "component": "jquery",
                            "version": "1.12.4",
                            "vulnerabilities": [
                                {
                                    "severity": "medium",
                                    "identifiers": {"CVE": ["CVE-2019-11358"], "summary": "Prototype Pollution in jQuery"},
                                    "info": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11358"],
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        with patch.object(adapter, "resolve_binary_path", return_value="/bin/retire"), \
             patch.object(adapter, "safe_execute_subprocess", new=AsyncMock(return_value=(0, json.dumps(mock_report), ""))):
            findings = await adapter.run(target, config, emit_log, emit_finding)
            assert len(findings) == 1
            assert findings[0].check_id == "SCA-JS-001"
            assert "CVE-2019-11358" in findings[0].title


# ============================================================================
# 18. Syft & Grype & OSV-Scanner Adapters Tests
# ============================================================================

class TestSupplyChainAdapters:
    @pytest.mark.asyncio
    async def test_syft_run_success(self, tmp_path):
        from app.adapters.syft_adapter import SyftAdapter
        adapter = SyftAdapter()
        target = Target(name="Repo", type=TargetType.LOCAL_PATH, value=str(tmp_path))
        config = ScanConfig()
        emitted_logs = []
        emitted_findings = []
        recorded_sbom = []

        async def emit_log(lvl, msg):
            emitted_logs.append((lvl, msg))

        async def emit_finding(f):
            emitted_findings.append(f)

        def record_sbom(s):
            recorded_sbom.append(s)

        mock_cyclonedx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"name": "fastapi", "version": "0.100.0", "type": "library", "purl": "pkg:pypi/fastapi@0.100.0"},
                {"name": "pydantic", "version": "2.0.0", "type": "library", "purl": "pkg:pypi/pydantic@2.0.0"},
            ],
        }

        with patch.object(adapter, "resolve_binary_path", return_value="/bin/syft"), \
             patch.object(adapter, "safe_execute_subprocess", new=AsyncMock(return_value=(0, json.dumps(mock_cyclonedx), ""))):
            findings = await adapter.run(target, config, emit_log, emit_finding, record_sbom_report=record_sbom)
            assert len(findings) == 1
            assert findings[0].check_id == "SCA-SBOM-001"
            assert len(recorded_sbom) == 1
            assert len(recorded_sbom[0].components) == 2

    @pytest.mark.asyncio
    async def test_grype_run_success(self, tmp_path):
        from app.adapters.grype_adapter import GrypeAdapter
        adapter = GrypeAdapter()
        target = Target(name="Repo", type=TargetType.LOCAL_PATH, value=str(tmp_path))
        config = ScanConfig()
        emitted_logs = []
        emitted_findings = []

        async def emit_log(lvl, msg):
            emitted_logs.append((lvl, msg))

        async def emit_finding(f):
            emitted_findings.append(f)

        mock_grype = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-9999",
                        "severity": "High",
                        "description": "Critical vulnerability in requests",
                        "fix": {"versions": ["2.31.0"]},
                    },
                    "artifact": {"name": "requests", "version": "2.28.0", "type": "python"},
                }
            ]
        }

        with patch.object(adapter, "resolve_binary_path", return_value="/bin/grype"), \
             patch.object(adapter, "safe_execute_subprocess", new=AsyncMock(return_value=(0, json.dumps(mock_grype), ""))):
            findings = await adapter.run(target, config, emit_log, emit_finding)
            assert len(findings) == 1
            assert findings[0].check_id == "SCA-SBOM-001"
            assert "CVE-2023-9999" in findings[0].title

    @pytest.mark.asyncio
    async def test_osv_scanner_run_success(self, tmp_path):
        from app.adapters.osv_scanner_adapter import OSVScannerAdapter
        adapter = OSVScannerAdapter()
        target = Target(name="Repo", type=TargetType.LOCAL_PATH, value=str(tmp_path))
        config = ScanConfig()
        emitted_logs = []
        emitted_findings = []

        async def emit_log(lvl, msg):
            emitted_logs.append((lvl, msg))

        async def emit_finding(f):
            emitted_findings.append(f)

        mock_osv = {
            "results": [
                {
                    "source": {"path": str(tmp_path / "package-lock.json")},
                    "packages": [
                        {
                            "package": {"name": "axios", "version": "0.21.1", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-cph5-m8f7-6c5x",
                                    "summary": "Server-Side Request Forgery in axios",
                                    "database_specific": {"severity": "HIGH"},
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        with patch.object(adapter, "resolve_binary_path", return_value="/bin/osv-scanner"), \
             patch.object(adapter, "safe_execute_subprocess", new=AsyncMock(return_value=(0, json.dumps(mock_osv), ""))):
            findings = await adapter.run(target, config, emit_log, emit_finding)
            assert len(findings) == 1
            assert findings[0].check_id == "SCA-OSV-001"


# ============================================================================
# 19. CIS Benchmarks (Prowler, Kube-Bench, Dockle) Adapters Tests
# ============================================================================

class TestCISBenchmarkAdapters:
    @pytest.mark.asyncio
    async def test_dockle_run_success(self):
        from app.adapters.dockle_adapter import DockleAdapter
        adapter = DockleAdapter()
        target = Target(name="Dockerfile", type=TargetType.DOCKERFILE, value="nginx:alpine")
        config = ScanConfig()
        emitted_logs = []
        emitted_findings = []
        recorded_cis = []

        async def emit_log(lvl, msg):
            emitted_logs.append((lvl, msg))

        async def emit_finding(f):
            emitted_findings.append(f)

        def record_cis(c):
            recorded_cis.append(c)

        mock_dockle = {
            "details": [
                {
                    "code": "CIS-DI-0001",
                    "title": "Create a user for the container",
                    "level": "WARN",
                    "alerts": ["Last user should not be root"],
                }
            ]
        }

        with patch.object(adapter, "resolve_binary_path", return_value="/bin/dockle"), \
             patch.object(adapter, "safe_execute_subprocess", new=AsyncMock(return_value=(0, json.dumps(mock_dockle), ""))):
            findings = await adapter.run(target, config, emit_log, emit_finding, record_cis_result=record_cis)
            assert len(findings) == 1
            assert findings[0].check_id == "DOCKER-CIS-001"
            assert len(recorded_cis) == 1

    @pytest.mark.asyncio
    async def test_kubebench_run_success(self, tmp_path):
        from app.adapters.kubebench_adapter import KubeBenchAdapter
        adapter = KubeBenchAdapter()
        target = Target(name="K8s", type=TargetType.IAC_MANIFEST, value=str(tmp_path))
        config = ScanConfig()
        emitted_logs = []
        emitted_findings = []
        recorded_cis = []

        async def emit_log(lvl, msg):
            emitted_logs.append((lvl, msg))

        async def emit_finding(f):
            emitted_findings.append(f)

        def record_cis(c):
            recorded_cis.append(c)

        mock_kb = {
            "Controls": [
                {
                    "id": "1.1",
                    "tests": [
                        {
                            "section": "1.1.1",
                            "results": [
                                {
                                    "test_number": "1.1.1",
                                    "test_desc": "Ensure that the API server pod specification file permissions are set to 644 or more restrictive",
                                    "status": "FAIL",
                                    "remediation": "chmod 644 /etc/kubernetes/manifests/kube-apiserver.yaml",
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        with patch.object(adapter, "resolve_binary_path", return_value="/bin/kube-bench"), \
             patch.object(adapter, "safe_execute_subprocess", new=AsyncMock(return_value=(0, json.dumps(mock_kb), ""))):
            findings = await adapter.run(target, config, emit_log, emit_finding, record_cis_result=record_cis)
            assert len(findings) == 1
            assert findings[0].check_id == "K8S-CIS-001"
            assert len(recorded_cis) == 1

    @pytest.mark.asyncio
    async def test_prowler_run_success(self, tmp_path):
        from app.adapters.prowler_adapter import ProwlerAdapter
        adapter = ProwlerAdapter()
        target = Target(name="Cloud", type=TargetType.LOCAL_PATH, value=str(tmp_path))
        config = ScanConfig()
        emitted_logs = []
        emitted_findings = []
        recorded_cis = []

        async def emit_log(lvl, msg):
            emitted_logs.append((lvl, msg))

        async def emit_finding(f):
            emitted_findings.append(f)

        def record_cis(c):
            recorded_cis.append(c)

        mock_prowler_lines = (
            '{"CheckID":"s3_bucket_public_access","Status":"FAIL","Severity":"critical","StatusExtended":"Bucket is publicly accessible","Region":"us-east-1","ResourceID":"my-public-bucket","Remediation":{"Recommendation":{"Text":"Block public access"}}}\n'
        )

        with patch.object(adapter, "resolve_binary_path", return_value="/bin/prowler"), \
             patch.object(adapter, "safe_execute_subprocess", new=AsyncMock(return_value=(0, mock_prowler_lines, ""))):
            findings = await adapter.run(target, config, emit_log, emit_finding, record_cis_result=record_cis)
            assert len(findings) == 1
            assert findings[0].check_id == "CLOUD-CIS-001"
            assert len(recorded_cis) == 1




