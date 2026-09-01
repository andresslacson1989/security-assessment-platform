"""Governed adapters for the extended Contract 03 tool set.

These adapters deliberately fail closed for execution until an installer-created
managed artifact record and an authoritative manifest entry exist. Version output
alone is never treated as artifact trust.
"""

from __future__ import annotations

import json
import re
import tempfile
import os
import hashlib
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional
from urllib.parse import urlparse

from app.adapters.base_adapter import BaseToolAdapter
from app.core.models import (
    Evidence,
    Finding,
    LogLevel,
    NormalizedExecutionState,
    ScanConfig,
    Severity,
    Target,
    TargetType,
    DiscoveredSubdomain,
    calculate_fingerprint,
    sanitize_sensitive_text,
)
from app.installers.tool_manifest import PINNED_TOOL_MANIFEST
from app.core.binary_resolver import resolve_tool_binary


EmitLog = Callable[[LogLevel, str], Awaitable[None]]
EmitFinding = Callable[[Finding], Awaitable[None]]


def _host(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = parsed.hostname or ""
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
        raise ValueError("Target host is invalid")
    return host.lower().rstrip(".")


def _target_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("A credential-free HTTP(S) target URL is required")
    return value


class GovernedExtendedAdapter(BaseToolAdapter):
    """Common managed-artifact and normalized-finding controls."""

    manifest_name: str
    binary_name: Optional[str] = None

    def resolve_binary_path(self, custom_path: Optional[str] = None) -> Optional[str]:
        return resolve_tool_binary(
            tool_name=self.binary_name or self.tool_name,
            custom_path=custom_path,
            local_bin_dir=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "bin")),
        )

    def verify_managed_binary(self, binary: str) -> bool:
        # The current authoritative manifest has no entries for this extended
        # set. Refuse execution rather than accepting a PATH binary or invented
        # digest. Once a real entry is installed, the inherited trust-record
        # checks are applied by the concrete adapter.
        if self.manifest_name not in PINNED_TOOL_MANIFEST:
            return False
        path = os.path.abspath(binary)
        managed_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "bin"))
        expected_name = (self.binary_name or self.tool_name).lower()
        if os.path.realpath(path) != path or os.path.dirname(path) != managed_dir:
            return False
        if os.path.basename(path).lower() not in {expected_name, f"{expected_name}.exe"}:
            return False
        try:
            with open(f"{path}.trust.json", "r", encoding="utf-8") as record_file:
                record = json.load(record_file)
            manifest = PINNED_TOOL_MANIFEST[self.manifest_name]
            expected_version = str(manifest.get("pinned_version", "")).lstrip("v")
            if record.get("tool_id") != f"TOOL-{self.manifest_name.upper().replace('-', '_')}":
                return False
            if record.get("trust_status") != "VALID" or str(record.get("tool_version", "")).lstrip("v") != expected_version:
                return False
            if record.get("executable_relative_path") != os.path.basename(path):
                return False
            if not {"ARCHIVE_INTEGRITY_VERIFIED", "EXECUTABLE_INTEGRITY_VERIFIED"}.issubset(set(record.get("claims", []))):
                return False
            with open(path, "rb") as binary_file:
                digest = hashlib.sha256(binary_file.read()).hexdigest()
            return digest == record.get("executable_sha256")
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return False

    async def _binary_or_block(
        self,
        config: ScanConfig,
        path: Optional[str],
        emit_log: EmitLog,
    ) -> Optional[str]:
        binary = self.resolve_binary_path(path)
        if not binary:
            self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.WARNING, f"{self.tool_name} binary not found; execution was not attempted.")
            return None
        if not self.verify_managed_binary(binary):
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, f"{self.tool_name} execution blocked: no authoritative managed artifact is available.")
            return None
        return binary

    def _finding(
        self,
        *,
        scan_id: str,
        organization_id: Optional[str],
        check_id: str,
        title: str,
        category: str,
        severity: Severity,
        cvss_score: float,
        location: str,
        observed: str,
        description: str,
        impact: str,
        remediation: str,
    ) -> Finding:
        safe_observed = sanitize_sensitive_text(observed)
        evidence = Evidence(
            location=sanitize_sensitive_text(location),
            observed_value=safe_observed,
            expected_value="No exploitable condition is present.",
            raw_response_snippet=safe_observed,
        )
        return Finding(
            scan_id=scan_id,
            organization_id=organization_id or "org-default",
            engine="network",
            source_tool=self.tool_name,
            check_id=check_id,
            category=category,
            title=title,
            severity=severity,
            cvss_score=cvss_score,
            description=description,
            impact=impact,
            remediation=remediation,
            evidence=evidence,
            fingerprint=calculate_fingerprint(check_id, location, safe_observed),
        )


class MetasploitAdapter(GovernedExtendedAdapter):
    manifest_name = "metasploit"
    binary_name = "msfconsole"

    @property
    def tool_name(self) -> str:
        return "metasploit"

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "-v"], timeout=15.0, pre_launch_check=pre_launch_check)
        match = re.search(r"Framework Version:\s*([0-9]+(?:\.[0-9]+)+(?:-[A-Za-z0-9.-]+)?)", stdout + stderr)
        return f"metasploit {match.group(1)}" if match else None

    @staticmethod
    def build_command(binary: str, target_host: str, port: int = 443) -> List[str]:
        host = _host(target_host)
        if not 1 <= port <= 65535:
            raise ValueError("Invalid target port")
        script = f"use auxiliary/scanner/ssl/openssl_heartbleed; set RHOSTS {host}; set RPORT {port}; run; exit"
        return [binary, "-q", "-x", script]

    async def run(self, target: Target, config: ScanConfig, emit_log: EmitLog, emit_finding: EmitFinding, **kwargs) -> List[Finding]:
        binary = await self._binary_or_block(config, getattr(config.adapters, "metasploit_path", None) or getattr(config.adapters, "custom_metasploit_path", None), emit_log)
        if not binary:
            return []
        command = self.build_command(binary, target.value, int(kwargs.get("port", 443)))
        code, stdout, stderr = await self.execute_command(command, timeout=min(60.0, config.timeout_seconds), emit_log=emit_log, pre_launch_check=lambda: self.verify_managed_binary(binary))
        findings: List[Finding] = []
        for line in stdout.splitlines():
            if "[+]" not in line:
                continue
            finding = self._finding(scan_id=kwargs.get("scan_id", "local-scan"), organization_id=kwargs.get("organization_id"), check_id="NET-TLS-001", title="Metasploit Auxiliary Verification Result", category="SSL/TLS", severity=Severity.HIGH, cvss_score=7.5, location=_host(target.value), observed=line, description="A governed Metasploit auxiliary scanner reported a TLS verification condition.", impact="The target may expose a known TLS implementation weakness.", remediation="Patch the TLS implementation and disable vulnerable protocol behavior.")
            findings.append(finding)
            await emit_finding(finding)
        self._record_execution(code, stdout, stderr, findings_count=len(findings))
        return findings


class SqlmapAdapter(GovernedExtendedAdapter):
    manifest_name = "sqlmap"

    @property
    def tool_name(self) -> str:
        return "sqlmap"

    @staticmethod
    def build_command(binary: str, target_url: str, output_dir: str) -> List[str]:
        url = _target_url(target_url)
        if not Path(output_dir).is_absolute():
            raise ValueError("Output directory must be an absolute server-derived path")
        return [binary, "-u", url, "--batch", "--banner", "--level=1", "--risk=1", "--timeout=15", "--retries=1", "--threads=2", "--output-dir", output_dir]

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "--version"], timeout=15.0, pre_launch_check=pre_launch_check)
        match = re.search(r"sqlmap/([0-9]+(?:\.[0-9]+)+)", stdout + stderr, re.IGNORECASE)
        return f"sqlmap {match.group(1)}" if match else None

    async def run(self, target: Target, config: ScanConfig, emit_log: EmitLog, emit_finding: EmitFinding, **kwargs) -> List[Finding]:
        binary = await self._binary_or_block(config, getattr(config.adapters, "sqlmap_path", None) or getattr(config.adapters, "custom_sqlmap_path", None), emit_log)
        if not binary:
            return []
        output_dir = kwargs.get("output_dir")
        if not output_dir:
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "sqlmap execution blocked: no server-derived output directory was supplied.")
            return []
        command = self.build_command(binary, target.value, output_dir)
        code, stdout, stderr = await self.execute_command(command, timeout=min(90.0, config.timeout_seconds), emit_log=emit_log, pre_launch_check=lambda: self.verify_managed_binary(binary))
        findings: List[Finding] = []
        for match in re.finditer(r"Parameter:\s*([^\s(]+).*?Type:\s*([^\n]+)", stdout, re.IGNORECASE | re.DOTALL):
            parameter, injection_type = match.group(1), match.group(2).strip()
            finding = self._finding(scan_id=kwargs.get("scan_id", "local-scan"), organization_id=kwargs.get("organization_id"), check_id="DAST-INJ-001", title="SQL Injection Confirmed by sqlmap", category="Injection", severity=Severity.CRITICAL, cvss_score=9.8, location=f"{target.value}#{parameter}", observed=f"Parameter: {parameter}; Type: {injection_type}", description="sqlmap confirmed an injectable request parameter under the bounded automated profile.", impact="An attacker may read or modify backend database data.", remediation="Use parameterized queries and strict server-side input validation.")
            findings.append(finding)
            await emit_finding(finding)
        self._record_execution(code, stdout, stderr, findings_count=len(findings))
        return findings


class AmassAdapter(GovernedExtendedAdapter):
    manifest_name = "amass"

    @property
    def tool_name(self) -> str:
        return "amass"

    @staticmethod
    def build_command(binary: str, domain: str, output_file: str) -> List[str]:
        root = _host(domain)
        if not Path(output_file).is_absolute():
            raise ValueError("Output file must be an absolute server-derived path")
        return [binary, "enum", "-passive", "-d", root, "-json", output_file, "-timeout", "30"]

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "-version"], timeout=15.0, pre_launch_check=pre_launch_check)
        match = re.search(r"v?(\d+(?:\.\d+)+)", stdout + stderr)
        return f"amass {match.group(1)}" if match else None

    async def run(self, target: Target, config: ScanConfig, emit_log: EmitLog, emit_finding: EmitFinding, **kwargs) -> List[Finding]:
        binary = await self._binary_or_block(config, getattr(config.adapters, "amass_path", None) or getattr(config.adapters, "custom_amass_path", None), emit_log)
        if not binary:
            return []
        output_file = kwargs.get("output_file")
        if not output_file:
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "Amass execution blocked: no server-derived output file was supplied.")
            return []
        command = self.build_command(binary, target.value, output_file)
        code, stdout, stderr = await self.execute_command(command, timeout=min(90.0, config.timeout_seconds), emit_log=emit_log, pre_launch_check=lambda: self.verify_managed_binary(binary))
        findings: List[Finding] = []
        emit_subdomain = kwargs.get("emit_subdomain")
        try:
            with open(output_file, "r", encoding="utf-8") as report:
                for line in report:
                    data = json.loads(line)
                    name = data.get("name")
                    if isinstance(name, str) and _host(name):
                        if emit_subdomain:
                            await emit_subdomain(DiscoveredSubdomain(
                                domain=_host(name),
                                ip_addresses=[],
                                cname_targets=[],
                                discovered_via=", ".join(str(source) for source in data.get("sources", []) if source) or "Amass",
                                dns_status="UNRESOLVED",
                            ))
                        finding = self._finding(scan_id=kwargs.get("scan_id", "local-scan"), organization_id=kwargs.get("organization_id"), check_id="EASM-SUB-001", title="Amass Passive Subdomain Discovery", category="OSINT", severity=Severity.INFO, cvss_score=0.0, location=name, observed=json.dumps({"name": name, "sources": data.get("sources", [])}, sort_keys=True), description="Amass passively reported a subdomain from configured public sources.", impact="The hostname expands the observed external attack surface.", remediation="Review and explicitly admit the hostname to inventory before any active assessment.")
                        findings.append(finding)
                        await emit_finding(finding)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            self._record_execution(code, stdout, stderr, parser_error=True)
            await emit_log(LogLevel.WARNING, f"Amass output parsing was incomplete: {type(exc).__name__}")
        self._record_execution(code, stdout, stderr, findings_count=len(findings))
        return findings


class HydraAdapter(GovernedExtendedAdapter):
    manifest_name = "hydra"

    @property
    def tool_name(self) -> str:
        return "hydra"

    @staticmethod
    def build_command(binary: str, username_file: str, password_file: str, protocol: str, target_host: str, port: int, output_file: str) -> List[str]:
        if protocol not in {"ssh", "ftp", "http-get", "https-get", "smtp"}:
            raise ValueError("Unsupported Hydra protocol")
        paths = [username_file, password_file, output_file]
        if any(not Path(path).is_absolute() for path in paths):
            raise ValueError("Credential and output files must be server-derived absolute paths")
        host = _host(target_host)
        if not 1 <= port <= 65535:
            raise ValueError("Invalid target port")
        return [binary, "-L", username_file, "-P", password_file, f"{protocol}://{host}:{port}", "-t", "2", "-W", "1", "-f", "-b", "json", "-o", output_file]

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "-h"], timeout=15.0, pre_launch_check=pre_launch_check)
        match = re.search(r"Hydra v([0-9]+(?:\.[0-9]+)+)", stdout + stderr, re.IGNORECASE)
        return f"hydra {match.group(1)}" if match else None

    async def run(self, target: Target, config: ScanConfig, emit_log: EmitLog, emit_finding: EmitFinding, **kwargs) -> List[Finding]:
        binary = await self._binary_or_block(config, getattr(config.adapters, "hydra_path", None) or getattr(config.adapters, "custom_hydra_path", None), emit_log)
        if not binary:
            return []
        username_file, password_file, output_file = (kwargs.get("username_file"), kwargs.get("password_file"), kwargs.get("output_file"))
        if not kwargs.get("explicit_credential_audit") or not all(isinstance(path, str) for path in (username_file, password_file, output_file)):
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "Hydra execution blocked: explicit credential-audit authorization and server-derived files are required.")
            return []
        command = self.build_command(binary, username_file, password_file, kwargs.get("protocol", "ssh"), target.value, int(kwargs.get("port", 22)), output_file)
        code, stdout, stderr = await self.execute_command(command, timeout=min(90.0, config.timeout_seconds), emit_log=emit_log, pre_launch_check=lambda: self.verify_managed_binary(binary))
        findings: List[Finding] = []
        try:
            with open(output_file, "r", encoding="utf-8") as report:
                data = json.load(report)
            for result in data.get("results", []) if isinstance(data, dict) else []:
                if result.get("login") and result.get("password"):
                    # Never persist the recovered password; retain only the fact
                    # that a credential pair succeeded and its login identifier.
                    login = sanitize_sensitive_text(str(result["login"]))
                    finding = self._finding(scan_id=kwargs.get("scan_id", "local-scan"), organization_id=kwargs.get("organization_id"), check_id="AUTH-STUFF-001", title="Weak Authentication Credential Accepted", category="Authentication Resilience", severity=Severity.HIGH, cvss_score=8.1, location=f"{_host(target.value)}:{kwargs.get('port', 22)}", observed=f"Successful credential for login '{login}'", description="Hydra confirmed that a bounded authorized credential-audit list succeeded.", impact="Weak credentials may permit unauthorized access to the service.", remediation="Remove default credentials, require strong unique passwords, and enforce MFA where supported.")
                    findings.append(finding)
                    await emit_finding(finding)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            self._record_execution(code, stdout, stderr, parser_error=True)
            await emit_log(LogLevel.WARNING, f"Hydra output parsing was incomplete: {type(exc).__name__}")
        self._record_execution(code, stdout, stderr, findings_count=len(findings))
        return findings
