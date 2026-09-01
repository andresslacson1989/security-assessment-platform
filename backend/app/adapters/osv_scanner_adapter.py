"""
Google OSV-Scanner Tool Adapter for Open Source Lockfile Vulnerability Scanning.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md (Section 4.2)
"""

from __future__ import annotations
import json
import os
import re
from typing import Optional, List, Callable, Awaitable, Dict, Any

from app.core.models import (
    Target, Finding, Evidence, ScanConfig, LogLevel, Severity,
    calculate_fingerprint, NormalizedExecutionState,
)
from app.adapters.base_adapter import BaseToolAdapter


class OSVScannerAdapter(BaseToolAdapter):
    """
    Adapter for Google's OSV-Scanner vulnerability database matcher.
    """
    approved_version = "1.7.0"

    @property
    def tool_name(self) -> str:
        return "osv-scanner"

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "--version"], timeout=10.0, pre_launch_check=pre_launch_check)
        output = stdout + " " + stderr
        match = re.search(r"\d+\.\d+\.\d+", output)
        if match:
            return f"osv-scanner {match.group(0)}"
        return "osv-scanner" if code == 0 else None

    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
        **kwargs,
    ) -> List[Finding]:
        findings: List[Finding] = []
        scan_id = kwargs.get("scan_id", "local-scan")

        binary = self.resolve_binary_path(config.adapters.osv_scanner_path or config.adapters.custom_osv_scanner_path)
        if not binary:
            self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.WARNING, "OSV-Scanner binary not found. Skipping Google OSV audit.")
            return findings

        scan_path = target.value
        if not os.path.exists(scan_path):
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.WARNING, f"Target directory not accessible: {scan_path}")
            return findings

        await emit_log(LogLevel.INFO, f"Executing Google OSV-Scanner against dependencies in: {scan_path}")
        managed_check = (lambda: self.verify_managed_binary(binary)) if kwargs.get("require_managed_binary") else None
        if kwargs.get("require_managed_binary") and not managed_check():
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "OSV-Scanner execution blocked: executable is not a trusted managed installation.")
            return findings
        if kwargs.get("require_managed_binary") and not await self.ensure_approved_version(
            config.adapters.osv_scanner_path or config.adapters.custom_osv_scanner_path, emit_log, pre_launch_check=managed_check
        ):
            return findings
        cmd = [binary, "scan", "--format", "json", "-r", scan_path]

        code, stdout, stderr = await self.execute_command(cmd, timeout=60.0, emit_log=emit_log, pre_launch_check=managed_check)

        try:
            data = json.loads(stdout)
            results = data.get("results", [])
            for res in results:
                source_path = res.get("source", {}).get("path", scan_path)
                packages = res.get("packages", [])
                for pkg_entry in packages:
                    pkg = pkg_entry.get("package", {})
                    pkg_name = pkg.get("name", "unknown")
                    pkg_ver = pkg.get("version", "0.0.0")
                    ecosystem = pkg.get("ecosystem", "generic")
                    vulns = pkg_entry.get("vulnerabilities", [])

                    for vuln in vulns:
                        vuln_id = vuln.get("id", "OSV-UNKNOWN")
                        summary = vuln.get("summary") or vuln.get("details") or f"Vulnerability {vuln_id} in {pkg_name}"
                        aliases = vuln.get("aliases", [])
                        alias_str = f" ({', '.join(aliases)})" if aliases else ""

                        evidence = Evidence(
                            location=f"{source_path} ({ecosystem}:{pkg_name}@{pkg_ver})",
                            observed_value=f"{vuln_id}{alias_str} reported by Google OSV",
                            expected_value=f"Update {pkg_name} to a secure version without known OSV advisories",
                            raw_response_snippet=json.dumps(vuln, indent=2)[:500],
                        )

                        finding = Finding(
                            scan_id=scan_id,
                            engine="code_sast",
                            source_tool="osv_scanner",
                            check_id="SCA-OSV-001",
                            category="Supply Chain Security",
                            title=f"Google OSV Advisory: {vuln_id} in {pkg_name}@{pkg_ver}",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            cwe_id="CWE-1395",
                            description=f"Google OSV database matched advisory `{vuln_id}`{alias_str} against `{pkg_name} v{pkg_ver}` in `{source_path}`. {summary[:250]}",
                            impact="Open-source vulnerabilities in application dependencies expose systems to supply-chain compromise.",
                            remediation=f"Update dependency `{pkg_name}` to a non-vulnerable release specified in OSV advisory {vuln_id}.",
                            references=[f"https://osv.dev/vulnerability/{vuln_id}"],
                            evidence=evidence,
                            fingerprint=calculate_fingerprint("SCA-OSV-001", f"{source_path}:{pkg_name}", vuln_id),
                        )
                        findings.append(finding)
                        await emit_finding(finding)

        except Exception as e:
            self._record_execution(code, stdout, stderr, parser_error=True)
            await emit_log(LogLevel.WARNING, f"OSV-Scanner output parsing error: {e}")

        self._record_execution(code, stdout, stderr, findings_count=len(findings))
        await emit_log(LogLevel.INFO, f"OSV-Scanner completed: {len(findings)} OSV advisories matched.")
        return findings
