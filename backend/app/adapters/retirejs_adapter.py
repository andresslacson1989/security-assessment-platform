"""
Retire.js Tool Adapter for Client-Side JavaScript Vulnerability Auditing.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md (Section 4.2)
"""

from __future__ import annotations
import json
import os
import re
from pathlib import Path
from typing import Optional, List, Callable, Awaitable, Dict, Any

from app.core.models import (
    Target, Finding, Evidence, ScanConfig, LogLevel, Severity,
    calculate_fingerprint, NormalizedExecutionState, sanitize_sensitive_text,
)
from app.adapters.base_adapter import BaseToolAdapter
from app.core.path_sandbox import safe_workspace_relative_path


class RetireJSAdapter(BaseToolAdapter):
    """
    Adapter for Retire.js client-side JavaScript library vulnerability scanner.
    """
    approved_version = "4.4.3"
    package_name = "retire"

    @property
    def tool_name(self) -> str:
        return "retire"

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "--version"], timeout=10.0, pre_launch_check=pre_launch_check)
        output = stdout + " " + stderr
        match = re.search(r"\d+\.\d+\.\d+", output)
        if match:
            return f"retire.js {match.group(0)}"
        return "retire" if code == 0 else None

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

        binary = self.resolve_binary_path(config.adapters.retirejs_path or config.adapters.custom_retirejs_path)
        if not binary:
            self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.WARNING, "Retire.js binary not found. Skipping client-side JS audit.")
            return findings

        scan_path = target.value
        if not os.path.exists(scan_path):
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.WARNING, f"Target path not accessible: {scan_path}")
            return findings

        await emit_log(LogLevel.INFO, f"Executing Retire.js vulnerability audit on: {scan_path}")
        if kwargs.get("require_managed_binary") and not self.verify_managed_binary(binary):
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "Retire.js execution blocked: executable is not a trusted managed installation.")
            return findings
        managed_check = (lambda: self.verify_managed_binary(binary)) if kwargs.get("require_managed_binary") else None
        if kwargs.get("require_managed_binary") and not await self.ensure_approved_version(
            config.adapters.retirejs_path or config.adapters.custom_retirejs_path,
            emit_log,
            pre_launch_check=managed_check,
        ):
            return findings
        cmd = [binary, "--path", scan_path, "--outputformat", "json", "--nodownload", "--exitwith", "0"]

        code, stdout, stderr = await self.execute_command(
            cmd, timeout=45.0, emit_log=emit_log,
            pre_launch_check=managed_check,
        )

        try:
            report_data = json.loads(stdout) if stdout.strip().startswith("{") or stdout.strip().startswith("[") else []
            if isinstance(report_data, dict):
                report_data = report_data.get("data", [])

            for item in report_data:
                file_path = safe_workspace_relative_path(item.get("file", "Unknown JS file"), Path(scan_path)) or "untrusted-output"
                results = item.get("results", [])
                for res in results:
                    component = res.get("component", "JS Library")
                    version = res.get("version", "unknown")
                    vulns = res.get("vulnerabilities", [])

                    for vuln in vulns:
                        identifiers = vuln.get("identifiers", {})
                        cves = identifiers.get("CVE", [])
                        cve_str = ", ".join(cves) if cves else identifiers.get("issue", "Prototype Pollution / XSS")
                        summary = sanitize_sensitive_text(vuln.get("info", ["Vulnerable JavaScript library component"])[0]) or "Vulnerable JavaScript library component"
                        severity_str = vuln.get("severity", "medium").upper()

                        sev_map = {
                            "CRITICAL": (Severity.CRITICAL, 9.8),
                            "HIGH": (Severity.HIGH, 7.5),
                            "MEDIUM": (Severity.MEDIUM, 5.3),
                            "LOW": (Severity.LOW, 3.1),
                        }
                        severity, cvss_score = sev_map.get(severity_str, (Severity.MEDIUM, 5.3))

                        evidence = Evidence(
                            location=f"{file_path} ({component}@{version})",
                            observed_value=f"{component} v{version} contains {cve_str}",
                            expected_value=f"Update {component} to a secure, patched version",
                            raw_response_snippet=json.dumps(vuln, indent=2),
                        )

                        finding = Finding(
                            scan_id=scan_id,
                            engine="code_sast",
                            source_tool="retirejs",
                            check_id="SCA-JS-001",
                            category="Vulnerable JS Library",
                            title=f"Vulnerable JavaScript Library: {component} v{version} ({cve_str})",
                            severity=severity,
                            cvss_score=cvss_score,
                            cwe_id="CWE-1395",
                            description=f"Retire.js identified vulnerable library `{component}` version `{version}` in `{file_path}`: {summary}.",
                            impact="Known client-side vulnerabilities may allow DOM-based Cross-Site Scripting (XSS), prototype pollution, or data exfiltration.",
                            remediation=f"Upgrade `{component}` to the latest patched release or replace with a maintained alternative.",
                            references=vuln.get("info", ["https://retirejs.github.io/retire.js/"]),
                            evidence=evidence,
                            fingerprint=calculate_fingerprint("SCA-JS-001", file_path, f"{component}-{version}-{cve_str}"),
                        )
                        findings.append(finding)
                        await emit_finding(finding)
        except Exception as e:
            self._record_execution(code, stdout, stderr, parser_error=True)
            await emit_log(LogLevel.WARNING, f"Retire.js parsing error: {e}")

        self._record_execution(code, stdout, stderr, findings_count=len(findings))
        await emit_log(LogLevel.INFO, f"Retire.js completed: {len(findings)} JavaScript library CVEs identified.")
        return findings
