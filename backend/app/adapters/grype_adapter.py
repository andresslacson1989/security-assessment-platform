"""
Grype Tool Adapter for SBOM & Package Vulnerability Matching.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md (Section 4.2)
"""

from __future__ import annotations
import json
import os
import re
from typing import Optional, List, Callable, Awaitable, Dict, Any

from app.core.models import (
    Target, Finding, Evidence, ScanConfig, LogLevel, Severity,
    calculate_fingerprint
)
from app.adapters.base_adapter import BaseToolAdapter


class GrypeAdapter(BaseToolAdapter):
    """
    Adapter for Anchore Grype vulnerability matcher for container images and filesystems.
    """

    @property
    def tool_name(self) -> str:
        return "grype"

    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "--version"], timeout=10.0)
        output = stdout + " " + stderr
        match = re.search(r"\d+\.\d+\.\d+", output)
        if match:
            return f"grype {match.group(0)}"
        return "grype" if code == 0 else None

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

        binary = self.resolve_binary_path(config.adapters.grype_path or config.adapters.custom_grype_path)
        if not binary:
            await emit_log(LogLevel.WARNING, "Grype binary not found. Skipping Grype vulnerability matching.")
            return findings

        scan_path = target.value
        if not os.path.exists(scan_path):
            await emit_log(LogLevel.WARNING, f"Target path not accessible: {scan_path}")
            return findings

        await emit_log(LogLevel.INFO, f"Executing Grype supply chain vulnerability scanner on: {scan_path}")
        cmd = [binary, scan_path, "-o", "json", "-q"]

        code, stdout, stderr = await self.execute_command(cmd, timeout=60.0, emit_log=emit_log)

        try:
            data = json.loads(stdout)
            matches = data.get("matches", [])

            sev_map = {
                "Critical": (Severity.CRITICAL, 9.8),
                "High": (Severity.HIGH, 7.5),
                "Medium": (Severity.MEDIUM, 5.3),
                "Low": (Severity.LOW, 3.1),
                "Negligible": (Severity.INFO, 0.0),
            }

            for match in matches:
                vuln = match.get("vulnerability", {})
                artifact = match.get("artifact", {})
                cve_id = vuln.get("id", "CVE-UNKNOWN")
                pkg_name = artifact.get("name", "unknown-package")
                pkg_version = artifact.get("version", "0.0.0")
                raw_sev = vuln.get("severity", "Medium")
                fix_versions = vuln.get("fix", {}).get("versions", [])
                fix_str = ", ".join(fix_versions) if fix_versions else "No fix available yet"

                severity, cvss_score = sev_map.get(raw_sev, (Severity.MEDIUM, 5.3))
                urls = vuln.get("urls", [])

                evidence = Evidence(
                    location=f"{pkg_name}@{pkg_version}",
                    observed_value=f"{cve_id} ({raw_sev}) - Installed: {pkg_version} | Fixed in: {fix_str}",
                    expected_value=f"Upgrade {pkg_name} to >= {fix_str}" if fix_versions else "Mitigate or replace component",
                    raw_response_snippet=json.dumps(match, indent=2),
                )

                finding = Finding(
                    scan_id=scan_id,
                    engine="code_sast",
                    source_tool="grype",
                    check_id="SCA-SBOM-001",
                    category="Vulnerable Dependencies",
                    title=f"{cve_id} in {pkg_name} v{pkg_version}",
                    severity=severity,
                    cvss_score=cvss_score,
                    cwe_id="CWE-1395",
                    description=f"Grype identified vulnerability `{cve_id}` in package `{pkg_name}` (v`{pkg_version}`). {vuln.get('description', '')[:250]}",
                    impact="Vulnerable dependencies can allow remote code execution, denial of service, or unauthorized data access.",
                    remediation=f"Upgrade `{pkg_name}` to version `{fix_str}` or apply vendor patches.",
                    references=urls or ["https://github.com/anchore/grype"],
                    evidence=evidence,
                    fingerprint=calculate_fingerprint("SCA-SBOM-001", f"{pkg_name}@{pkg_version}", cve_id),
                )
                findings.append(finding)
                await emit_finding(finding)

        except Exception as e:
            await emit_log(LogLevel.WARNING, f"Grype output parsing error: {e}")

        await emit_log(LogLevel.INFO, f"Grype completed: {len(findings)} package vulnerabilities matched.")
        return findings
