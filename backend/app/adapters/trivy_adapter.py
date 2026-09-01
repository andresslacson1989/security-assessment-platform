"""
Contract 03 (Section 4.2), Contract 06 (Section 2) & Contract 08 (Section 8.4) Trivy Tool Adapter.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import json
import re
from typing import Optional, List, Callable, Awaitable

from app.core.models import (
    Target,
    Finding,
    Evidence,
    Severity,
    ScanConfig,
    LogLevel,
    calculate_fingerprint,
    NormalizedExecutionState,
)
from app.adapters.base_adapter import BaseToolAdapter


SEVERITY_MAP = {
    "CRITICAL": (Severity.CRITICAL, 9.8),
    "HIGH": (Severity.HIGH, 7.5),
    "MEDIUM": (Severity.MEDIUM, 5.3),
    "LOW": (Severity.LOW, 3.1),
    "UNKNOWN": (Severity.LOW, 3.0),
}


class TrivyAdapter(BaseToolAdapter):
    """
    Hybrid tool adapter for Aqua Security Trivy vulnerability and dependency scanner.
    Normalizes JSON scan output into canonical SAST-DEP-001 and IAC-DOCK-xxx findings.
    """
    approved_version = "0.50.0"

    @property
    def tool_name(self) -> str:
        return "trivy"

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        """
        Retrieves Trivy version string via `trivy --version`.
        """
        path = self.resolve_binary_path(custom_path)
        if not path:
            return None

        returncode, stdout, stderr = await self.execute_command([path, "--version"], timeout=5.0, pre_launch_check=pre_launch_check)
        output = stdout or stderr
        if output:
            for line in output.splitlines():
                match = re.search(r"Version:\s*([0-9]+\.[0-9]+\.[0-9]+)", line, re.IGNORECASE)
                if match:
                    return f"trivy {match.group(1)}"
                match2 = re.search(r"trivy\s+version\s+([0-9]+\.[0-9]+\.[0-9]+)", line, re.IGNORECASE)
                if match2:
                    return f"trivy {match2.group(1)}"
            first_line = output.splitlines()[0].strip()
            return first_line if first_line else None
        return None

    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
        **kwargs,
    ) -> List[Finding]:
        """
        Executes Trivy filesystem scan: trivy fs --format json <repo_path>
        Parses JSON results for vulnerabilities and misconfigurations.
        """
        findings: List[Finding] = []
        custom_path = getattr(config.adapters, "trivy_path", None) or getattr(config.adapters, "custom_trivy_path", None)
        trivy_path = self.resolve_binary_path(custom_path)

        if not trivy_path:
            self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.WARNING, "Trivy binary not found on host. Skipping Trivy execution.")
            return findings

        managed_check = (lambda: self.verify_managed_binary(trivy_path)) if kwargs.get("require_managed_binary") else None
        if kwargs.get("require_managed_binary") and not managed_check():
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "Trivy execution blocked: executable is not a trusted managed installation.")
            return findings
        if kwargs.get("require_managed_binary") and not await self.ensure_approved_version(custom_path, emit_log, pre_launch_check=managed_check):
            return findings

        repo_path = target.value.strip()
        cmd = [
            trivy_path,
            "fs",
            "--format", "json",
            repo_path,
        ]

        await emit_log(LogLevel.INFO, f"Starting Trivy SCA and dependency scan on path '{repo_path}'...")
        returncode, stdout, stderr = await self.execute_command(
            cmd,
            timeout=float(min(60.0, config.timeout_seconds * 6)),
            emit_log=emit_log,
            pre_launch_check=managed_check,
        )

        if not stdout.strip():
            self._record_execution(returncode, stdout, stderr)
            if returncode != 0 and stderr:
                await emit_log(LogLevel.WARNING, f"Trivy exited with code {returncode}: {stderr.strip()}")
            else:
                await emit_log(LogLevel.INFO, "Trivy completed with no findings.")
            return findings

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            self._record_execution(returncode, stdout, stderr, parser_error=True)
            await emit_log(LogLevel.ERROR, f"Failed to parse Trivy JSON output: {e}")
            return findings

        scan_id = kwargs.get("scan_id", "adapter-trivy")
        results = data.get("Results", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])

        for res in results:
            target_file = res.get("Target", "dependencies")
            target_class = res.get("Class", "")

            # 1. Process Vulnerabilities (SCA / Dependencies)
            vulnerabilities = res.get("Vulnerabilities", []) or []
            for v in vulnerabilities:
                vuln_id = v.get("VulnerabilityID") or "CVE-UNKNOWN"
                pkg_name = v.get("PkgName") or "unknown"
                installed_ver = v.get("InstalledVersion") or "unknown"
                fixed_ver = v.get("FixedVersion") or "N/A"
                title = v.get("Title") or f"Vulnerable package {pkg_name}"
                description = v.get("Description") or f"Vulnerability {vuln_id} detected in dependency {pkg_name} ({installed_ver})."
                severity_raw = str(v.get("Severity", "MEDIUM")).upper()
                primary_url = v.get("PrimaryURL") or ""

                severity, cvss_score = SEVERITY_MAP.get(severity_raw, (Severity.MEDIUM, 5.3))

                # Primary CVSS if available
                cvss_info = v.get("CVSS", {})
                nvd_v3 = cvss_info.get("nvd", {}).get("V3Score")
                redhat_v3 = cvss_info.get("redhat", {}).get("V3Score")
                if nvd_v3:
                    cvss_score = float(nvd_v3)
                elif redhat_v3:
                    cvss_score = float(redhat_v3)

                cwe_ids = v.get("CweIDs", [])
                cwe_id = cwe_ids[0] if cwe_ids else "CWE-1395"

                evidence = Evidence(
                    location=f"{target_file}:{pkg_name}@{installed_ver}",
                    observed_value=f"{vuln_id} affecting {pkg_name} {installed_ver} (Fixed in: {fixed_ver})",
                    expected_value="Dependency free of known vulnerabilities",
                    raw_response_snippet=f"Target: {target_file}\nPackage: {pkg_name}\nInstalled: {installed_ver}\nFixed: {fixed_ver}\nCVE: {vuln_id}",
                )

                finding = Finding(
                    scan_id=scan_id,
                    engine="code_sast",
                    source_tool="trivy",
                    check_id="SAST-DEP-001",
                    category="Vulnerable Dependencies",
                    title=f"Vulnerable Dependency ({pkg_name} {installed_ver} - {vuln_id})",
                    severity=severity,
                    cvss_score=cvss_score,
                    cvss_vector=None,
                    cwe_id=cwe_id,
                    owasp_category="A06:2021-Vulnerable and Outdated Components",
                    nist_control="SA-15, SI-2",
                    description=description,
                    impact=f"Known CVE {vuln_id} in {pkg_name} may expose application to remote exploitation.",
                    remediation=f"Upgrade dependency '{pkg_name}' to version {fixed_ver} or latest secure release.",
                    remediation_code_snippet=f"# Update dependency in lockfile:\n{pkg_name} >= {fixed_ver}" if fixed_ver != "N/A" else None,
                    references=[primary_url] if primary_url else [f"https://nvd.nist.gov/vuln/detail/{vuln_id}"],
                    evidence=evidence,
                    fingerprint=calculate_fingerprint("SAST-DEP-001", f"{target_file}:{pkg_name}", vuln_id),
                )

                findings.append(finding)
                await emit_finding(finding)

            # 2. Process Misconfigurations (IaC / Dockerfile / K8s)
            misconfigurations = res.get("Misconfigurations", []) or []
            for m in misconfigurations:
                misc_id = m.get("ID") or "IAC-DOCK-001"
                title = m.get("Title") or "IaC Security Misconfiguration"
                description = m.get("Description") or f"Misconfiguration {misc_id} identified in {target_file}."
                message = m.get("Message") or description
                severity_raw = str(m.get("Severity", "HIGH")).upper()
                resolution = m.get("Resolution") or "Update configuration to follow security hardening guidance."
                primary_url = m.get("PrimaryURL") or ""

                severity, cvss_score = SEVERITY_MAP.get(severity_raw, (Severity.HIGH, 7.8))

                check_id = "IAC-DOCK-001"
                if "root" in title.lower() or "user" in title.lower():
                    check_id = "IAC-DOCK-001"
                elif "healthcheck" in title.lower():
                    check_id = "IAC-DOCK-003"
                elif "secret" in title.lower():
                    check_id = "IAC-DOCK-004"
                elif "privileged" in title.lower():
                    check_id = "IAC-CMP-001"
                elif "docker.sock" in title.lower():
                    check_id = "IAC-CMP-002"

                evidence = Evidence(
                    location=target_file,
                    observed_value=f"{misc_id}: {title} - {message}",
                    expected_value="Container/IaC manifest configured per security hardening standards",
                    raw_response_snippet=f"File: {target_file}\nRule: {misc_id}\nResolution: {resolution}",
                )

                finding = Finding(
                    scan_id=scan_id,
                    engine="infra_iac",
                    source_tool="trivy",
                    check_id=check_id,
                    category="Container Posture",
                    title=f"Container Misconfiguration ({misc_id}: {title})",
                    severity=severity,
                    cvss_score=cvss_score,
                    cwe_id="CWE-250",
                    owasp_category="A05:2021-Security Misconfiguration",
                    nist_control="AC-6, CM-7",
                    description=description,
                    impact="Insecure container configuration may permit privilege escalation or host compromise.",
                    remediation=resolution,
                    references=[primary_url] if primary_url else [f"https://avd.aquasec.com/misconfig/{misc_id.lower()}"],
                    evidence=evidence,
                    fingerprint=calculate_fingerprint(check_id, target_file, misc_id),
                )

                findings.append(finding)
                await emit_finding(finding)

        self._record_execution(returncode, stdout, stderr, findings_count=len(findings))
        await emit_log(LogLevel.INFO, f"Trivy scan completed. Generated {len(findings)} findings.")
        return findings
