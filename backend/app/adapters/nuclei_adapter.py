"""
Contract 03 (Section 4.2), Contract 06 (Section 2) & Contract 08 (Section 8.2) Nuclei Tool Adapter.
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
from app.core.ssrf_protector import bind_url_to_validated_target


SEVERITY_MAP = {
    "critical": (Severity.CRITICAL, 9.8),
    "high": (Severity.HIGH, 7.5),
    "medium": (Severity.MEDIUM, 5.3),
    "low": (Severity.LOW, 3.1),
    "info": (Severity.INFO, 0.0),
}

APPROVED_VERSION = "3.2.0"


def normalize_target_url(target_value: str) -> str:
    """
    Ensures target has an HTTP or HTTPS scheme for Nuclei.
    """
    target_value = target_value.strip()
    if target_value.startswith("http://") or target_value.startswith("https://"):
        return target_value
    return f"https://{target_value}"


def map_nuclei_check_id(template_id: str, name: str, tags: List[str]) -> tuple[str, str, str, str]:
    """
    Maps Nuclei template metadata to canonical check ID, category, OWASP, and NIST taxonomy.
    """
    combined = f"{template_id} {name} {' '.join(tags)}".lower()

    if "sqli" in combined or "sql-injection" in combined or "sql injection" in combined:
        return "DAST-INJ-001", "Injection", "A03:2021-Injection", "SI-10"
    if "xss" in combined or "cross-site-scripting" in combined:
        return "DAST-XSS-001", "Injection", "A03:2021-Injection", "SI-10"
    if "lfi" in combined or "path-traversal" in combined or "traversal" in combined or "file-inclusion" in combined:
        return "DAST-LFI-001", "Broken Access Control", "A01:2021-Broken Access Control", "AC-3, SI-10"
    if "ssti" in combined or "template-injection" in combined:
        return "DAST-SSTI-001", "Injection", "A03:2021-Injection", "SI-10"
    if "cors" in combined:
        return "DAST-CORS-001", "Misconfiguration", "A01:2021-Broken Access Control", "AC-3, SC-7"
    if "env" in combined or ".env" in combined:
        return "DAST-EXP-001", "Sensitive Data Exposure", "A01:2021-Broken Access Control", "AC-3, SC-28"
    if "git" in combined or ".git" in combined:
        return "DAST-EXP-002", "Sensitive Data Exposure", "A01:2021-Broken Access Control", "AC-3, SC-28"
    if "actuator" in combined or "spring" in combined:
        return "DAST-EXP-003", "Sensitive Data Exposure", "A05:2021-Security Misconfiguration", "AC-3"
    if "swagger" in combined or "openapi" in combined:
        return "DAST-EXP-004", "Sensitive Data Exposure", "A05:2021-Security Misconfiguration", "AC-3"
    if "header" in combined or "csp" in combined or "hsts" in combined or "x-frame" in combined:
        return "DAST-HDR-001", "Security Headers", "A05:2021-Security Misconfiguration", "SC-18, SI-10"
    if "graphql" in combined or "introspection" in combined:
        return "DAST-GQL-001", "API Security", "A05:2021-Security Misconfiguration", "AC-3"

    # Default mapping for general CVEs / web findings
    return "DAST-EXP-001", "Web Vulnerability", "A01:2021-Broken Access Control", "AC-3, SI-10"


class NucleiAdapter(BaseToolAdapter):
    """
    Hybrid tool adapter for ProjectDiscovery Nuclei vulnerability scanner.
    Normalizes JSON Lines output into canonical DAST-xxx findings.
    """

    def __init__(self):
        super().__init__()
        self.approved_version = APPROVED_VERSION
        self.last_execution_state = NormalizedExecutionState.COMPLETED_NO_FINDINGS

    @property
    def tool_name(self) -> str:
        return "nuclei"

    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        """
        Retrieves Nuclei version string via `nuclei -version`.
        """
        path = self.resolve_binary_path(custom_path)
        if not path:
            return None

        returncode, stdout, stderr = await self.execute_command([path, "-version"], timeout=5.0)
        output = stdout or stderr
        if output:
            for line in output.splitlines():
                match = re.search(r"v([0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9\.\-]*)", line)
                if match:
                    return f"nuclei v{match.group(1)}"
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
        Executes Nuclei scan:
        nuclei -u <target_url> -j -silent -tags cve,misconfig -severity low,medium,high,critical
        Parses streaming JSON line-by-line and creates normalized Finding objects.
        """
        findings: List[Finding] = []
        self.last_execution_state = NormalizedExecutionState.COMPLETED_NO_FINDINGS
        custom_path = getattr(config.adapters, "nuclei_path", None) or getattr(config.adapters, "custom_nuclei_path", None)
        nuclei_path = self.resolve_binary_path(custom_path)

        if not nuclei_path:
            self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.WARNING, "Nuclei binary not found on host. Skipping Nuclei execution.")
            return findings

        if kwargs.get("require_managed_binary") and not self.verify_managed_binary(nuclei_path):
            self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.ERROR, "Nuclei execution blocked: executable is not a trusted managed installation.")
            return findings

        if not await self.ensure_approved_version(custom_path, emit_log):
            return findings

        target_url = normalize_target_url(target.value)
        host_header = None
        if kwargs.get("validated_target") is not None:
            target_url, host_header = bind_url_to_validated_target(target_url, kwargs["validated_target"])
        cmd = [
            nuclei_path,
            "-u", target_url,
            "-j",
            "-silent",
            "-tags", "cve,misconfig",
            "-severity", "low,medium,high,critical",
        ]
        if host_header:
            cmd.extend(["-H", f"Host: {host_header}", "-sni", host_header])

        await emit_log(LogLevel.INFO, f"Starting Nuclei DAST vulnerability scan on target '{target_url}'...")
        returncode, stdout, stderr = await self.execute_command(
            cmd,
            timeout=float(min(60.0, config.timeout_seconds * 6)),
            emit_log=emit_log,
        )

        if not stdout.strip():
            self.last_execution_state = NormalizedExecutionState.EXECUTION_TIMED_OUT if "timed out" in stderr.lower() else (NormalizedExecutionState.TOOL_EXECUTION_FAILED if returncode != 0 else NormalizedExecutionState.COMPLETED_NO_FINDINGS)
            if returncode != 0 and stderr:
                await emit_log(LogLevel.WARNING, f"Nuclei exited with code {returncode}: {stderr.strip()}")
            else:
                await emit_log(LogLevel.INFO, "Nuclei completed with no findings.")
            return findings

        scan_id = kwargs.get("scan_id", "adapter-nuclei")

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                self.last_execution_state = NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING
                continue

            template_id = data.get("template-id") or data.get("templateID") or "nuclei-check"
            info = data.get("info", {})
            name = info.get("name") or template_id
            description = info.get("description") or f"Nuclei template {template_id} triggered on target."
            severity_str = str(info.get("severity", "medium")).lower()

            severity, cvss_score = SEVERITY_MAP.get(severity_str, (Severity.MEDIUM, 5.3))

            # Extract CWE IDs
            classification = info.get("classification", {})
            cwe_data = classification.get("cwe-id", [])
            if isinstance(cwe_data, list) and cwe_data:
                cwe_id = str(cwe_data[0]).upper()
                if not cwe_id.startswith("CWE-"):
                    cwe_id = f"CWE-{cwe_id}"
            elif isinstance(cwe_data, str) and cwe_data:
                cwe_id = cwe_data.upper()
                if not cwe_id.startswith("CWE-"):
                    cwe_id = f"CWE-{cwe_id}"
            else:
                cwe_id = "CWE-200"

            tags = info.get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]

            check_id, category, owasp_cat, nist_ctl = map_nuclei_check_id(template_id, name, tags)

            matched_at = data.get("matched-at") or data.get("host") or target_url
            curl_cmd = data.get("curl-command")
            extracted_results = data.get("extracted-results", [])
            extracted_snippet = "\n".join(str(e) for e in extracted_results) if extracted_results else None

            refs = info.get("reference", [])
            if isinstance(refs, str):
                refs = [refs]

            evidence = Evidence(
                location=str(matched_at),
                observed_value=f"Nuclei match for template '{template_id}' ({name})",
                expected_value="Clean and secure response without vulnerability signatures",
                raw_response_snippet=extracted_snippet or data.get("matcher-name"),
            )

            finding = Finding(
                scan_id=scan_id,
                engine="web_dast",
                source_tool="nuclei",
                check_id=check_id,
                category=category,
                title=f"{name} ({template_id})",
                severity=severity,
                cvss_score=cvss_score,
                cwe_id=cwe_id,
                owasp_category=owasp_cat,
                nist_control=nist_ctl,
                description=description,
                impact=f"Potential vulnerability exploitation via template {template_id}.",
                remediation=info.get("remediation") or "Remediate identified flaw by patching or updating application configuration.",
                references=refs or [f"https://github.com/projectdiscovery/nuclei-templates/search?q={template_id}"],
                evidence=evidence,
                reproduction_curl=curl_cmd,
                fingerprint=calculate_fingerprint(check_id, str(matched_at), template_id),
            )

            findings.append(finding)
            await emit_finding(finding)

        await emit_log(LogLevel.INFO, f"Nuclei scan completed. Generated {len(findings)} findings.")
        if returncode != 0 or self.last_execution_state == NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING:
            self.last_execution_state = NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING
        elif findings:
            self.last_execution_state = NormalizedExecutionState.COMPLETED_WITH_FINDINGS
        return findings
