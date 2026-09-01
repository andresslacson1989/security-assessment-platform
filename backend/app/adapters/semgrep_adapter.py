"""
Contract 03 (Section 4.2), Contract 06 (Section 2) & Contract 08 (Section 8.3) Semgrep Tool Adapter.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import json
import os
from pathlib import Path
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
    sanitize_sensitive_text,
)
from app.adapters.base_adapter import BaseToolAdapter
from app.core.path_sandbox import safe_workspace_relative_path


def map_semgrep_rule(
    rule_id: str,
    message: str,
    severity_raw: str,
    cwe_raw: Optional[str] = None,
) -> tuple[str, str, Severity, float, str, str, str]:
    """
    Normalizes Semgrep rule match into canonical check ID, category, Severity, CVSS, CWE, OWASP, and NIST mapping.
    """
    rule_lower = rule_id.lower()
    msg_lower = message.lower()
    combined = f"{rule_lower} {msg_lower}"

    # 1. SQL Injection
    if "sql" in combined or "sqli" in combined:
        return (
            "SAST-TAINT-001",
            "Code Injection",
            Severity.CRITICAL,
            9.8,
            cwe_raw or "CWE-89",
            "A03:2021-Injection",
            "SI-10",
        )

    # 2. Command / Shell Injection
    if any(k in combined for k in ("command-injection", "shell-injection", "subprocess", "os.system", "exec", "system(")):
        return (
            "SAST-TAINT-002",
            "Code Injection",
            Severity.CRITICAL,
            9.8,
            cwe_raw or "CWE-78",
            "A03:2021-Injection",
            "SI-10",
        )

    # 3. Insecure Deserialization
    if any(k in combined for k in ("pickle", "yaml.load", "deserialization", "unpickle")):
        return (
            "SAST-INJ-003",
            "Insecure Deserialization",
            Severity.HIGH,
            8.5,
            cwe_raw or "CWE-502",
            "A08:2021-Software and Data Integrity Failures",
            "SI-10",
        )

    # 4. Hardcoded Secrets
    if any(k in combined for k in ("secret", "token", "password", "api_key", "private-key", "credentials")):
        return (
            "SAST-SEC-001",
            "Hardcoded Secrets",
            Severity.HIGH,
            8.6,
            cwe_raw or "CWE-798",
            "A07:2021-Identification and Authentication Failures",
            "IA-5, SC-28",
        )

    # 5. Insecure Cryptography / Hash / Cipher
    if any(k in combined for k in ("md5", "sha1", "cipher", "crypto", "ecb", "random", "prng")):
        return (
            "SAST-CRY-001",
            "Cryptographic Flaws",
            Severity.MEDIUM,
            5.3,
            cwe_raw or "CWE-327",
            "A02:2021-Cryptographic Failures",
            "SC-13",
        )

    # Default based on severity_raw
    sev_upper = severity_raw.upper()
    if sev_upper in ("ERROR", "CRITICAL"):
        return (
            "SAST-INJ-001",
            "Static Code Analysis",
            Severity.HIGH,
            7.5,
            cwe_raw or "CWE-200",
            "A05:2021-Security Misconfiguration",
            "SI-10",
        )
    elif sev_upper in ("WARNING", "WARN"):
        return (
            "SAST-INJ-001",
            "Static Code Analysis",
            Severity.MEDIUM,
            5.3,
            cwe_raw or "CWE-200",
            "A05:2021-Security Misconfiguration",
            "SI-10",
        )
    else:
        return (
            "SAST-INJ-001",
            "Static Code Analysis",
            Severity.LOW,
            3.1,
            cwe_raw or "CWE-200",
            "A05:2021-Security Misconfiguration",
            "SI-10",
        )


class SemgrepAdapter(BaseToolAdapter):
    """
    Hybrid tool adapter for Semgrep static AST code scanner.
    Normalizes JSON scan output into canonical SAST-xxx findings.
    """

    approved_version = "1.65.0"
    package_name = "semgrep"

    @property
    def tool_name(self) -> str:
        return "semgrep"

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        """
        Retrieves Semgrep version string via `semgrep --version`.
        """
        path = self.resolve_binary_path(custom_path)
        if not path:
            return None

        returncode, stdout, stderr = await self.execute_command([path, "--version"], timeout=5.0, pre_launch_check=pre_launch_check)
        output = stdout or stderr
        if output:
            first_line = output.splitlines()[0].strip()
            match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", first_line)
            if match:
                return f"semgrep {match.group(1)}"
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
        Executes Semgrep scan: semgrep scan --config auto --json <repo_path>
        Parses JSON results and generates normalized Finding objects.
        """
        findings: List[Finding] = []
        custom_path = getattr(config.adapters, "semgrep_path", None) or getattr(config.adapters, "custom_semgrep_path", None)
        semgrep_path = self.resolve_binary_path(custom_path)

        if not semgrep_path:
            self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.WARNING, "Semgrep binary not found on host. Skipping Semgrep execution.")
            return findings
        managed_check = (lambda: self.verify_managed_binary(semgrep_path)) if kwargs.get("require_managed_binary") else None
        if kwargs.get("require_managed_binary") and not managed_check():
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "Semgrep execution blocked: executable is not a trusted managed package installation.")
            return findings
        if kwargs.get("require_managed_binary") and not await self.ensure_approved_version(custom_path, emit_log, pre_launch_check=managed_check):
            return findings

        repo_path = target.value.strip()
        cmd = [
            semgrep_path,
            "scan",
            "--config", "auto",
            "--json",
            repo_path,
        ]

        await emit_log(LogLevel.INFO, f"Starting Semgrep SAST scan on path '{repo_path}'...")
        returncode, stdout, stderr = await self.execute_command(
            cmd,
            timeout=float(min(60.0, config.timeout_seconds * 6)),
            emit_log=emit_log,
            pre_launch_check=managed_check,
        )

        if not stdout.strip():
            self._record_execution(returncode, stdout, stderr)
            if returncode != 0 and stderr:
                await emit_log(LogLevel.WARNING, f"Semgrep exited with code {returncode}: {stderr.strip()}")
            else:
                await emit_log(LogLevel.INFO, "Semgrep completed with no findings.")
            return findings

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            self._record_execution(returncode, stdout, stderr, parser_error=True)
            await emit_log(LogLevel.ERROR, f"Failed to parse Semgrep JSON output: {e}")
            return findings

        scan_id = kwargs.get("scan_id", "adapter-semgrep")
        results = data.get("results", [])

        for r in results:
            rule_id = r.get("check_id") or "semgrep-rule"
            file_path = r.get("path") or "unknown"
            file_path = safe_workspace_relative_path(file_path, Path(repo_path)) or "untrusted-output"
            start = r.get("start", {})
            line_no = start.get("line", 1)
            col_no = start.get("col", 1)
            extra = r.get("extra", {})
            message = extra.get("message") or f"Semgrep rule {rule_id} triggered."
            severity_raw = extra.get("severity", "WARNING")
            lines_snippet = extra.get("lines", "")
            metadata = extra.get("metadata", {})

            # Extract CWE
            cwe_info = metadata.get("cwe")
            cwe_id = None
            if isinstance(cwe_info, list) and cwe_info:
                cwe_id = str(cwe_info[0]).split(":")[0].strip()
            elif isinstance(cwe_info, str):
                cwe_id = cwe_info.split(":")[0].strip()

            check_id, category, sev, cvss, cwe_resolved, owasp_cat, nist_ctl = map_semgrep_rule(
                rule_id=rule_id,
                message=message,
                severity_raw=severity_raw,
                cwe_raw=cwe_id,
            )

            refs = metadata.get("references", [])
            if isinstance(refs, str):
                refs = [refs]

            evidence = Evidence(
                location=f"{file_path}:{line_no}",
                observed_value=message[:300],
                expected_value="Code adheres to secure development best practices and lacks taint sinks",
                raw_response_snippet=sanitize_sensitive_text(lines_snippet.strip()) if lines_snippet else None,
                line_number=line_no,
                column_number=col_no,
            )

            finding = Finding(
                scan_id=scan_id,
                engine="code_sast",
                source_tool="semgrep",
                check_id=check_id,
                category=category,
                title=f"{rule_id.split('.')[-1].replace('-', ' ').title()} ({rule_id})",
                severity=sev,
                cvss_score=cvss,
                cwe_id=cwe_resolved,
                owasp_category=owasp_cat,
                nist_control=nist_ctl,
                description=message,
                impact="Potential static code vulnerability exposing application to security weaknesses.",
                remediation=extra.get("fix") or f"Review code at {file_path}:{line_no} and apply secure coding patterns.",
                references=refs or [f"https://semgrep.dev/r?q={rule_id}"],
                evidence=evidence,
                fingerprint=calculate_fingerprint(check_id, f"{file_path}:{line_no}", rule_id),
            )

            findings.append(finding)
            await emit_finding(finding)

        self._record_execution(returncode, stdout, stderr, findings_count=len(findings))
        await emit_log(LogLevel.INFO, f"Semgrep scan completed. Generated {len(findings)} findings.")
        return findings
