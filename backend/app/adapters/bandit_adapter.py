"""
Contract 03 (Section 4.2), Contract 06 (Section 2) & Contract 08 (Section 8.8) Bandit Tool Adapter.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import json
import os
import re
from pathlib import Path
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


class BanditAdapter(BaseToolAdapter):
    """
    Hybrid tool adapter for Bandit Python AST static security linter.
    Normalizes JSON findings into canonical SAST-CRY-xxx and SAST-INJ-xxx findings.
    """
    approved_version = "1.7.8"
    package_name = "bandit"

    @property
    def tool_name(self) -> str:
        return "bandit"

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        """
        Retrieves Bandit version string via `bandit --version`.
        """
        path = self.resolve_binary_path(custom_path)
        if not path:
            return None

        returncode, stdout, stderr = await self.execute_command([path, "--version"], timeout=5.0, pre_launch_check=pre_launch_check)
        output = stdout.strip() or stderr.strip()
        if output:
            match = re.search(r"(\d+\.\d+(\.\d+)?)", output)
            if match:
                return f"Bandit {match.group(1)}"
            return output.splitlines()[0]
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
        Executes Bandit against Python source code repository.
        """
        findings: List[Finding] = []
        custom_path = getattr(config.adapters, "bandit_path", None) or getattr(config.adapters, "custom_bandit_path", None)
        bandit_path = self.resolve_binary_path(custom_path)

        if not bandit_path:
            self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.WARNING, "Bandit binary not found on host. Skipping Bandit execution.")
            return findings

        managed_check = (lambda: self.verify_managed_binary(bandit_path)) if kwargs.get("require_managed_binary") else None
        if kwargs.get("require_managed_binary") and not managed_check():
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "Bandit execution blocked: executable is not a trusted managed package installation.")
            return findings
        if kwargs.get("require_managed_binary") and not await self.ensure_approved_version(custom_path, emit_log, pre_launch_check=managed_check):
            return findings

        repo_path = target.value.strip()
        if not os.path.exists(repo_path):
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.WARNING, f"Target path '{repo_path}' does not exist for Bandit scan.")
            return findings

        cmd = [
            bandit_path,
            "-r", repo_path,
            "-f", "json",
            "-q",
        ]

        await emit_log(LogLevel.INFO, f"Starting Bandit Python AST security linter on '{repo_path}'...")
        returncode, stdout, stderr = await self.execute_command(
            cmd,
            timeout=float(min(60.0, config.timeout_seconds * 6)),
            emit_log=emit_log,
            pre_launch_check=managed_check,
        )

        if not stdout.strip():
            self._record_execution(returncode, stdout, stderr)
            if returncode not in (0, 1):
                await emit_log(LogLevel.WARNING, f"Bandit finished with exit code {returncode}: {stderr[:200]}")
            return findings

        try:
            data = json.loads(stdout)
            results = data.get("results", [])

            for item in results:
                test_id = item.get("test_id", "")
                issue_text = item.get("issue_text", "Insecure Python code pattern")
                filename = safe_workspace_relative_path(item.get("filename", "unknown"), Path(repo_path)) or "untrusted-output"
                line_number = item.get("line_number", 1)
                code_snippet = sanitize_sensitive_text(item.get("code", "")) or ""
                issue_sev = item.get("issue_severity", "MEDIUM").upper()

                severity_map = {
                    "HIGH": (Severity.HIGH, 8.5),
                    "MEDIUM": (Severity.MEDIUM, 6.0),
                    "LOW": (Severity.LOW, 3.5),
                }
                sev, cvss = severity_map.get(issue_sev, (Severity.MEDIUM, 6.0))

                check_id = "SAST-CRY-001"
                category = "Cryptographic Failures"
                cwe = "CWE-327"

                if "B303" in test_id or "md5" in issue_text.lower() or "sha1" in issue_text.lower():
                    check_id = "SAST-CRY-001"
                    category = "Cryptographic Failures"
                    cwe = "CWE-328"
                elif "B602" in test_id or "B603" in test_id or "subprocess" in issue_text.lower() or "shell" in issue_text.lower():
                    check_id = "SAST-INJ-002"
                    category = "Command Injection"
                    cwe = "CWE-78"
                    sev = Severity.HIGH
                    cvss = 8.8
                elif "B608" in test_id or "sql" in issue_text.lower():
                    check_id = "SAST-TAINT-001"
                    category = "SQL Injection"
                    cwe = "CWE-89"
                    sev = Severity.CRITICAL
                    cvss = 9.8
                elif "B105" in test_id or "B106" in test_id or "password" in issue_text.lower():
                    check_id = "SAST-SEC-005"
                    category = "Hardcoded Secrets"
                    cwe = "CWE-798"
                    sev = Severity.HIGH
                    cvss = 7.5

                evidence = Evidence(
                    location=f"{filename}:{line_number}",
                    observed_value=issue_text,
                    expected_value="Secure Python coding standard without insecure functions or raw string formatting",
                    raw_response_snippet=code_snippet,
                    line_number=line_number,
                )

                f = Finding(
                    scan_id=kwargs.get("scan_id", "manual"),
                    engine="code_sast",
                    source_tool="bandit",
                    check_id=check_id,
                    category=category,
                    title=f"Bandit ({test_id}): {issue_text[:80]}",
                    severity=sev,
                    cvss_score=cvss,
                    cwe_id=cwe,
                    owasp_category="A03:2021-Injection" if "INJ" in check_id else "A02:2021-Cryptographic Failures",
                    nist_control="SI-10, SC-13",
                    description=f"Bandit Python AST security analysis detected {issue_text} in {filename}:{line_number}.",
                    impact="Security weakness that could lead to code execution, data exposure, or cryptographic failure.",
                    remediation="Refactor code to use safe standard library methods, parameterized queries, or modern cryptography primitives.",
                    remediation_code_snippet=code_snippet,
                    references=["https://bandit.readthedocs.io/"],
                    evidence=evidence,
                    fingerprint=calculate_fingerprint(check_id, f"{filename}:{line_number}", issue_text),
                )
                findings.append(f)
                await emit_finding(f)

        except Exception as e:
            self._record_execution(returncode, stdout, stderr, parser_error=True)
            await emit_log(LogLevel.WARNING, f"Failed to parse Bandit JSON results: {str(e)}")

        self._record_execution(returncode, stdout, stderr, findings_count=len(findings))

        return findings
