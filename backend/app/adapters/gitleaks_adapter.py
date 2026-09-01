"""
Contract 03 (Section 4.2), Contract 06 (Section 2) & Contract 08 (Section 8.7) Gitleaks Tool Adapter.
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
    mask_secret,
    calculate_fingerprint,
    NormalizedExecutionState,
    sanitize_sensitive_text,
)
from app.adapters.base_adapter import BaseToolAdapter
from app.core.path_sandbox import safe_workspace_relative_path


class GitleaksAdapter(BaseToolAdapter):
    """
    Hybrid tool adapter for Gitleaks dedicated git history and secret scanner.
    Normalizes JSON findings with mandatory token masking into canonical SAST-SEC-xxx and SAST-GIT-001 findings.
    """
    approved_version = "8.18.2"

    @property
    def tool_name(self) -> str:
        return "gitleaks"

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        """
        Retrieves Gitleaks version string via `gitleaks version`.
        """
        path = self.resolve_binary_path(custom_path)
        if not path:
            return None

        returncode, stdout, _ = await self.execute_command([path, "version"], timeout=5.0, pre_launch_check=pre_launch_check)
        if stdout:
            match = re.search(r"(\d+\.\d+(\.\d+)?)", stdout)
            if match:
                return f"Gitleaks {match.group(1)}"
            return stdout.strip().splitlines()[0]
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
        Executes Gitleaks against local repository path.
        """
        findings: List[Finding] = []
        try:
            custom_path = getattr(config.adapters, "gitleaks_path", None) or getattr(config.adapters, "custom_gitleaks_path", None)
            gitleaks_path = self.resolve_binary_path(custom_path)

            if not gitleaks_path:
                self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
                await emit_log(LogLevel.WARNING, "Gitleaks binary not found on host. Skipping Gitleaks execution.")
                return findings

            repo_path = target.value.strip()
            if not os.path.isdir(repo_path):
                self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
                await emit_log(LogLevel.WARNING, f"Gitleaks requires a directory path, received '{repo_path}'.")
                return findings

            cmd = [
                gitleaks_path,
                "detect",
                "--source", repo_path,
                "--report-format", "json",
                "--report-path", "-",
                "--no-banner",
            ]

            managed_check = (lambda: self.verify_managed_binary(gitleaks_path)) if kwargs.get("require_managed_binary") else None
            if kwargs.get("require_managed_binary") and not managed_check():
                self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
                await emit_log(LogLevel.ERROR, "Gitleaks execution blocked: executable is not a trusted managed installation.")
                return findings
            if kwargs.get("require_managed_binary") and not await self.ensure_approved_version(custom_path, emit_log, pre_launch_check=managed_check):
                return findings

            await emit_log(LogLevel.INFO, f"Starting Gitleaks secret detection on '{repo_path}'...")
            returncode, stdout, stderr = await self.execute_command(
                cmd,
                timeout=float(min(60.0, config.timeout_seconds * 6)),
                emit_log=emit_log,
                pre_launch_check=managed_check,
            )

            if not stdout.strip():
                self._record_execution(returncode, stdout, stderr)
                if returncode not in (0, 1):  # Gitleaks exits with 1 when leaks are found
                    await emit_log(LogLevel.WARNING, f"Gitleaks finished with exit code {returncode}: {stderr[:200]}")
                return findings

            try:
                leaks = json.loads(stdout)
                if isinstance(leaks, list):
                    for leak in leaks:
                        rule_id = leak.get("RuleID", "generic-api-key")
                        description = leak.get("Description", "Hardcoded Secret Identified")
                        file_path = safe_workspace_relative_path(leak.get("File", "unknown"), Path(repo_path)) or "untrusted-output"
                        start_line = leak.get("StartLine", 1)
                        raw_secret = leak.get("Secret", "")
                        commit = leak.get("Commit", "")

                        masked_value = mask_secret(raw_secret) if raw_secret else "********"
                        check_id = "SAST-GIT-001" if commit else "SAST-SEC-001"
                        
                        if "aws" in rule_id.lower():
                            check_id = "SAST-SEC-001"
                        elif "github" in rule_id.lower():
                            check_id = "SAST-SEC-002"
                        elif "stripe" in rule_id.lower():
                            check_id = "SAST-SEC-003"
                        elif "private" in rule_id.lower() or "rsa" in rule_id.lower() or "key" in rule_id.lower():
                            check_id = "SAST-SEC-004"

                        location_str = f"{file_path}:{start_line}"
                        if commit:
                            location_str += f" (Commit: {commit[:8]})"

                        evidence = Evidence(
                            location=location_str,
                            observed_value=masked_value,
                            expected_value="No hardcoded API credentials or cryptographic keys in source code",
                            raw_response_snippet=sanitize_sensitive_text(f"Rule: {rule_id}\nFile: {file_path}:{start_line}\nMasked Secret: {masked_value}"),
                            line_number=start_line,
                        )

                        f = Finding(
                            scan_id=kwargs.get("scan_id", "manual"),
                            engine="code_sast",
                            source_tool="gitleaks",
                            check_id=check_id,
                            category="Hardcoded Secrets",
                            title=f"Hardcoded Secret ({rule_id}) Detected by Gitleaks",
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            cwe_id="CWE-798",
                            owasp_category="A07:2021-Identification and Authentication Failures",
                            nist_control="IA-5, SC-28",
                            description=description,
                            impact="Unauthorized API access, system compromise, or data breach.",
                            remediation="Revoke exposed credentials immediately and remove secret from source and commit history.",
                            remediation_code_snippet="# Load from environment variable:\nimport os\nAPI_KEY = os.environ.get('API_KEY')",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
                            evidence=evidence,
                            fingerprint=calculate_fingerprint(check_id, location_str, masked_value),
                        )
                        findings.append(f)
                        await emit_finding(f)
            except Exception as parse_err:
                self._record_execution(returncode, stdout, stderr, parser_error=True)
                await emit_log(LogLevel.WARNING, f"Failed to parse Gitleaks JSON report: {parse_err}")

            self._record_execution(returncode, stdout, stderr, findings_count=len(findings))

        except Exception as err:
            self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.WARNING, f"Gitleaks execution error: {err}")

        return findings
