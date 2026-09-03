"""
Dockle Tool Adapter for CIS Docker Container Image Hardening Auditing.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md (Section 4.2)
"""

from __future__ import annotations
import json
import os
import re
from typing import Optional, List, Callable, Awaitable, Dict, Any

from app.core.models import (
    Target, Finding, Evidence, ScanConfig, LogLevel, Severity,
    calculate_fingerprint, CISBenchmarkResult, NormalizedExecutionState
)
from app.adapters.base_adapter import BaseToolAdapter


class DockleAdapter(BaseToolAdapter):
    """
    Adapter for Goodwithtech Dockle container image linter for CIS Docker Benchmark compliance.
    """
    approved_version = "0.4.14"

    @property
    def tool_name(self) -> str:
        return "dockle"

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "--version"], timeout=10.0, pre_launch_check=pre_launch_check)
        output = stdout + " " + stderr
        match = re.search(r"\d+\.\d+\.\d+", output)
        if match:
            return f"dockle {match.group(0)}"
        return "dockle" if code == 0 else None

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
        record_cis_result: Optional[Callable[[CISBenchmarkResult], None]] = kwargs.get("record_cis_result")

        binary = self.resolve_binary_path(config.adapters.dockle_path or config.adapters.custom_dockle_path)
        if not binary:
            await emit_log(LogLevel.WARNING, "Dockle binary not found. Skipping CIS Docker image audit.")
            return findings

        managed_check = (lambda: self.verify_managed_binary(binary)) if kwargs.get("require_managed_binary") else None
        if kwargs.get("require_managed_binary") and not managed_check():
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "Dockle execution blocked: executable is not a trusted managed installation.")
            return findings
        if kwargs.get("require_managed_binary") and not await self.ensure_approved_version(
            config.adapters.dockle_path or config.adapters.custom_dockle_path,
            emit_log,
            pre_launch_check=managed_check,
        ):
            return findings

        target_image = target.value
        await emit_log(LogLevel.INFO, f"Executing Dockle CIS container security linter on: {target_image}")
        cmd = [binary, "-f", "json", "--exit-code", "0", target_image]

        code, stdout, stderr = await self.execute_command(cmd, timeout=60.0, emit_log=emit_log, pre_launch_check=managed_check)

        if not stdout.strip():
            self._record_execution(code, stdout, stderr)
            await emit_log(LogLevel.WARNING, f"Dockle produced no report (exit code {code}).")
            return findings

        try:
            data = json.loads(stdout)
            details = data.get("details", [])
            for item in details:
                code_id = item.get("code", "CIS-DI-0001")
                title = item.get("title", "CIS Docker Benchmark Violation")
                level = item.get("level", "WARN").upper()
                alerts = item.get("alerts", [])
                alert_text = "; ".join(alerts) if alerts else title

                status = "FAIL" if level in ("FATAL", "WARN") else "INFO"
                remediation = f"Follow CIS Docker Benchmark recommendation for {code_id}: resolve {title}."

                cis_model = CISBenchmarkResult(
                    benchmark_name="CIS Docker Benchmark",
                    section_id=code_id,
                    title=title,
                    status=status,
                    remediation=remediation,
                    scored=True,
                )
                if record_cis_result:
                    record_cis_result(cis_model)

                if level in ("FATAL", "WARN"):
                    canonical_id, cwe_id, severity, cvss_score = {
                        "CIS-DI-0001": ("IAC-DOCKER-001", "CWE-250", Severity.HIGH, 7.5),
                        "CIS-DI-0005": ("IAC-DOCKER-002", "CWE-522", Severity.CRITICAL, 9.0),
                    }.get(
                        code_id,
                        ("IAC-DOCKER-001", "CWE-250", Severity.HIGH if level == "FATAL" else Severity.MEDIUM, 7.5 if level == "FATAL" else 5.3),
                    )

                    evidence = Evidence(
                        location=f"{target_image} ({code_id})",
                        observed_value=f"Dockle Check {code_id} Alert: {alert_text}",
                        expected_value="Adhere to CIS Docker container image best practices (non-root, no SUID bits, clean cache)",
                        raw_response_snippet=json.dumps(item, indent=2),
                    )

                    finding = Finding(
                        scan_id=scan_id,
                        engine="infra_iac",
                        source_tool="dockle",
                        check_id=canonical_id,
                        category="Container Hardening",
                        title=f"CIS Docker Benchmark [{code_id}]: {title}",
                        severity=severity,
                        cvss_score=cvss_score,
                        cwe_id=cwe_id,
                        description=f"Dockle identified a CIS Docker container violation `{code_id}` in image `{target_image}`: {alert_text}.",
                        impact="Running containers as root or with unnecessary SUID binaries increases the blast radius of container escapes.",
                        remediation=remediation,
                        references=["https://github.com/goodwithtech/dockle"],
                        evidence=evidence,
                        fingerprint=calculate_fingerprint(canonical_id, target_image, code_id),
                    )
                    findings.append(finding)
                    await emit_finding(finding)

        except Exception as e:
            self._record_execution(code, stdout, stderr, parser_error=True)
            await emit_log(LogLevel.WARNING, f"Dockle output parsing error: {e}")

        self._record_execution(code, stdout, stderr, findings_count=len(findings))
        await emit_log(LogLevel.INFO, f"Dockle completed: {len(findings)} CIS container image findings reported.")
        return findings
