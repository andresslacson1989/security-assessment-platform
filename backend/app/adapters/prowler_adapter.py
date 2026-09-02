"""
Prowler Tool Adapter for Multi-Cloud CIS Foundations Benchmark & Posture Auditing.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md (Section 4.2)
"""

from __future__ import annotations
import json
import logging
import os
import re
from typing import Optional, List, Callable, Awaitable, Dict, Any

from app.core.models import (
    Target, Finding, Evidence, ScanConfig, LogLevel, Severity,
    calculate_fingerprint, CISBenchmarkResult, NormalizedExecutionState
)
from app.adapters.base_adapter import BaseToolAdapter

logger = logging.getLogger("cyberassess.adapters.prowler")


class ProwlerAdapter(BaseToolAdapter):
    """
    Adapter for Prowler multi-cloud security assessment, audit, and CIS benchmark engine.
    """
    approved_version = "4.1.0"
    package_name = "prowler"

    @property
    def tool_name(self) -> str:
        return "prowler"

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "-v"], timeout=10.0, pre_launch_check=pre_launch_check)
        output = stdout + " " + stderr
        match = re.search(r"\d+\.\d+\.\d+", output)
        if match:
            return f"prowler {match.group(0)}"
        return "prowler" if code == 0 else None

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

        binary = self.resolve_binary_path(config.adapters.prowler_path or config.adapters.custom_prowler_path)
        if not binary:
            await emit_log(LogLevel.WARNING, "Prowler binary not found. Skipping multi-cloud CIS benchmark audit.")
            return findings

        if kwargs.get("require_managed_binary"):
            from app.core.ssrf_protector import validate_validated_target

            try:
                validated_target = validate_validated_target(kwargs.get("validated_target"))
            except Exception:
                self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
                await emit_log(LogLevel.ERROR, "Prowler execution blocked: a gateway-issued cloud ValidatedTarget is required.")
                return findings

            target_type = getattr(validated_target.target_type, "value", str(validated_target.target_type))
            if target_type not in {"CLOUD_ACCOUNT", "KUBERNETES_CLUSTER"}:
                self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
                await emit_log(LogLevel.ERROR, "Prowler execution blocked: only cloud-account or Kubernetes targets are supported.")
                return findings

        managed_check = (lambda: self.verify_managed_binary(binary)) if kwargs.get("require_managed_binary") else None
        if kwargs.get("require_managed_binary") and not managed_check():
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "Prowler execution blocked: executable is not a trusted managed installation.")
            return findings
        if kwargs.get("require_managed_binary") and not await self.ensure_approved_version(
            config.adapters.prowler_path or config.adapters.custom_prowler_path,
            emit_log,
            pre_launch_check=managed_check,
        ):
            return findings

        await emit_log(LogLevel.INFO, "Executing Prowler CIS Cloud Foundations compliance assessment...")
        cmd = [binary, "aws", "-M", "json", "--quiet"]

        code, stdout, stderr = await self.execute_command(cmd, timeout=60.0, emit_log=emit_log, pre_launch_check=managed_check)

        if not stdout.strip():
            self._record_execution(code, stdout, stderr)
            await emit_log(LogLevel.WARNING, f"Prowler produced no report (exit code {code}).")
            return findings

        try:
            items = []
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        items.append(json.loads(line))
                    except Exception as exc:
                        logger.debug("Prowler result item could not be normalized: error_type=%s", type(exc).__name__)

            for item in items:
                status = item.get("Status", "FAIL").upper()
                check_title = item.get("CheckTitle", "CIS Cloud Check")
                check_id = item.get("CheckID", "cloud_check")
                service_name = item.get("ServiceName", "Cloud Infrastructure")
                resource_id = item.get("ResourceId", "Cloud Resource")
                remediation = item.get("Remediation", {}).get("Recommendation", {}).get("Text", "Review cloud configuration.")
                compliance = item.get("Compliance", {})

                cis_model = CISBenchmarkResult(
                    benchmark_name="CIS Cloud Foundations Benchmark",
                    section_id=check_id,
                    title=check_title,
                    status=status,
                    remediation=remediation,
                    scored=True,
                )
                if record_cis_result:
                    record_cis_result(cis_model)

                if status == "FAIL":
                    evidence = Evidence(
                        location=f"{service_name}:{resource_id}",
                        observed_value=f"Failed CIS Check: {check_title}",
                        expected_value=f"Compliant with CIS standard ({remediation[:100]})",
                        raw_response_snippet=json.dumps(item, indent=2)[:500],
                    )

                    finding = Finding(
                        scan_id=scan_id,
                        engine="infra_iac",
                        source_tool="prowler",
                        check_id="CLOUD-CIS-001",
                        category="Cloud Compliance",
                        title=f"CIS Cloud Benchmark Failure: {check_title}",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        cwe_id="CWE-284",
                        description=f"Prowler CIS benchmark check `{check_id}` failed for resource `{resource_id}` on `{service_name}`.",
                        impact="Non-compliant cloud configurations can allow data leakage, lateral movement, or unauthorized API access.",
                        remediation=remediation,
                        references=["https://github.com/prowler-cloud/prowler"],
                        evidence=evidence,
                        fingerprint=calculate_fingerprint("CLOUD-CIS-001", f"{service_name}:{resource_id}", check_id),
                    )
                    findings.append(finding)
                    await emit_finding(finding)

        except Exception as e:
            self._record_execution(code, stdout, stderr, parser_error=True)
            await emit_log(LogLevel.WARNING, f"Prowler output parsing error: {e}")

        self._record_execution(code, stdout, stderr, findings_count=len(findings))
        await emit_log(LogLevel.INFO, f"Prowler completed: {len(findings)} CIS cloud compliance failures reported.")
        return findings
