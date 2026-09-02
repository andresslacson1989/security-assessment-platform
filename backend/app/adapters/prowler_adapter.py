"""
Prowler Tool Adapter for Multi-Cloud CIS Foundations Benchmark & Posture Auditing.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md (Section 4.2)
"""

from __future__ import annotations
import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Optional, List, Callable, Awaitable, Dict, Any

from app.core.models import (
    Target, Finding, Evidence, ScanConfig, LogLevel, Severity,
    calculate_fingerprint, CISBenchmarkResult, NormalizedExecutionState,
    CloudCredentialEnvelope, utc_now,
)
from app.adapters.base_adapter import BaseToolAdapter

logger = logging.getLogger("cyberassess.adapters.prowler")


class ProwlerAdapter(BaseToolAdapter):
    """
    Adapter for Prowler multi-cloud security assessment, audit, and CIS benchmark engine.
    """
    approved_version = "4.1.0"
    package_name = "prowler"

    @staticmethod
    def _parse_asff_report(payload: str) -> List[Dict[str, Any]]:
        """Parse the bounded ASFF envelope emitted by assured Prowler runs."""
        try:
            document = json.loads(payload)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("Prowler ASFF report is not valid JSON") from exc
        if not isinstance(document, dict) or not isinstance(document.get("Findings"), list):
            raise ValueError("Prowler ASFF report must contain a Findings array")

        findings = document["Findings"]
        required = ("Title", "Severity", "Compliance", "Remediation")
        for item in findings:
            if not isinstance(item, dict) or any(key not in item for key in required):
                raise ValueError("Prowler ASFF finding is missing required fields")
            if not isinstance(item["Title"], str) or not item["Title"].strip():
                raise ValueError("Prowler ASFF finding has an invalid Title")
            severity = item["Severity"]
            compliance = item["Compliance"]
            remediation = item["Remediation"]
            if (
                not isinstance(severity, dict)
                or not isinstance(severity.get("Label"), str)
                or not severity["Label"].strip()
                or not isinstance(compliance, dict)
                or not isinstance(compliance.get("Status"), str)
                or not compliance["Status"].strip()
                or not isinstance(remediation, dict)
                or not isinstance(remediation.get("Recommendation"), dict)
                or not isinstance(remediation["Recommendation"].get("Text"), str)
                or not remediation["Recommendation"]["Text"].strip()
            ):
                raise ValueError("Prowler ASFF finding has an invalid required schema field")
        return findings

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
            if not validated_target.authorization_context.get("active_probing_granted"):
                self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
                await emit_log(LogLevel.ERROR, "Prowler execution blocked: explicit active cloud-audit authorization is required.")
                return findings

            envelope = kwargs.get("cloud_credentials")
            if not isinstance(envelope, CloudCredentialEnvelope):
                self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
                await emit_log(LogLevel.ERROR, "Prowler execution blocked: a typed tenant-scoped credential envelope is required.")
                return findings
            if (
                envelope.organization_id != validated_target.organization_id
                or envelope.asset_id != validated_target.asset_id
                or envelope.provider != validated_target.authorization_context.get("cloud_provider")
                or envelope.expires_at.tzinfo is None
                or envelope.expires_at <= utc_now()
            ):
                self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
                await emit_log(LogLevel.ERROR, "Prowler execution blocked: credential envelope scope or expiry is invalid.")
                return findings
            credentials = envelope.credentials
            allowed_credentials = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}
            if not isinstance(credentials, dict) or not {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}.issubset(credentials):
                self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
                await emit_log(LogLevel.ERROR, "Prowler execution blocked: scoped read-only cloud credentials are required.")
                return findings
            if set(credentials) - allowed_credentials or any(
                not isinstance(value, str) or not value or any(ord(char) < 32 for char in value)
                for value in credentials.values()
            ):
                self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
                await emit_log(LogLevel.ERROR, "Prowler execution blocked: cloud credential envelope is invalid.")
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
        output_path = None
        report_payload = None
        temp_output_dir = None
        execution_env = None
        sensitive_env_keys = None
        if kwargs.get("require_managed_binary"):
            provider = validated_target.authorization_context.get("cloud_provider")
            temp_output_dir = tempfile.TemporaryDirectory(prefix="cyberassess-prowler-")
            output_path = str(Path(temp_output_dir.name) / "prowler-asff.json")
            cmd = [binary, provider, "-M", "json-asff", "--output-filename", output_path, "--quiet"]
            execution_env = dict(credentials)
            sensitive_env_keys = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}
        else:
            cmd = [binary, "aws", "-M", "json", "--quiet"]

        try:
            code, stdout, stderr = await self.execute_command(
                cmd,
                timeout=120.0 if kwargs.get("require_managed_binary") else 60.0,
                emit_log=emit_log,
                pre_launch_check=managed_check,
                env=execution_env,
                sensitive_env_keys=sensitive_env_keys,
                max_output_bytes=10 * 1024 * 1024,
            )
            if output_path:
                try:
                    report = Path(output_path)
                    if report.is_file() and report.stat().st_size <= 10 * 1024 * 1024:
                        report_payload = report.read_text(encoding="utf-8")
                        stdout = stdout + "\n" + report_payload
                except (OSError, UnicodeError):
                    await emit_log(LogLevel.WARNING, "Prowler report file could not be read; retaining supervised stdout only.")
        finally:
            if execution_env is not None:
                execution_env.clear()
            if temp_output_dir is not None:
                temp_output_dir.cleanup()

        if not stdout.strip():
            self._record_execution(code, stdout, stderr)
            await emit_log(LogLevel.WARNING, f"Prowler produced no report (exit code {code}).")
            return findings

        try:
            if kwargs.get("require_managed_binary"):
                if not report_payload:
                    raise ValueError("Prowler ASFF report was not produced")
                items = self._parse_asff_report(report_payload)
            else:
                items = []
                for line in stdout.splitlines():
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            items.append(json.loads(line))
                        except Exception as exc:
                            logger.debug("Prowler result item could not be normalized: error_type=%s", type(exc).__name__)

            for item in items:
                status = item.get("Compliance", {}).get("Status", item.get("Status", "FAIL")).upper()
                check_title = item.get("Title", item.get("CheckTitle", "CIS Cloud Check"))
                severity_value = item.get("Severity", {})
                severity_label = (
                    severity_value.get("Label", "HIGH")
                    if isinstance(severity_value, dict)
                    else severity_value or "HIGH"
                ).upper()
                finding_severity = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                    "INFORMATIONAL": Severity.INFO,
                    "INFO": Severity.INFO,
                }.get(severity_label, Severity.HIGH)
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

                if status in {"FAIL", "FAILED", "FAILURE"}:
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
                        severity=finding_severity,
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
