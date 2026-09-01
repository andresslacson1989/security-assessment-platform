"""
Schemathesis Tool Adapter for Property-Based API Contract & Fuzz Testing.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md (Section 4.2)
"""

from __future__ import annotations
import json
import re
from typing import Optional, List, Callable, Awaitable, Dict, Any

from app.core.models import (
    Target, Finding, Evidence, ScanConfig, LogLevel, Severity,
    calculate_fingerprint, NormalizedExecutionState
)
from app.adapters.base_adapter import BaseToolAdapter
from app.core.ssrf_protector import bind_url_to_validated_target

APPROVED_VERSION = "3.20.0"


class SchemathesisAdapter(BaseToolAdapter):
    """
    Adapter for Schemathesis property-based OpenAPI/GraphQL contract fuzzer.
    """

    def __init__(self):
        super().__init__()
        self.approved_version = APPROVED_VERSION
        self.last_execution_state = NormalizedExecutionState.COMPLETED_NO_FINDINGS

    @property
    def tool_name(self) -> str:
        return "schemathesis"

    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "--version"], timeout=10.0)
        output = stdout + " " + stderr
        match = re.search(r"\d+\.\d+\.\d+", output)
        if match:
            return f"schemathesis {match.group(0)}"
        return "schemathesis" if code == 0 else None

    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
        **kwargs,
    ) -> List[Finding]:
        findings: List[Finding] = []
        self.last_execution_state = NormalizedExecutionState.COMPLETED_NO_FINDINGS
        scan_id = kwargs.get("scan_id", "local-scan")

        binary = self.resolve_binary_path(config.adapters.schemathesis_path or config.adapters.custom_schemathesis_path)
        if not binary:
            self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.WARNING, "Schemathesis binary not found. Skipping API contract fuzzing.")
            return findings

        if not await self.ensure_approved_version(config.adapters.schemathesis_path or config.adapters.custom_schemathesis_path, emit_log):
            return findings

        target_url = target.value
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"
        host_header = None
        if kwargs.get("validated_target") is not None:
            target_url, host_header = bind_url_to_validated_target(target_url, kwargs["validated_target"])

        # Schema detection (e.g. /openapi.json, /swagger.json, /api-docs)
        schema_url = target_url
        if not (schema_url.endswith(".json") or schema_url.endswith(".yaml") or "openapi" in schema_url):
            schema_url = f"{target_url.rstrip('/')}/openapi.json"

        await emit_log(LogLevel.INFO, f"Executing Schemathesis API contract audit against: {schema_url}")
        cmd = [
            binary, "run", schema_url,
            "--hypothesis-max-examples=10",
            "--validate-schema=true",
            "--checks=not_a_server_error,status_code_conformance,content_type_conformance",
            "--report-format=json"
        ]
        if host_header:
            cmd.extend(["--header", f"Host: {host_header}"])

        code, stdout, stderr = await self.execute_command(cmd, timeout=60.0, emit_log=emit_log)

        # Parse JSON report if available, or regex parse stdout
        try:
            if stdout.strip().startswith("{"):
                report = json.loads(stdout)
                errors = report.get("errors", []) or report.get("failures", [])
                for err in errors:
                    title = err.get("message") or err.get("title") or "API Schema Contract Violation"
                    endpoint = err.get("endpoint") or target_url
                    method = err.get("method", "GET")
                    reproduction = err.get("code_sample") or f"curl -X {method} '{endpoint}'"

                    evidence = Evidence(
                        location=f"{method} {endpoint}",
                        observed_value=str(err.get("observed") or "Server 500 error / schema violation"),
                        expected_value="API must conform to OpenAPI specification with no unhandled 500 crashes",
                        raw_response_snippet=json.dumps(err, indent=2),
                    )
                    finding = Finding(
                        scan_id=scan_id,
                        engine="web_dast",
                        source_tool="schemathesis",
                        check_id="API-SCHEMA-001",
                        category="API Security",
                        title=f"API Contract Failure: {title}",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        cwe_id="CWE-20",
                        description=f"Schemathesis fuzzing revealed an unhandled server error or schema contract discrepancy on `{method} {endpoint}`.",
                        impact="Unhandled input edge cases can lead to Denial of Service (DoS) or unexpected data corruption.",
                        remediation="Validate all request parameters and payloads against the schema before processing, and catch all exceptions gracefully.",
                        references=["https://schemathesis.readthedocs.io/"],
                        evidence=evidence,
                        reproduction_curl=reproduction,
                        fingerprint=calculate_fingerprint("API-SCHEMA-001", f"{method} {endpoint}", title),
                    )
                    findings.append(finding)
                    await emit_finding(finding)
        except Exception:
            self.last_execution_state = NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING
            pass

        # Regex fallback for text output
        if "FAILED" in stdout or "ServerError" in stdout:
            for match in re.finditer(r"(?:FAIL|ERROR):\s+(GET|POST|PUT|DELETE)\s+([^\s]+)\s+->\s+([^\n]+)", stdout):
                method, path, detail = match.groups()
                evidence = Evidence(
                    location=f"{method} {path}",
                    observed_value=detail.strip(),
                    expected_value="2xx / 4xx valid response conforming to API contract",
                    raw_response_snippet=stdout[:500],
                )
                finding = Finding(
                    scan_id=scan_id,
                    engine="web_dast",
                    source_tool="schemathesis",
                    check_id="API-SCHEMA-001",
                    category="API Security",
                    title=f"API Schema Violation on {method} {path}",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    cwe_id="CWE-20",
                    description=f"Schemathesis identified an API contract failure on {method} {path}: {detail.strip()}",
                    impact="Server crashes and unhandled exceptions violate API integrity.",
                    remediation="Add strict schema validation and sanitization for all input parameters.",
                    references=["https://schemathesis.readthedocs.io/"],
                    evidence=evidence,
                    reproduction_curl=f"curl -X {method} '{target_url.rstrip('/')}{path}'",
                    fingerprint=calculate_fingerprint("API-SCHEMA-001", f"{method} {path}", detail),
                )
                findings.append(finding)
                await emit_finding(finding)

        await emit_log(LogLevel.INFO, f"Schemathesis finished: {len(findings)} contract issues identified.")
        if code != 0:
            self.last_execution_state = NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING if stdout.strip() else (NormalizedExecutionState.EXECUTION_TIMED_OUT if "timed out" in stderr.lower() else NormalizedExecutionState.TOOL_EXECUTION_FAILED)
        elif findings:
            self.last_execution_state = NormalizedExecutionState.COMPLETED_WITH_FINDINGS
        return findings
