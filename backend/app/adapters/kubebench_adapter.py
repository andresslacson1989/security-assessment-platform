"""
Kube-bench Tool Adapter for CIS Kubernetes Benchmark Compliance Auditing.
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


class KubeBenchAdapter(BaseToolAdapter):
    """
    Adapter for Aqua Security kube-bench CIS Kubernetes Benchmark checker.
    """
    approved_version = "0.7.0"

    @property
    def tool_name(self) -> str:
        return "kube-bench"

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "version"], timeout=10.0, pre_launch_check=pre_launch_check)
        output = stdout + " " + stderr
        match = re.search(r"\d+\.\d+\.\d+", output)
        if match:
            return f"kube-bench {match.group(0)}"
        return "kube-bench" if code == 0 else None

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

        binary = self.resolve_binary_path(config.adapters.kube_bench_path or config.adapters.custom_kube_bench_path)
        if not binary:
            await emit_log(LogLevel.WARNING, "Kube-bench binary not found. Skipping Kubernetes CIS benchmark audit.")
            return findings

        managed_check = (lambda: self.verify_managed_binary(binary)) if kwargs.get("require_managed_binary") else None
        if kwargs.get("require_managed_binary") and not managed_check():
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "Kube-bench execution blocked: executable is not a trusted managed installation.")
            return findings
        if kwargs.get("require_managed_binary") and not await self.ensure_approved_version(
            config.adapters.kube_bench_path or config.adapters.custom_kube_bench_path,
            emit_log,
            pre_launch_check=managed_check,
        ):
            return findings

        await emit_log(LogLevel.INFO, "Executing Kube-bench CIS Kubernetes Benchmark compliance audit...")
        cmd = [binary, "run", "--json"]

        code, stdout, stderr = await self.execute_command(cmd, timeout=60.0, emit_log=emit_log, pre_launch_check=managed_check)

        if not stdout.strip():
            self._record_execution(code, stdout, stderr)
            await emit_log(LogLevel.WARNING, f"Kube-bench produced no report (exit code {code}).")
            return findings

        try:
            data = json.loads(stdout)
            controls = data.get("Controls", [])
            for control in controls:
                bench_id = control.get("id", "CIS Kubernetes")
                bench_text = control.get("text", "CIS Kubernetes Benchmark")
                tests = control.get("tests", [])

                for test in tests:
                    results = test.get("results", [])
                    for res in results:
                        status = res.get("status", "FAIL").upper()
                        test_number = res.get("test_number", "1.1")
                        test_desc = res.get("test_desc", "Kubernetes Control")
                        remediation = res.get("remediation", "Apply Kubernetes hardening guidelines.")
                        scored = bool(res.get("scored", True))

                        cis_model = CISBenchmarkResult(
                            benchmark_name=f"CIS Kubernetes Benchmark ({bench_id})",
                            section_id=test_number,
                            title=test_desc,
                            status=status,
                            remediation=remediation,
                            scored=scored,
                        )
                        if record_cis_result:
                            record_cis_result(cis_model)

                        if status in ("FAIL", "WARN"):
                            severity = Severity.HIGH if status == "FAIL" else Severity.MEDIUM
                            cvss_score = 7.5 if status == "FAIL" else 5.3

                            evidence = Evidence(
                                location=f"K8s Control {test_number}",
                                observed_value=f"CIS Check {test_number} Failed: {test_desc}",
                                expected_value="Compliant with CIS Kubernetes Benchmark configuration",
                                raw_response_snippet=json.dumps(res, indent=2),
                            )

                            finding = Finding(
                                scan_id=scan_id,
                                engine="infra_iac",
                                source_tool="kube_bench",
                                check_id="K8S-CIS-001",
                                category="Cluster Compliance",
                                title=f"CIS Kubernetes Benchmark [{test_number}]: {test_desc}",
                                severity=severity,
                                cvss_score=cvss_score,
                                cwe_id="CWE-284",
                                description=f"Kube-bench identified a non-compliant Kubernetes control under {test_number}: {test_desc}.",
                                impact="Misconfigured control planes, kubelet flags, or API server configs expose nodes to container escape and cluster takeover.",
                                remediation=remediation,
                                references=["https://github.com/aquasecurity/kube-bench"],
                                evidence=evidence,
                                fingerprint=calculate_fingerprint("K8S-CIS-001", f"K8s-{test_number}", test_desc),
                            )
                            findings.append(finding)
                            await emit_finding(finding)

        except Exception as e:
            self._record_execution(code, stdout, stderr, parser_error=True)
            await emit_log(LogLevel.WARNING, f"Kube-bench output parsing error: {e}")

        self._record_execution(code, stdout, stderr, findings_count=len(findings))
        await emit_log(LogLevel.INFO, f"Kube-bench completed: {len(findings)} CIS Kubernetes benchmark findings reported.")
        return findings
