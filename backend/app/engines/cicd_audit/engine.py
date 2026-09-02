"""
Contract 03, 06 & 08 CI/CD Pipeline Assessment Engine Coordinator.
"""

from __future__ import annotations
from typing import List

from app.core.models import Target, Finding, ScanConfig, TargetType, LogLevel
from app.engines.base import BaseAssessmentEngine, LogCallback, ProgressCallback, FindingCallback
from app.engines.cicd_audit.github_actions_auditor import audit_github_workflows


class CicdAuditAssessmentEngine(BaseAssessmentEngine):
    """
    Coordinator engine for CI/CD Pipeline, GitHub Actions, and Build Supply Chain Security Audits.
    """

    @property
    def name(self) -> str:
        return "cicd_audit"

    @property
    def display_name(self) -> str:
        return "CI/CD Pipeline & Build Security Auditor"

    @property
    def description(self) -> str:
        return (
            "Analyzes CI/CD pipelines (.github/workflows/) for insecure pull_request_target checkout triggers, "
            "unpinned third-party actions (@main/@v1), inline script injection via untrusted github context expressions, "
            "and overly permissive GITHUB_TOKEN write-all permissions."
        )

    def is_applicable(self, target: Target) -> bool:
        """
        Applicable to local repository paths containing CI/CD configuration.
        """
        return target.type == TargetType.LOCAL_PATH

    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        emit_finding: FindingCallback,
        **kwargs,
    ) -> List[Finding]:
        findings: List[Finding] = []
        scan_id = kwargs.get("scan_id", "active")
        repo_path = target.value

        # --- Stage 1: GitHub Actions CI/CD Workflow Audit (0% - 100%) ---
        await emit_progress(20, "Scanning .github/workflows/ for pipeline supply chain and injection flaws...")
        await emit_log(LogLevel.INFO, f"Initiating CI/CD security audit in '{repo_path}'.")

        gha_findings = await audit_github_workflows(repo_path, emit_log=emit_log)
        for f in gha_findings:
            f.scan_id = scan_id
            findings.append(f)
            await emit_finding(f)

        await emit_progress(100, "CI/CD pipeline assessment completed.")
        await emit_log(LogLevel.INFO, f"CI/CD engine completed with {len(findings)} total findings.")

        return findings
