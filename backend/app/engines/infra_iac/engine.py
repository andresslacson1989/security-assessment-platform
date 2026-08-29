"""
Contract 03, 06 & 08 Infrastructure-as-Code & Container Security Engine Coordinator.
"""

from __future__ import annotations
from typing import List

from app.core.models import Target, Finding, ScanConfig, TargetType, LogLevel
from app.engines.base import BaseAssessmentEngine, LogCallback, ProgressCallback, FindingCallback
from app.engines.infra_iac.dockerfile_auditor import audit_dockerfiles
from app.engines.infra_iac.compose_auditor import audit_compose_files
from app.engines.infra_iac.k8s_manifest_auditor import audit_k8s_manifests
from app.engines.infra_iac.terraform_auditor import audit_terraform_files


class InfraIacAssessmentEngine(BaseAssessmentEngine):
    """
    Coordinator engine for Container Hardening, Docker Compose, Kubernetes, and Terraform IaC security audits.
    """

    @property
    def name(self) -> str:
        return "infra_iac"

    @property
    def display_name(self) -> str:
        return "Infrastructure-as-Code & Container Auditor"

    @property
    def description(self) -> str:
        return (
            "Audits Dockerfiles (root user, unpinned base images, build secrets), Docker Compose "
            "(privileged mode, socket mounts, exposed DB ports), Kubernetes manifests (host namespaces, "
            "allowPrivilegeEscalation, resource limits), and Terraform files (public S3, 0.0.0.0/0 SSH, IAM wildcards)."
        )

    def is_applicable(self, target: Target) -> bool:
        """
        Applicable to Dockerfiles, IaC manifests, and local repository directories.
        """
        return target.type in (TargetType.DOCKERFILE, TargetType.IAC_MANIFEST, TargetType.LOCAL_PATH)

    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        emit_finding: FindingCallback,
    ) -> List[Finding]:
        findings: List[Finding] = []
        target_path = target.value

        # --- Stage 1: Dockerfile Container Hardening (0% - 25%) ---
        await emit_progress(10, "Auditing Dockerfiles for root user, unpinned base images, and secrets...")
        await emit_log(LogLevel.INFO, f"Scanning Dockerfile instructions in '{target_path}'.")

        dock_findings = await audit_dockerfiles(target_path, emit_log=emit_log)
        for f in dock_findings:
            f.scan_id = "active"
            findings.append(f)
            await emit_finding(f)

        # --- Stage 2: Docker Compose Security (25% - 50%) ---
        await emit_progress(35, "Evaluating Docker Compose services, socket mounts, and exposed ports...")
        await emit_log(LogLevel.INFO, f"Analyzing docker-compose service specifications.")

        cmp_findings = await audit_compose_files(target_path, emit_log=emit_log)
        for f in cmp_findings:
            f.scan_id = "active"
            findings.append(f)
            await emit_finding(f)

        # --- Stage 3: Kubernetes Security Standards (50% - 75%) ---
        await emit_progress(60, "Checking Kubernetes manifests against Pod Security Standards...")
        await emit_log(LogLevel.INFO, f"Auditing Kubernetes pod and deployment securityContext configurations.")

        k8s_findings = await audit_k8s_manifests(target_path, emit_log=emit_log)
        for f in k8s_findings:
            f.scan_id = "active"
            findings.append(f)
            await emit_finding(f)

        # --- Stage 4: Terraform & Cloud Infrastructure (75% - 100%) ---
        await emit_progress(85, "Auditing Terraform cloud infrastructure (S3 ACLs, Security Groups, IAM)...")
        await emit_log(LogLevel.INFO, f"Scanning Terraform HCL resources for cloud misconfigurations.")

        tf_findings = await audit_terraform_files(target_path, emit_log=emit_log)
        for f in tf_findings:
            f.scan_id = "active"
            findings.append(f)
            await emit_finding(f)

        await emit_progress(100, "Infrastructure-as-Code & Container assessment completed.")
        await emit_log(LogLevel.INFO, f"Infra IaC engine finished with {len(findings)} total findings.")

        return findings
