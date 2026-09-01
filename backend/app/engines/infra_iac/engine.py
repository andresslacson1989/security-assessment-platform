"""
Contract 03, 06 & 08 Infrastructure-as-Code & Container Security Engine Coordinator.
"""

from __future__ import annotations
from typing import List

from app.core.models import Target, Finding, ScanConfig, TargetType, LogLevel, NormalizedExecutionState
from app.engines.base import BaseAssessmentEngine, LogCallback, ProgressCallback, FindingCallback
from app.engines.infra_iac.dockerfile_auditor import audit_dockerfiles
from app.engines.infra_iac.compose_auditor import audit_compose_files
from app.engines.infra_iac.k8s_manifest_auditor import audit_k8s_manifests
from app.engines.infra_iac.terraform_auditor import audit_terraform_files
from app.adapters.checkov_adapter import CheckovAdapter
from app.adapters.trivy_adapter import TrivyAdapter
from app.adapters.dockle_adapter import DockleAdapter
from app.adapters.kubebench_adapter import KubeBenchAdapter
from app.adapters.prowler_adapter import ProwlerAdapter
from app.adapters.gtfobins_adapter import GTFOBinsAdapter


class InfraIacAssessmentEngine(BaseAssessmentEngine):
    """
    Coordinator engine for Container Hardening, Docker Compose, Kubernetes, Terraform IaC, and CIS Benchmarks.
    Follows Adapters First-in-Line Architecture (Checkov + Trivy + Dockle + Kube-bench + Prowler primary, native HCL/YAML/Dockerfile manifest auditors fallback & enrichment).
    """

    @property
    def name(self) -> str:
        return "infra_iac"

    @property
    def display_name(self) -> str:
        return "Infrastructure-as-Code & Cloud Posture Auditor"

    @property
    def description(self) -> str:
        return (
            "Audits Dockerfiles (root user, unpinned base images, build secrets), Docker Compose "
            "(privileged mode, socket mounts, exposed DB ports), Kubernetes manifests (host namespaces, "
            "allowPrivilegeEscalation, resource limits), Terraform files (public S3, 0.0.0.0/0 SSH, IAM wildcards), "
            "CIS Docker Benchmark (Dockle), CIS Kubernetes Benchmark (kube-bench), and Multi-Cloud CIS Foundations (Prowler)."
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
        **kwargs,
    ) -> List[Finding]:
        findings: List[Finding] = []
        existing_fps = set()
        target_path = target.value
        record_cis = kwargs.get("record_cis_result")
        tool_state_cb = kwargs.get("emit_tool_execution_state")

        async def report_tool_state(tool_name: str, adapter, finding_count: int = 0) -> None:
            if not tool_state_cb:
                return
            state = getattr(adapter, "last_execution_state", NormalizedExecutionState.TOOL_EXECUTION_FAILED)
            if finding_count and state == NormalizedExecutionState.COMPLETED_NO_FINDINGS:
                state = NormalizedExecutionState.COMPLETED_WITH_FINDINGS
            await tool_state_cb(tool_name, state.value)

        # --- Stage 0: Primary External IaC & CIS Tool Adapters First-in-Line ---
        await emit_progress(5, "Running primary external IaC & CIS benchmark tool adapters...")

        # 0.1 Checkov Adapter (IaC Security Policy Engine)
        if getattr(config.adapters, "enable_checkov", True):
            checkov_adapter = CheckovAdapter()
            custom_path = getattr(config.adapters, "checkov_path", None) or getattr(config.adapters, "custom_checkov_path", None)
            try:
                if await checkov_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Checkov CLI adapter for Infrastructure-as-Code policy auditing...")
                    checkov_findings = await checkov_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                        require_managed_binary=True,
                    )
                    await report_tool_state("checkov", checkov_adapter, len(checkov_findings))
                    for f in checkov_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "checkov"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    if tool_state_cb:
                        await tool_state_cb("checkov", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                    await emit_log(LogLevel.INFO, "Checkov CLI not available - using native IaC & manifest auditors")
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("checkov", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                await emit_log(LogLevel.WARNING, f"Checkov adapter error: {e}")

        # 0.2 Trivy Adapter (Container & Dockerfile SCA)
        if getattr(config.adapters, "enable_trivy", True):
            trivy_adapter = TrivyAdapter()
            custom_path = getattr(config.adapters, "trivy_path", None) or getattr(config.adapters, "custom_trivy_path", None)
            try:
                if await trivy_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Trivy CLI adapter for container and manifest auditing...")
                    trivy_findings = await trivy_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                        require_managed_binary=True,
                    )
                    await report_tool_state("trivy", trivy_adapter, len(trivy_findings))
                    for f in trivy_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "trivy"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    if tool_state_cb:
                        await tool_state_cb("trivy", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                    await emit_log(LogLevel.INFO, "Trivy CLI not available - using native Dockerfile auditor")
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("trivy", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                await emit_log(LogLevel.WARNING, f"Trivy adapter error: {e}")

        # 0.3 Dockle Adapter (CIS Docker Container Hardening)
        if getattr(config.adapters, "enable_dockle", True):
            dockle_adapter = DockleAdapter()
            custom_path = getattr(config.adapters, "dockle_path", None) or getattr(config.adapters, "custom_dockle_path", None)
            try:
                if await dockle_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Dockle CIS Docker container hardening audit...")
                    dockle_findings = await dockle_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                        record_cis_result=record_cis,
                        require_managed_binary=True,
                    )
                    await report_tool_state("dockle", dockle_adapter, len(dockle_findings))
                    for f in dockle_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "dockle"
                            f.scan_id = "active"
                            findings.append(f)
                elif tool_state_cb:
                    await tool_state_cb("dockle", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("dockle", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                await emit_log(LogLevel.WARNING, f"Dockle adapter error: {e}")

        # 0.4 Kube-bench Adapter (CIS Kubernetes Benchmark)
        if getattr(config.adapters, "enable_kube_bench", True):
            kb_adapter = KubeBenchAdapter()
            custom_path = getattr(config.adapters, "kube_bench_path", None) or getattr(config.adapters, "custom_kube_bench_path", None)
            try:
                if await kb_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Kube-bench CIS Kubernetes compliance audit...")
                    kb_findings = await kb_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                        record_cis_result=record_cis,
                        require_managed_binary=True,
                    )
                    await report_tool_state("kube-bench", kb_adapter, len(kb_findings))
                    for f in kb_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "kube_bench"
                            f.scan_id = "active"
                            findings.append(f)
                elif tool_state_cb:
                    await tool_state_cb("kube-bench", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("kube-bench", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                await emit_log(LogLevel.WARNING, f"Kube-bench adapter error: {e}")

        # 0.5 Prowler Adapter (Multi-Cloud CIS Foundations)
        if getattr(config.adapters, "enable_prowler", True):
            prowler_adapter = ProwlerAdapter()
            custom_path = getattr(config.adapters, "prowler_path", None) or getattr(config.adapters, "custom_prowler_path", None)
            try:
                if await prowler_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Prowler multi-cloud CIS Foundations posture audit...")
                    prowler_findings = await prowler_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                        record_cis_result=record_cis,
                        require_managed_binary=True,
                    )
                    await report_tool_state("prowler", prowler_adapter, len(prowler_findings))
                    for f in prowler_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "prowler"
                            f.scan_id = "active"
                            findings.append(f)
                elif tool_state_cb:
                    await tool_state_cb("prowler", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("prowler", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                await emit_log(LogLevel.WARNING, f"Prowler adapter error: {e}")

        # --- Stage 1: Dockerfile Container Hardening ---
        if getattr(config.adapters, "enable_gtfobins", True):
            gtfobins_adapter = GTFOBinsAdapter()
            try:
                gtfobins_findings = await gtfobins_adapter.run(
                    target,
                    config,
                    emit_log,
                    emit_finding,
                    scan_id=kwargs.get("scan_id", "active"),
                    organization_id=kwargs.get("organization_id") or "org-default",
                    host_audit_input=kwargs.get("host_audit_input"),
                )
                for finding in gtfobins_findings:
                    if finding.fingerprint not in existing_fps:
                        existing_fps.add(finding.fingerprint)
                        findings.append(finding)
            except Exception as exc:
                await emit_log(LogLevel.WARNING, f"GTFOBins rule evaluation error: {exc}")

        # --- Stage 1: Dockerfile Container Hardening ---
        await emit_progress(25, "Auditing Dockerfiles for root user, unpinned base images, and secrets...")
        dock_findings = await audit_dockerfiles(target_path, emit_log=emit_log)
        for f in dock_findings:
            if f.fingerprint not in existing_fps:
                existing_fps.add(f.fingerprint)
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

        # --- Stage 2: Docker Compose Security ---
        await emit_progress(50, "Evaluating Docker Compose services, socket mounts, and exposed ports...")
        cmp_findings = await audit_compose_files(target_path, emit_log=emit_log)
        for f in cmp_findings:
            if f.fingerprint not in existing_fps:
                existing_fps.add(f.fingerprint)
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

        # --- Stage 3: Kubernetes Security Standards ---
        await emit_progress(75, "Checking Kubernetes manifests against Pod Security Standards...")
        k8s_findings = await audit_k8s_manifests(target_path, emit_log=emit_log)
        for f in k8s_findings:
            if f.fingerprint not in existing_fps:
                existing_fps.add(f.fingerprint)
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

        # --- Stage 4: Terraform & Cloud Infrastructure ---
        await emit_progress(90, "Auditing Terraform cloud infrastructure (S3 ACLs, Security Groups, IAM)...")
        tf_findings = await audit_terraform_files(target_path, emit_log=emit_log)
        for f in tf_findings:
            if f.fingerprint not in existing_fps:
                existing_fps.add(f.fingerprint)
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

        await emit_progress(100, "Infrastructure-as-Code & Container assessment completed.")
        await emit_log(LogLevel.INFO, f"Infra IaC engine finished with {len(findings)} total findings.")

        return findings
