"""
Contract 03, 06 & 08 Kubernetes Manifest & Pod Security Context Auditor.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import List, Optional, Dict, Any
import yaml

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, LogLevel
from app.engines.base import LogCallback

IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}


def extract_containers(doc: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Extracts containers from Kubernetes Pod, Deployment, DaemonSet, StatefulSet, or Job specs.
    """
    containers = []
    spec = doc.get("spec", {})
    if "template" in spec and isinstance(spec["template"], dict):
        pod_spec = spec["template"].get("spec", {})
    else:
        pod_spec = spec

    for c in pod_spec.get("containers", []):
        if isinstance(c, dict):
            containers.append((c.get("name", "container"), c))
    return containers


def audit_k8s_yaml(content: str, file_path_str: str) -> List[Finding]:
    """
    Evaluates Kubernetes documents for Pod Security Standards violations.
    """
    findings: List[Finding] = []
    try:
        docs = list(yaml.safe_load_all(content))
    except Exception:
        return findings

    for doc_idx, doc in enumerate(docs):
        if not isinstance(doc, dict):
            continue

        kind = doc.get("kind", "")
        if kind not in ("Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"):
            continue

        meta_name = doc.get("metadata", {}).get("name", f"item-{doc_idx}")
        spec = doc.get("spec", {})
        pod_spec = spec.get("template", {}).get("spec", spec) if "template" in spec else spec

        loc_pod = f"{file_path_str} [{kind}: {meta_name}]"

        # 1. Host Namespace Sharing (IAC-K8S-002)
        host_ns_flags = []
        if pod_spec.get("hostPID") is True:
            host_ns_flags.append("hostPID: true")
        if pod_spec.get("hostNetwork") is True:
            host_ns_flags.append("hostNetwork: true")
        if pod_spec.get("hostIPC") is True:
            host_ns_flags.append("hostIPC: true")

        if host_ns_flags:
            findings.append(Finding(
                scan_id="auto",
                engine="infra_iac",
                check_id="IAC-K8S-002",
                category="Kubernetes Security",
                title=f"Kubernetes Pod Shares Host Namespaces ({', '.join(host_ns_flags)})",
                severity=Severity.HIGH,
                cvss_score=7.8,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
                cwe_id="CWE-250",
                owasp_category="A05:2021-Security Misconfiguration",
                nist_control="AC-6, SC-7",
                description=f"Pod '{meta_name}' in '{file_path_str}' shares host kernel namespaces ({', '.join(host_ns_flags)}).",
                impact="Processes inside the container can snoop on host processes, sniff host network traffic, or manipulate host IPC shared memory.",
                remediation="Disable hostPID, hostNetwork, and hostIPC in pod specification.",
                remediation_code_snippet="spec:\n  hostPID: false\n  hostNetwork: false\n  hostIPC: false",
                references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
                evidence=Evidence(
                    location=loc_pod,
                    observed_value=", ".join(host_ns_flags),
                    expected_value="hostPID: false, hostNetwork: false, hostIPC: false",
                ),
                fingerprint=calculate_fingerprint("IAC-K8S-002", loc_pod, str(host_ns_flags)),
            ))

        # Check Container specs
        for c_name, c_spec in extract_containers(doc):
            loc_c = f"{loc_pod} [container: {c_name}]"
            sec_ctx = c_spec.get("securityContext", {})

            # 2. Privileged & Privilege Escalation (IAC-K8S-001)
            is_priv = sec_ctx.get("privileged") is True
            allow_esc = sec_ctx.get("allowPrivilegeEscalation") is True

            if is_priv or allow_esc:
                desc_detail = "privileged: true" if is_priv else "allowPrivilegeEscalation: true"
                findings.append(Finding(
                    scan_id="auto",
                    engine="infra_iac",
                    check_id="IAC-K8S-001",
                    category="Kubernetes Security",
                    title=f"Container '{c_name}' Configured with Elevated Privileges ({desc_detail})",
                    severity=Severity.HIGH,
                    cvss_score=8.5,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                    cwe_id="CWE-250",
                    owasp_category="A05:2021-Security Misconfiguration",
                    nist_control="AC-6",
                    description=f"Container '{c_name}' in '{loc_pod}' specifies '{desc_detail}'.",
                    impact="Grants all root capabilities to the container and bypasses kernel isolation boundaries.",
                    remediation="Set 'privileged: false' and 'allowPrivilegeEscalation: false'.",
                    remediation_code_snippet="securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false",
                    references=["https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"],
                    evidence=Evidence(
                        location=loc_c,
                        observed_value=desc_detail,
                        expected_value="privileged: false, allowPrivilegeEscalation: false",
                    ),
                    fingerprint=calculate_fingerprint("IAC-K8S-001", loc_c, desc_detail),
                ))

            # 3. ReadOnlyRootFilesystem (IAC-K8S-003)
            if sec_ctx.get("readOnlyRootFilesystem") is not True:
                findings.append(Finding(
                    scan_id="auto",
                    engine="infra_iac",
                    check_id="IAC-K8S-003",
                    category="Kubernetes Security",
                    title=f"Container '{c_name}' Missing Read-Only Root Filesystem",
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
                    cwe_id="CWE-250",
                    owasp_category="A05:2021-Security Misconfiguration",
                    nist_control="SC-28",
                    description=f"Container '{c_name}' has an ephemeral writable root filesystem.",
                    impact="Attackers gaining code execution can write malicious payloads or modify system binaries on disk.",
                    remediation="Set 'readOnlyRootFilesystem: true' and use emptyDir mounts for temporary write directories.",
                    remediation_code_snippet="securityContext:\n  readOnlyRootFilesystem: true",
                    references=["https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"],
                    evidence=Evidence(
                        location=loc_c,
                        observed_value=f"readOnlyRootFilesystem is {sec_ctx.get('readOnlyRootFilesystem', 'unset')}",
                        expected_value="readOnlyRootFilesystem: true",
                    ),
                    fingerprint=calculate_fingerprint("IAC-K8S-003", loc_c, "writable_root"),
                ))

            # 4. Resource Limits (IAC-K8S-004)
            resources = c_spec.get("resources", {})
            limits = resources.get("limits", {})
            if not limits.get("cpu") or not limits.get("memory"):
                findings.append(Finding(
                    scan_id="auto",
                    engine="infra_iac",
                    check_id="IAC-K8S-004",
                    category="Kubernetes Security",
                    title=f"Container '{c_name}' Missing CPU/Memory Resource Limits",
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                    cwe_id="CWE-400",
                    owasp_category="A05:2021-Security Misconfiguration",
                    nist_control="SC-5",
                    description=f"Container '{c_name}' does not specify CPU and memory resource limits.",
                    impact="A memory leak or denial-of-service condition can starve neighbor pods on the same Kubernetes worker node.",
                    remediation="Declare explicit CPU and memory resource limits in the container spec.",
                    remediation_code_snippet="resources:\n  limits:\n    cpu: \"500m\"\n    memory: \"512Mi\"",
                    references=["https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"],
                    evidence=Evidence(
                        location=loc_c,
                        observed_value="resources.limits is missing or incomplete",
                        expected_value="resources.limits with cpu and memory declared",
                    ),
                    fingerprint=calculate_fingerprint("IAC-K8S-004", loc_c, "missing_limits"),
                ))

    return findings


async def audit_k8s_manifests(
    target_path: str,
    emit_log: Optional[LogCallback] = None,
) -> List[Finding]:
    """
    Finds and audits Kubernetes YAML manifest files.
    """
    findings: List[Finding] = []
    root = Path(target_path)
    if not root.exists():
        return findings

    files_to_check = []
    if root.is_file() and root.suffix.lower() in (".yml", ".yaml"):
        files_to_check.append(root)
    elif root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
            for fn in filenames:
                if fn.lower().endswith((".yml", ".yaml")):
                    files_to_check.append(Path(dirpath) / fn)

    for fpath in files_to_check:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if "apiVersion:" in content and "kind:" in content:
                rel_str = str(fpath.relative_to(root) if root.is_dir() else fpath.name)
                findings.extend(audit_k8s_yaml(content, rel_str))
        except Exception:
            continue

    if emit_log:
        await emit_log(LogLevel.INFO, f"Kubernetes auditor scanned {len(files_to_check)} YAML manifest(s).")

    return findings
