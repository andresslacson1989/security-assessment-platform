"""
Contract 03, 06 & 08 Dockerfile Container Hardening & Security Auditor.
"""

from __future__ import annotations
import os
from pathlib import Path
import re
from typing import List, Optional

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, mask_secret, LogLevel
from app.engines.base import LogCallback

IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}


def audit_dockerfile_content(content: str, file_path_str: str) -> List[Finding]:
    """
    Parses Dockerfile lines and applies security hardening rules.
    """
    findings: List[Finding] = []
    lines = content.splitlines()

    has_non_root_user = False
    has_healthcheck = False
    base_image_findings_emitted = False

    for line_num, line in enumerate(lines, start=1):
        line_str = line.strip()
        if not line_str or line_str.startswith("#"):
            continue

        # 1. Base Image :latest or untagged (IAC-DOCK-002)
        if line_str.upper().startswith("FROM "):
            from_target = line_str[5:].strip().split()[0]
            if ":" not in from_target or from_target.endswith(":latest"):
                findings.append(Finding(
                    scan_id="auto",
                    engine="infra_iac",
                    check_id="IAC-DOCK-002",
                    category="Container Hardening",
                    title=f"Base Image Uses Insecure or Unpinned ':latest' Tag ('{from_target}')",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-1104",
                    owasp_category="A06:2021-Vulnerable and Outdated Components",
                    nist_control="SA-15",
                    description=f"Dockerfile in '{file_path_str}' uses an unpinned base image '{from_target}'.",
                    impact="Builds are non-deterministic and can pull in breaking or compromised upstream image changes silently.",
                    remediation="Pin base images to explicit version tags or SHA-256 digests.",
                    remediation_code_snippet=f"FROM {from_target.split(':')[0]}:3.18-alpine",
                    references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"],
                    evidence=Evidence(
                        location=f"{file_path_str}:{line_num}",
                        observed_value=line_str,
                        expected_value="FROM <image>:<immutable-version-or-sha256>",
                        line_number=line_num,
                    ),
                    fingerprint=calculate_fingerprint("IAC-DOCK-002", f"{file_path_str}:{line_num}", from_target),
                ))

        # 2. USER directive check
        if line_str.upper().startswith("USER "):
            user_val = line_str[5:].strip().lower()
            if user_val not in ("root", "0"):
                has_non_root_user = True

        # 3. HEALTHCHECK directive check
        if line_str.upper().startswith("HEALTHCHECK "):
            has_healthcheck = True

        # 4. Plaintext Secret in ENV / ARG (IAC-DOCK-004)
        if line_str.upper().startswith(("ENV ", "ARG ")):
            if re.search(r"(SECRET|PASSWORD|PASSWD|API_KEY|TOKEN|PRIVATE_KEY)\s*[:=]\s*[^\s]+", line_str, re.IGNORECASE):
                masked = mask_secret(line_str)
                findings.append(Finding(
                    scan_id="auto",
                    engine="infra_iac",
                    check_id="IAC-DOCK-004",
                    category="Hardcoded Secrets",
                    title="Hardcoded Secret in Dockerfile ENV / ARG Instruction",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-798",
                    owasp_category="A07:2021-Identification and Authentication Failures",
                    nist_control="IA-5, SC-28",
                    description=f"Secret credentials found hardcoded in Dockerfile build arguments or environment variables in '{file_path_str}'.",
                    impact="Image layer metadata exposes plaintext secrets to anyone with image pull permissions.",
                    remediation="Use BuildKit secret mounts (--mount=type=secret) or inject credentials at runtime via container orchestrator secrets.",
                    remediation_code_snippet="# BuildKit secret syntax:\nRUN --mount=type=secret,id=mysecret cat /run/secrets/mysecret",
                    references=["https://docs.docker.com/develop/develop-images/build_enhancements/#using-secret-information"],
                    evidence=Evidence(
                        location=f"{file_path_str}:{line_num}",
                        observed_value=masked,
                        expected_value="Secrets injected via BuildKit secret mounts or runtime environment variables",
                        line_number=line_num,
                    ),
                    fingerprint=calculate_fingerprint("IAC-DOCK-004", f"{file_path_str}:{line_num}", "env_secret"),
                ))

        # 5. Package Cache Retained (IAC-DOCK-005)
        if "apt-get install" in line_str and "rm -rf /var/lib/apt/lists" not in line_str:
            findings.append(Finding(
                scan_id="auto",
                engine="infra_iac",
                check_id="IAC-DOCK-005",
                category="Container Hygiene",
                title="Apt Package Cache Retained in Image Layer",
                severity=Severity.LOW,
                cvss_score=2.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                cwe_id="CWE-1021",
                owasp_category="A05:2021-Security Misconfiguration",
                nist_control="CM-6",
                description="apt-get install command without cleaning /var/lib/apt/lists/* in the same RUN layer.",
                impact="Inflates container image size and increases attack surface with outdated package index metadata.",
                remediation="Combine apt-get update && apt-get install with 'rm -rf /var/lib/apt/lists/*' in a single RUN instruction.",
                remediation_code_snippet="RUN apt-get update && apt-get install -y --no-install-recommends pkg \\\n    && rm -rf /var/lib/apt/lists/*",
                references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run"],
                evidence=Evidence(
                    location=f"{file_path_str}:{line_num}",
                    observed_value=line_str[:120],
                    expected_value="apt-get install followed by rm -rf /var/lib/apt/lists/*",
                    line_number=line_num,
                ),
                fingerprint=calculate_fingerprint("IAC-DOCK-005", f"{file_path_str}:{line_num}", "apt_cache"),
            ))

        # 6. Sudo Usage (IAC-DOCK-006)
        if re.search(r"\bsudo\s+", line_str) and line_str.upper().startswith("RUN "):
            findings.append(Finding(
                scan_id="auto",
                engine="infra_iac",
                check_id="IAC-DOCK-006",
                category="Privilege Management",
                title="Insecure Sudo Command Usage in Docker RUN Instruction",
                severity=Severity.MEDIUM,
                cvss_score=6.5,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-250",
                owasp_category="A05:2021-Security Misconfiguration",
                nist_control="AC-6",
                description="Using 'sudo' inside Dockerfile RUN commands introduces unnecessary privilege elevation binaries.",
                impact="Increases image footprint and potential privilege escalation surface.",
                remediation="Execute commands directly as root during build before switching to a non-root USER.",
                references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"],
                evidence=Evidence(
                    location=f"{file_path_str}:{line_num}",
                    observed_value=line_str[:120],
                    expected_value="Commands run directly without sudo",
                    line_number=line_num,
                ),
                fingerprint=calculate_fingerprint("IAC-DOCK-006", f"{file_path_str}:{line_num}", "sudo_usage"),
            ))

    # Check for missing non-root USER directive (IAC-DOCKER-001)
    if not has_non_root_user:
        findings.append(Finding(
            scan_id="auto",
            engine="infra_iac",
            check_id="IAC-DOCKER-001",
            category="Container Hardening",
            title="Container Runs as Root User (Missing Non-Root USER Directive)",
            severity=Severity.HIGH,
            cvss_score=7.8,
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-250",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="AC-6",
            description=f"The Dockerfile in '{file_path_str}' does not specify a non-root USER instruction.",
            impact="If a container breakout vulnerability occurs, the compromised process has root privileges on the host kernel.",
            remediation="Create a non-root user/group and declare 'USER <username>' before ENTRYPOINT/CMD.",
            remediation_code_snippet="RUN addgroup -S appgroup && adduser -S appuser -G appgroup\nUSER appuser",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"],
            evidence=Evidence(
                location=file_path_str,
                observed_value="No non-root USER instruction found",
                expected_value="USER appuser (UID > 0)",
            ),
            fingerprint=calculate_fingerprint("IAC-DOCKER-001", file_path_str, "root_user"),
        ))

    # Check for missing HEALTHCHECK (IAC-DOCK-003)
    if not has_healthcheck:
        findings.append(Finding(
            scan_id="auto",
            engine="infra_iac",
            check_id="IAC-DOCK-003",
            category="Container Hardening",
            title="Missing Container HEALTHCHECK Directive",
            severity=Severity.LOW,
            cvss_score=3.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            cwe_id="CWE-1021",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="SC-5",
            description=f"Dockerfile in '{file_path_str}' does not define a HEALTHCHECK instruction.",
            impact="Orchestrators cannot automatically detect stalled or unresponsive application processes.",
            remediation="Add a HEALTHCHECK instruction querying a lightweight health probe endpoint.",
            remediation_code_snippet="HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1",
            references=["https://docs.docker.com/engine/reference/builder/#healthcheck"],
            evidence=Evidence(
                location=file_path_str,
                observed_value="HEALTHCHECK instruction missing",
                expected_value="HEALTHCHECK --interval=30s CMD curl -f http://localhost/health || exit 1",
            ),
            fingerprint=calculate_fingerprint("IAC-DOCK-003", file_path_str, "missing_healthcheck"),
        ))

    return findings


async def audit_dockerfiles(
    target_path: str,
    emit_log: Optional[LogCallback] = None,
) -> List[Finding]:
    """
    Recursively finds and audits Dockerfiles in target directory or single file.
    """
    findings: List[Finding] = []
    root = Path(target_path)
    if not root.exists():
        return findings

    files_to_check = []
    if root.is_file():
        files_to_check.append(root)
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
            for fn in filenames:
                if "dockerfile" in fn.lower() or fn.lower().endswith(".dockerfile"):
                    files_to_check.append(Path(dirpath) / fn)

    for fpath in files_to_check:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            rel_str = str(fpath.relative_to(root) if root.is_dir() else fpath.name)
            findings.extend(audit_dockerfile_content(content, rel_str))
        except Exception:
            continue

    if emit_log:
        await emit_log(LogLevel.INFO, f"Dockerfile auditor inspected {len(files_to_check)} Dockerfile(s).")

    return findings
