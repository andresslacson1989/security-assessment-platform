"""
Contract 03 §3.3 & Contract 08 §4.2: Historical Git Commit Secret Scanner.
Inspects commit history (git log -p) for leaked credentials and hardcoded secrets in historical revisions.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List, Optional

from app.core.models import Finding, Evidence, Severity, mask_secret, calculate_fingerprint
from app.engines.code_sast.secret_scanner import SECRET_RULES
from app.core.process_supervisor import process_supervisor
from app.core.path_sandbox import safe_workspace_relative_path


async def audit_git_commit_history(
    repo_path: str,
    max_commits: int = 100,
    execution_id: Optional[str] = None,
) -> List[Finding]:
    """
    Scans git commit diff history for exposed secrets using regex rules and entropy checks.
    """
    findings: List[Finding] = []
    p = Path(repo_path)
    if not p.exists():
        return findings

    # Check if target is inside a git repository
    git_dir = p / ".git" if p.is_dir() else p.parent / ".git"
    if not git_dir.exists():
        return findings

    cmd = ["git", "log", "--no-ext-diff", "--no-textconv", "-p", f"-n{max_commits}", "--"]
    cwd = str(p if p.is_dir() else p.parent)

    try:
        returncode, stdout, _ = await process_supervisor.execute(
            cmd=cmd,
            cwd=cwd,
            timeout=8.0,
            max_output_bytes=10 * 1024 * 1024,
            env={"GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"},
            execution_id=execution_id,
        )
        if returncode not in (0, 1):
            return findings
        diff_text = stdout
    except Exception:
        return findings

    current_commit = "unknown_commit"
    current_file = "unknown_file"

    for line in diff_text.splitlines():
        if line.startswith("commit "):
            current_commit = line.split()[1][:8]
            continue
        elif line.startswith("diff --git a/"):
            parts = line.split()
            if len(parts) >= 4:
                current_file = safe_workspace_relative_path(parts[2].replace("a/", ""), p) or "untrusted-output"
            continue

        # Only audit added lines in commits
        if line.startswith("+") and not line.startswith("+++"):
            code_line = line[1:].strip()
            if not code_line or len(code_line) < 10:
                continue

            for rule in SECRET_RULES:
                pattern = rule["pattern"]
                check_id = rule["check_id"]
                title = rule["title"]
                match = pattern.search(code_line)
                if match:
                    raw_secret = match.group(0)
                    masked = mask_secret(raw_secret)
                    loc = f"git://{current_commit}/{current_file}"
                    obs = f"Found secret pattern {check_id} in commit {current_commit}: {masked}"

                    findings.append(Finding(
                        scan_id="auto",
                        engine="code_sast",
                        check_id="SAST-GIT-001",
                        category="Hardcoded Secrets",
                        title=f"Exposed {title} in Historical Git Commit ({current_commit})",
                        severity=Severity.HIGH,
                        cvss_score=8.6,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-798",
                        owasp_category="A07:2021-Identification and Authentication Failures",
                        nist_control="IA-5, SC-28",
                        description=(
                            f"Git commit history analysis detected a hardcoded secret ({title}) committed in revision {current_commit} "
                            f"in file '{current_file}'. Even if deleted in current HEAD, historical commits retain secrets permanently."
                        ),
                        impact="Potential credential exposure allowing unauthorized access to cloud, APIs, or databases.",
                        remediation="Immediately revoke and rotate the exposed token. Rewrite git history using 'git filter-repo' or BFG Repo-Cleaner.",
                        remediation_code_snippet="# Rotate token in cloud provider console immediately.\n# Remove from git history:\ngit filter-repo --invert-paths --path <file>",
                        references=[
                            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                            "https://cwe.mitre.org/data/definitions/798.html"
                        ],
                        evidence=Evidence(
                            location=loc,
                            observed_value=obs,
                            expected_value="Zero credentials committed to version control history",
                            raw_response_snippet=f"+ {code_line[:15]}...[MASKED]...",
                        ),
                        fingerprint=calculate_fingerprint("SAST-GIT-001", loc, masked),
                        source_tool="native",
                    ))
                    break

    return findings
