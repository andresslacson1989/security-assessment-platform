"""
Contract 03, 06 & 08 Terraform & AWS Cloud Infrastructure Auditor.
"""

from __future__ import annotations
import os
from pathlib import Path
import re
from typing import List, Optional

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, LogLevel
from app.engines.base import LogCallback

IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", ".terraform", "dist", "build"}


def audit_terraform_file(content: str, file_path_str: str) -> List[Finding]:
    """
    Scans HCL syntax for cloud security anti-patterns.
    """
    findings: List[Finding] = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, start=1):
        line_str = line.strip()
        if not line_str or line_str.startswith(("#", "//")):
            continue

        loc_str = f"{file_path_str}:{line_num}"

        # 1. Public S3 Bucket ACL (IAC-TF-001)
        if re.search(r'acl\s*=\s*["\']public-(read|read-write)["\']', line_str, re.IGNORECASE):
            findings.append(Finding(
                scan_id="auto",
                engine="infra_iac",
                check_id="IAC-TF-001",
                category="Cloud Infrastructure Security",
                title="Publicly Accessible S3 Bucket ACL in Terraform",
                severity=Severity.HIGH,
                cvss_score=8.2,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                cwe_id="CWE-284",
                owasp_category="A01:2021-Broken Access Control",
                nist_control="AC-3, SC-7",
                description=f"Terraform resource in '{file_path_str}' configures an AWS S3 bucket with a public ACL ({line_str}).",
                impact="Unauthenticated internet users can list, read, or upload objects in the cloud storage bucket.",
                remediation="Set S3 ACL to 'private' and enable AWS S3 Block Public Access.",
                remediation_code_snippet='resource "aws_s3_bucket" "b" {\n  acl = "private"\n}',
                references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
                evidence=Evidence(
                    location=loc_str,
                    observed_value=line_str,
                    expected_value='acl = "private"',
                    line_number=line_num,
                ),
                fingerprint=calculate_fingerprint("IAC-TF-001", loc_str, "public_s3"),
            ))

        # 2. Unencrypted Storage Volume (IAC-TF-003)
        if re.search(r'encrypted\s*=\s*false', line_str, re.IGNORECASE):
            findings.append(Finding(
                scan_id="auto",
                engine="infra_iac",
                check_id="IAC-TF-003",
                category="Cloud Infrastructure Security",
                title="Storage Volume Explicitly Disables Encryption at Rest",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-311",
                owasp_category="A02:2021-Cryptographic Failures",
                nist_control="SC-28",
                description=f"Storage volume in '{file_path_str}' explicitly disables encryption at rest ('encrypted = false').",
                impact="Physical drives or volume snapshots may be recovered without cryptographic protection.",
                remediation="Enable encryption at rest using AWS KMS or default provider encryption keys.",
                remediation_code_snippet="encrypted = true",
                references=["https://cwe.mitre.org/data/definitions/311.html"],
                evidence=Evidence(
                    location=loc_str,
                    observed_value=line_str,
                    expected_value="encrypted = true",
                    line_number=line_num,
                ),
                fingerprint=calculate_fingerprint("IAC-TF-003", loc_str, "unencrypted_storage"),
            ))

    # Multiline Block Analysis
    # 3. Security Group with 0.0.0.0/0 on Port 22 or 3389 (IAC-TF-002)
    # Search for blocks containing from_port = 22 and cidr_blocks = ["0.0.0.0/0"]
    if '0.0.0.0/0' in content:
        if re.search(r'(from_port\s*=\s*(22|3389)|to_port\s*=\s*(22|3389))', content):
            findings.append(Finding(
                scan_id="auto",
                engine="infra_iac",
                check_id="IAC-TF-002",
                category="Cloud Infrastructure Security",
                title="Security Group Allows Public Ingress (0.0.0.0/0) to SSH/RDP Ports (22/3389)",
                severity=Severity.HIGH,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe_id="CWE-284",
                owasp_category="A01:2021-Broken Access Control",
                nist_control="AC-3, SC-7",
                description=f"Security group rule in '{file_path_str}' allows inbound access from '0.0.0.0/0' to administrative management ports (SSH 22 or RDP 3389).",
                impact="Management interfaces are exposed to global internet brute-force attacks and zero-day vulnerabilities.",
                remediation="Restrict SSH/RDP ingress to trusted corporate VPN CIDR blocks or AWS Systems Manager Session Manager.",
                remediation_code_snippet='cidr_blocks = ["10.0.0.0/16"] # Corporate VPC only',
                references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html"],
                evidence=Evidence(
                    location=file_path_str,
                    observed_value="cidr_blocks = [\"0.0.0.0/0\"] on port 22/3389",
                    expected_value="Restricted CIDR block or Session Manager",
                ),
                fingerprint=calculate_fingerprint("IAC-TF-002", file_path_str, "open_ssh_sg"),
            ))

    # 4. Wildcard IAM Policy (IAC-TF-004)
    has_wildcard_action = bool(re.search(r'["\']?Action["\']?\s*[:=]\s*(["\']\*["\']|\[\s*["\']\*["\']\s*\])', content, re.IGNORECASE))
    has_wildcard_resource = bool(re.search(r'["\']?Resource["\']?\s*[:=]\s*(["\']\*["\']|\[\s*["\']\*["\']\s*\])', content, re.IGNORECASE))
    if has_wildcard_action and has_wildcard_resource:
        findings.append(Finding(
            scan_id="auto",
            engine="infra_iac",
            check_id="IAC-TF-004",
            category="Cloud Infrastructure Security",
            title="Overly Permissive IAM Wildcard Policy (Action: '*' on Resource: '*')",
            severity=Severity.HIGH,
            cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
            cwe_id="CWE-732",
            owasp_category="A01:2021-Broken Access Control",
            nist_control="AC-6",
            description=f"IAM policy in '{file_path_str}' grants full administrator permissions with wildcard Action and Resource.",
            impact="Violates the principle of least privilege, allowing complete account takeover if the role/identity is compromised.",
            remediation="Scope IAM policies to specific actions and target resource ARNs.",
            remediation_code_snippet='Action   = ["s3:GetObject"]\nResource = ["arn:aws:s3:::my-bucket/*"]',
            references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"],
            evidence=Evidence(
                location=file_path_str,
                observed_value="Action: \"*\", Resource: \"*\"",
                expected_value="Least privilege action and resource ARNs",
            ),
            fingerprint=calculate_fingerprint("IAC-TF-004", file_path_str, "wildcard_iam"),
        ))

    return findings


async def audit_terraform_files(
    target_path: str,
    emit_log: Optional[LogCallback] = None,
) -> List[Finding]:
    """
    Finds and audits Terraform .tf files.
    """
    findings: List[Finding] = []
    root = Path(target_path)
    if not root.exists():
        return findings

    files_to_check = []
    if root.is_file() and root.suffix.lower() == ".tf":
        files_to_check.append(root)
    elif root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
            for fn in filenames:
                if fn.lower().endswith(".tf"):
                    files_to_check.append(Path(dirpath) / fn)

    for fpath in files_to_check:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            rel_str = str(fpath.relative_to(root) if root.is_dir() else fpath.name)
            findings.extend(audit_terraform_file(content, rel_str))
        except Exception:
            continue

    if emit_log:
        await emit_log(LogLevel.INFO, f"Terraform auditor scanned {len(files_to_check)} .tf file(s).")

    return findings
