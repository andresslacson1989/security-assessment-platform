"""
Contract 03, 06 & 08 Software Composition Analysis (SCA) & Lockfile Dependency Auditor.
"""

from __future__ import annotations
import json
import os
from pathlib import Path
import re
from typing import List, Optional, Dict, Tuple

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, LogLevel
from app.engines.base import LogCallback

IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}

# Known vulnerable package versions database (package_name_lower -> list of (vulnerable_pattern, cve_id, description, fix_version))
KNOWN_VULNERABLE_PACKAGES: Dict[str, List[Tuple[str, str, str, str]]] = {
    "requests": [
        (r"^2\.(?:[0-9]|1[0-9]|2[0-9]|30)\.", "CVE-2023-32681", "Leaked Proxy-Authorization headers on redirect", ">=2.31.0"),
    ],
    "urllib3": [
        (r"^1\.26\.(?:[0-9]|1[0-7])\b", "CVE-2023-45803", "Request body not stripped on redirect", ">=1.26.18"),
        (r"^2\.0\.(?:[0-6])\b", "CVE-2023-45803", "Request body not stripped on redirect", ">=2.0.7"),
    ],
    "django": [
        (r"^(?:3\.|4\.0|4\.1)\.", "CVE-2023-31047", "Bypass validation in MultiValueField", ">=4.2.1"),
    ],
    "flask": [
        (r"^0\.|^1\.[01]\.", "CVE-2018-1000656", "Denial of Service in decoding JSON payload", ">=2.0.0"),
    ],
    "lodash": [
        (r"^4\.17\.(?:[0-9]|1[0-9]|20)\b", "CVE-2021-23337", "Command Injection via template function", ">=4.17.21"),
    ],
    "express": [
        (r"^4\.(?:[0-9]|1[0-8])\.", "CVE-2024-29041", "Open redirect and query parsing vulnerabilities", ">=4.19.2"),
    ],
    "jsonwebtoken": [
        (r"^8\.|^9\.0\.0\b", "CVE-2022-23529", "Insecure key verification allowing arbitrary file read", ">=9.0.1"),
    ],
}


def parse_requirements_txt(content: str) -> List[Tuple[str, str, int]]:
    """
    Parses requirements.txt lines into (package_name, version_spec, line_num).
    """
    results = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Match 'package==1.2.3' or 'package>=1.0.0'
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~^!]+.*)?", line)
        if match:
            pkg_name = match.group(1).lower()
            version_spec = (match.group(2) or "").strip()
            results.append((pkg_name, version_spec, line_num))
    return results


def parse_package_json(content: str) -> List[Tuple[str, str, int]]:
    """
    Parses package.json dependencies and devDependencies.
    """
    results = []
    try:
        data = json.loads(content)
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        for pkg, ver in deps.items():
            results.append((pkg.lower(), str(ver), 1))
    except Exception:
        pass
    return results


async def audit_dependencies(
    repo_path: str,
    emit_log: Optional[LogCallback] = None,
) -> List[Finding]:
    """
    Audits manifest and lockfiles for known CVEs and wildcard versions.
    """
    findings: List[Finding] = []
    root = Path(repo_path)
    if not root.exists():
        return findings

    manifest_files_found = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in IGNORED_DIRS and not (Path(dirpath) / d).is_symlink()
        ]

        for filename in filenames:
            file_path = Path(dirpath) / filename
            if file_path.is_symlink():
                continue
            rel_path = file_path.relative_to(root)
            fn_lower = filename.lower()

            parsed_packages: List[Tuple[str, str, int]] = []

            if fn_lower in ("requirements.txt", "requirements-dev.txt"):
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        parsed_packages = parse_requirements_txt(f.read())
                    manifest_files_found += 1
                except Exception:
                    continue

            elif fn_lower == "package.json":
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        parsed_packages = parse_package_json(f.read())
                    manifest_files_found += 1
                except Exception:
                    continue

            for pkg_name, ver_spec, line_num in parsed_packages:
                location_str = f"{rel_path}:{line_num}"

                # 1. Wildcard version check (SAST-DEP-002)
                if ver_spec in ("*", ">=0.0.0", "", "latest"):
                    findings.append(Finding(
                        scan_id="auto",
                        engine="code_sast",
                        check_id="SAST-DEP-002",
                        category="Dependency Hygiene",
                        title=f"Unpinned / Wildcard Dependency Version: '{pkg_name}'",
                        severity=Severity.LOW,
                        cvss_score=3.7,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                        cwe_id="CWE-1104",
                        owasp_category="A06:2021-Vulnerable and Outdated Components",
                        nist_control="SA-15",
                        description=f"Dependency '{pkg_name}' specifies a wildcard or unpinned version: '{ver_spec or '*'}' in '{rel_path}'.",
                        impact="Builds are non-reproducible and automatic installation of future upstream breaking changes or compromised releases can introduce vulnerabilities.",
                        remediation="Pin the dependency to a specific immutable semantic version (e.g. package==1.2.3).",
                        remediation_code_snippet=f"{pkg_name}==1.2.3",
                        references=["https://cwe.mitre.org/data/definitions/1104.html"],
                        evidence=Evidence(
                            location=location_str,
                            observed_value=f"{pkg_name} {ver_spec or '*'}",
                            expected_value="Exact pinned version (e.g. package==X.Y.Z)",
                            line_number=line_num,
                        ),
                        fingerprint=calculate_fingerprint("SAST-DEP-002", location_str, pkg_name),
                    ))

                # 2. Known CVE version check (SAST-DEP-001)
                if pkg_name in KNOWN_VULNERABLE_PACKAGES:
                    clean_ver = re.sub(r"^[=^~><\s]+", "", ver_spec)
                    for pattern, cve_id, cve_desc, fix_ver in KNOWN_VULNERABLE_PACKAGES[pkg_name]:
                        if re.search(pattern, clean_ver):
                            findings.append(Finding(
                                scan_id="auto",
                                engine="code_sast",
                                check_id="SAST-DEP-001",
                                category="Software Composition Analysis",
                                title=f"Vulnerable Dependency '{pkg_name}=={clean_ver}' ({cve_id})",
                                severity=Severity.HIGH,
                                cvss_score=7.5,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                cwe_id="CWE-1395",
                                owasp_category="A06:2021-Vulnerable and Outdated Components",
                                nist_control="SA-15, SI-2",
                                description=f"Package '{pkg_name}' version '{clean_ver}' in '{rel_path}' is affected by {cve_id}: {cve_desc}.",
                                impact="Attackers can leverage known public exploits targeting this outdated component.",
                                remediation=f"Upgrade '{pkg_name}' to version {fix_ver} or higher.",
                                remediation_code_snippet=f"# Upgrade command:\npip install --upgrade \"{pkg_name}{fix_ver}\"",
                                references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                                evidence=Evidence(
                                    location=location_str,
                                    observed_value=f"{pkg_name}=={clean_ver} (Matches {cve_id})",
                                    expected_value=f"{pkg_name}{fix_ver}",
                                    line_number=line_num,
                                ),
                                fingerprint=calculate_fingerprint("SAST-DEP-001", location_str, f"{pkg_name}_{cve_id}"),
                            ))

    if emit_log:
        await emit_log(LogLevel.INFO, f"Dependency auditor inspected {manifest_files_found} manifest files.")

    return findings
