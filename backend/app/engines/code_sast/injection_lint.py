"""
Contract 03, 06 & 08 Static Injection Anti-Pattern Linting (SQLi, Command Injection, Unsafe Deserialization).
"""

from __future__ import annotations
import os
from pathlib import Path
import re
from typing import List, Optional

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, LogLevel, sanitize_sensitive_text
from app.engines.base import LogCallback

IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
SOURCE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".go"}

INJECTION_RULES = [
    {
        "check_id": "SAST-INJ-001",
        "title": "Raw SQL Query String Formatting / Concatenation",
        "severity": Severity.HIGH,
        "cvss": 8.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-89",
        "pattern": re.compile(r"(\.execute\(\s*f['\"].*(SELECT|INSERT|UPDATE|DELETE|DROP|FROM|WHERE).*\{|\.execute\(\s*['\"].*(SELECT|INSERT|UPDATE|DELETE|WHERE).*%s['\"]\s*%)", re.IGNORECASE),
        "desc": "Direct string interpolation or f-string concatenation in SQL database query execution.",
        "impact": "Enables SQL Injection attacks where malicious user input can read, modify, or drop database tables.",
        "remediation": "Use parameterized queries or prepared statements with placeholder parameters.",
        "code_snippet": "# Parameterized query:\ncursor.execute(\"SELECT * FROM users WHERE email = %s\", (user_email,))",
    },
    {
        "check_id": "SAST-INJ-002",
        "title": "Unsafe Shell Execution (shell=True / os.system)",
        "severity": Severity.HIGH,
        "cvss": 8.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-78",
        "pattern": re.compile(r"(subprocess\.(Popen|run|call|check_output)\(.*shell\s*=\s*True|os\.system\(|exec\(|eval\()"),
        "desc": "Spawning shell processes with shell=True or direct string execution creates command injection risks.",
        "impact": "If user input reaches the command string, attackers can execute arbitrary OS commands on the host server.",
        "remediation": "Pass arguments as an explicit list without shell=True, or use shlex.quote() when shell is strictly necessary.",
        "code_snippet": "subprocess.run([\"ls\", \"-la\", safe_dir], shell=False, check=True)",
    },
    {
        "check_id": "SAST-INJ-003",
        "title": "Unsafe Object Deserialization (pickle / unsafe YAML)",
        "severity": Severity.HIGH,
        "cvss": 8.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-502",
        "pattern": re.compile(r"(pickle\.loads\(|yaml\.load\(.*Loader\s*=\s*(yaml\.)?(UnsafeLoader|Loader)|_pickle\.loads\()"),
        "desc": "Deserializing untrusted data with Python pickle or standard PyYAML Loader allows arbitrary code execution during object instantiation.",
        "impact": "Remote Code Execution (RCE) via malicious serialized object payloads.",
        "remediation": "Use safe deserialization formats like JSON (json.loads) or PyYAML's yaml.safe_load().",
        "code_snippet": "import yaml\ndata = yaml.safe_load(untrusted_stream)",
    },
]


async def audit_injection_patterns(
    repo_path: str,
    emit_log: Optional[LogCallback] = None,
) -> List[Finding]:
    """
    Scans source files for raw SQL concatenation, shell=True command execution, and unsafe deserialization.
    """
    findings: List[Finding] = []
    root = Path(repo_path)
    read_errors = 0
    if not root.exists():
        return findings

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS and not (Path(dirpath) / d).is_symlink()]

        for filename in filenames:
            ext = Path(filename).suffix.lower()
            if ext not in SOURCE_EXTS:
                continue

            file_path = Path(dirpath) / filename
            if file_path.is_symlink():
                continue
            rel_path = file_path.relative_to(root)

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, start=1):
                        line_str = line.strip()
                        if not line_str or line_str.startswith(("#", "//", "/*", "*")):
                            continue

                        for rule in INJECTION_RULES:
                            match = rule["pattern"].search(line_str)
                            if match:
                                location_str = f"{rel_path}:{line_num}"
                                findings.append(Finding(
                                    scan_id="auto",
                                    engine="code_sast",
                                    check_id=rule["check_id"],
                                    category="Injection Vulnerabilities",
                                    title=rule["title"],
                                    severity=rule["severity"],
                                    cvss_score=rule["cvss"],
                                    cvss_vector=rule["cvss_vector"],
                                    cwe_id=rule["cwe"],
                                    owasp_category="A03:2021-Injection",
                                    nist_control="SI-10",
                                    description=f"{rule['desc']} Found in '{rel_path}' at line {line_num}.",
                                    impact=rule["impact"],
                                    remediation=rule["remediation"],
                                    remediation_code_snippet=rule["code_snippet"],
                                    references=["https://cwe.mitre.org/data/definitions/89.html"],
                                    evidence=Evidence(
                                        location=location_str,
                                        observed_value=sanitize_sensitive_text(line_str[:120]),
                                        expected_value="Safe parameterized / sanitized call",
                                        line_number=line_num,
                                    ),
                                    fingerprint=calculate_fingerprint(rule["check_id"], location_str, line_str[:60]),
                                ))
            except Exception as exc:
                read_errors += 1
                if emit_log:
                    await emit_log(LogLevel.WARNING, f"Injection linter could not read '{rel_path}': {type(exc).__name__}")

    if emit_log and read_errors:
        await emit_log(LogLevel.WARNING, f"Injection linter skipped {read_errors} files; coverage is degraded.")

    return findings
