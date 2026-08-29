"""
Contract 03, 06 & 08 Insecure Cryptography, Broken Hash Functions and PRNG Linting.
"""

from __future__ import annotations
import os
from pathlib import Path
import re
from typing import List, Optional

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, LogLevel
from app.engines.base import LogCallback

IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
SOURCE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".php", ".rb"}

CRYPTO_RULES = [
    {
        "check_id": "SAST-CRY-001",
        "title": "Usage of Broken Cryptographic Hash Function (MD5 / SHA1)",
        "severity": Severity.MEDIUM,
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-328",
        "pattern": re.compile(r"(hashlib\.(md5|sha1)\(|crypto\.createHash\(['\"](md5|sha1)['\"]\)|MD5_Init|sha1\(|md5\()", re.IGNORECASE),
        "desc": "MD5 and SHA-1 have known collision and preimage attacks and are cryptographically broken.",
        "remediation": "Upgrade to SHA-256 (SHA-2), SHA-3, or password-hashing algorithms (Argon2id, bcrypt, PBKDF2).",
        "code_snippet": "import hashlib\nhashlib.sha256(data.encode()).hexdigest()",
    },
    {
        "check_id": "SAST-CRY-002",
        "title": "Insecure Pseudo-Random Number Generator (PRNG) in Security Context",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-338",
        "pattern": re.compile(r"((token|key|secret|password|auth|session|salt)\s*=\s*.*(random\.random\(\)|random\.randint\(|Math\.random\(\)|rand\(\)))", re.IGNORECASE),
        "desc": "Standard pseudo-random number generators (like Python 'random' or JS 'Math.random') are predictable and must not be used for cryptographic secrets or session tokens.",
        "remediation": "Use cryptographically secure pseudo-random generators (Python 'secrets' module, Node.js 'crypto.randomBytes()').",
        "code_snippet": "import secrets\nsecure_token = secrets.token_hex(32)",
    },
    {
        "check_id": "SAST-CRY-003",
        "title": "Insecure Symmetric Cipher Mode (AES-ECB)",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-327",
        "pattern": re.compile(r"(MODE_ECB|AES/ECB/|aes-128-ecb|aes-256-ecb)", re.IGNORECASE),
        "desc": "Electronic Codebook (ECB) mode produces identical ciphertext for identical plaintext blocks, leaking structural data patterns.",
        "remediation": "Use authenticated encryption with associated data (AEAD) such as AES-GCM or ChaCha20-Poly1305.",
        "code_snippet": "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\naesgcm = AESGCM(key)",
    },
]


async def audit_crypto_patterns(
    repo_path: str,
    emit_log: Optional[LogCallback] = None,
) -> List[Finding]:
    """
    Scans source files for broken cryptography, insecure PRNG, and ECB cipher modes.
    """
    findings: List[Finding] = []
    root = Path(repo_path)
    if not root.exists():
        return findings

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]

        for filename in filenames:
            ext = Path(filename).suffix.lower()
            if ext not in SOURCE_EXTS:
                continue

            file_path = Path(dirpath) / filename
            rel_path = file_path.relative_to(root)

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, start=1):
                        line_str = line.strip()
                        if not line_str or line_str.startswith(("#", "//", "/*", "*")):
                            continue

                        for rule in CRYPTO_RULES:
                            match = rule["pattern"].search(line_str)
                            if match:
                                location_str = f"{rel_path}:{line_num}"
                                findings.append(Finding(
                                    scan_id="auto",
                                    engine="code_sast",
                                    check_id=rule["check_id"],
                                    category="Cryptographic Failures",
                                    title=rule["title"],
                                    severity=rule["severity"],
                                    cvss_score=rule["cvss"],
                                    cvss_vector=rule["cvss_vector"],
                                    cwe_id=rule["cwe"],
                                    owasp_category="A02:2021-Cryptographic Failures",
                                    nist_control="SC-13",
                                    description=f"{rule['desc']} Detected in '{rel_path}' on line {line_num}.",
                                    impact="Weak algorithms allow attackers to forge tokens, recover plaintext data, or break hashing protections.",
                                    remediation=rule["remediation"],
                                    remediation_code_snippet=rule["code_snippet"],
                                    references=["https://cwe.mitre.org/data/definitions/327.html"],
                                    evidence=Evidence(
                                        location=location_str,
                                        observed_value=line_str[:120],
                                        expected_value="Strong modern cryptography (SHA-256, AES-GCM, secrets.token_hex)",
                                        line_number=line_num,
                                    ),
                                    fingerprint=calculate_fingerprint(rule["check_id"], location_str, line_str[:60]),
                                ))
            except Exception:
                continue

    return findings
