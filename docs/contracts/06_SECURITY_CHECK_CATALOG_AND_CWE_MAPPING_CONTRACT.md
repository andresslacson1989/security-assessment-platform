# Contract 06: Security Check Catalog, ASVS 5.0.0, CWE Mappings & Evidence Hashing

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 10.0.0 (ASVS 5.0.0 Version-Qualified Mapping, NIST SP 800-53 Control Mapping, Cryptographic Evidence Hashing & Secret Masking Rules)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Canonical Security Checks, Vulnerability Taxonomies, Evidence Integrity & Sanitization  

---

## 1. Vulnerability Taxonomies & Standards Mapping

Every check executed by CyberAssess MUST map to:
1. **CWE ID:** Specific Common Weakness Enumeration identifier (e.g., `CWE-89` for SQLi, `CWE-79` for XSS, `CWE-918` for SSRF).
2. **OWASP Top 10 (2021):** Standard OWASP category (e.g., `A01:2021-Broken Access Control`, `A03:2021-Injection`).
3. **OWASP ASVS 5.0.0:** Exact version-qualified verification requirement (e.g., `v5.0.0-V5.3.4` for Parameterized Queries, `v5.0.0-V12.1.1` for SSRF).
4. **NIST SP 800-53 Rev. 5:** Exact security control identifier (e.g., `SI-10` Information Input Validation, `AC-3` Access Enforcement, `IA-2` Identification and Authentication).

---

## 2. Cryptographic Evidence Hashing

To ensure non-repudiation and evidence integrity across the vulnerability lifecycle:
- Every raw finding evidence record generates an immutable SHA-256 digest: `evidence_hash = sha256(observed_value + location)`.
- Exported reports (SARIF, JSON, HTML) include `evidence_hash` to prove evidence has not been tampered with post-detection.

---

## 3. Mandatory Multi-Stage Secret Masking

Sensitive credentials MUST be masked BEFORE storage, logging, SSE transmission, and reporting:
- **API Keys / JWTs / Bearer Tokens:** Retain first 6 and last 4 characters; mask middle with `******` (e.g., `eyJhbG******9abc`).
- **Passwords / Connection Strings:** Completely replace credential components (e.g., `postgres://user:********@db:5432/app`).
- **Private Keys:** Mask internal key material, preserving header and footer markers only.
