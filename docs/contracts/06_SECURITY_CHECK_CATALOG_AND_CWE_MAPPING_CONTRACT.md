# Contract 06: Security Check Catalog, ASVS 5.0.0, CWE Mappings & Evidence Hashing

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 14.0.0 (ASVS 5.0.0 Version-Qualified Mapping, NIST SP 800-53 Control Mapping, 26-Tool Fleet Catalog & Cryptographic Hashing)  
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

## 2. Canonical Security Check Catalog

| Check ID | Title | CWE ID | OWASP Category | ASVS 5.0 Control | NIST SP 800-53 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `DAST-INJ-001` | SQL Injection (In-band, Error, Blind, Time-based) | `CWE-89` | `A03:2021-Injection` | `v5.0.0-V5.3.4` | `SI-10` |
| `DAST-INJ-002` | Reflected Cross-Site Scripting (XSS) | `CWE-79` | `A03:2021-Injection` | `v5.0.0-V5.3.3` | `SI-10` |
| `DAST-INJ-003` | Stored Cross-Site Scripting (XSS) | `CWE-79` | `A03:2021-Injection` | `v5.0.0-V5.3.1` | `SI-10` |
| `DAST-INJ-004` | Local File Inclusion (LFI) & Path Traversal | `CWE-22` | `A01:2021-Broken Access Control` | `v5.0.0-V12.3.1` | `AC-3` |
| `DAST-INJ-005` | Server-Side Template Injection (SSTI) | `CWE-1336` | `A03:2021-Injection` | `v5.0.0-V5.2.4` | `SI-10` |
| `DAST-SSRF-001`| Server-Side Request Forgery & Metadata Extraction | `CWE-918` | `A10:2021-SSRF` | `v5.0.0-V12.1.1` | `AC-4` |
| `DAST-AUTH-001`| Missing Anti-CSRF Token on State-Changing Action | `CWE-352` | `A01:2021-Broken Access Control` | `v5.0.0-V4.2.2` | `AC-3` |
| `DAST-AUTH-002`| Insecure Session Cookie Flags (Missing HttpOnly/Secure) | `CWE-614` | `A05:2021-Security Misconfiguration` | `v5.0.0-V3.4.1` | `AC-3` |
| `DAST-AUTH-003`| Broken Object Level Authorization (BOLA / IDOR) | `CWE-639` | `A01:2021-Broken Access Control` | `v5.0.0-V4.1.1` | `AC-3` |
| `DAST-CORS-001`| Overly Permissive CORS Policy with Credentials | `CWE-942` | `A05:2021-Security Misconfiguration` | `v5.0.0-V14.4.6` | `AC-4` |
| `DAST-HDR-001` | Missing Content-Security-Policy (CSP) Header | `CWE-1021` | `A05:2021-Security Misconfiguration` | `v5.0.0-V14.4.1` | `SC-8` |
| `DAST-HDR-002` | Missing Strict-Transport-Security (HSTS) Header | `CWE-319` | `A05:2021-Security Misconfiguration` | `v5.0.0-V9.1.2` | `SC-8` |
| `DAST-HDR-003` | Missing X-Frame-Options / Clickjacking Protection | `CWE-1021` | `A05:2021-Security Misconfiguration` | `v5.0.0-V14.4.2` | `SC-8` |
| `DAST-HDR-004` | Missing X-Content-Type-Options (MIME Sniffing Risk) | `CWE-693` | `A05:2021-Security Misconfiguration` | `v5.0.0-V14.4.3` | `SC-8` |
| `DAST-API-001` | GraphQL Introspection Exposed in Production | `CWE-200` | `A05:2021-Security Misconfiguration` | `v5.0.0-V13.1.1` | `CM-7` |
| `DAST-API-002` | Swagger / OpenAPI Schema Publicly Accessible | `CWE-215` | `A05:2021-Security Misconfiguration` | `v5.0.0-V13.1.2` | `CM-7` |
| `DAST-REDIR-001`| Unvalidated Open URL Redirection | `CWE-601` | `A01:2021-Broken Access Control` | `v5.0.0-V5.1.5` | `AC-3` |
| `NET-PORT-001` | Exposed Administrative Remote Management Port | `CWE-284` | `A05:2021-Security Misconfiguration` | `v5.0.0-V14.1.1` | `AC-17` |
| `NET-PORT-002` | Exposed Database / In-Memory Cache Port | `CWE-284` | `A05:2021-Security Misconfiguration` | `v5.0.0-V14.1.2` | `AC-3` |
| `NET-TLS-001`  | Deprecated SSL/TLS Protocol (SSLv3, TLS 1.0/1.1) | `CWE-326` | `A02:2021-Cryptographic Failures` | `v5.0.0-V9.1.1` | `SC-8` |
| `NET-TLS-002`  | Expired, Self-Signed or Untrusted TLS Certificate | `CWE-295` | `A02:2021-Cryptographic Failures` | `v5.0.0-V9.2.1` | `SC-8` |
| `NET-DNS-001`  | Missing or Permissive Email SPF/DMARC Record | `CWE-345` | `A05:2021-Security Misconfiguration` | `v5.0.0-V14.3.1` | `SI-8` |
| `NET-DNS-002`  | Unrestricted DNS Zone Transfer (AXFR) | `CWE-200` | `A05:2021-Security Misconfiguration` | `v5.0.0-V14.3.2` | `CM-7` |
| `NET-SUB-001`  | Dangling DNS CNAME & Subdomain Takeover Risk | `CWE-284` | `A05:2021-Security Misconfiguration` | `v5.0.0-V14.3.3` | `SC-20` |
| `NET-ORIG-001` | Direct Origin IP Exposure (Cloudflare/CDN Bypass) | `CWE-200` | `A05:2021-Security Misconfiguration` | `v5.0.0-V14.1.3` | `SC-7` |
| `NET-SMB-001`  | Missing SMB Signing & NTLM Relay Exposure | `CWE-294` | `A07:2021-Identification & Auth` | `v5.0.0-V9.1.3` | `AC-3` |
| `NET-LLMNR-001`| Active LLMNR / NBT-NS Broadcast Name Resolution | `CWE-294` | `A07:2021-Identification & Auth` | `v5.0.0-V14.1.4` | `SC-8` |
| `AUTH-STUFF-001`| Missing Rate Limiting on Authentication Endpoint | `CWE-307` | `A07:2021-Identification & Auth` | `v5.0.0-V2.2.1` | `IA-2` |
| `HOST-PRIV-001`| Dangerous SUID Binaries & GTFOBins Privilege Escalation | `CWE-250` | `A01:2021-Broken Access Control` | `v5.0.0-V1.4.2` | `AC-6` |
| `HOST-SUDO-001`| Insecure Sudoers `NOPASSWD` Privilege Escalation Vector | `CWE-250` | `A01:2021-Broken Access Control` | `v5.0.0-V1.4.3` | `AC-6` |
| `SAST-SEC-001` | Hardcoded High-Entropy Secret or Cloud Credential | `CWE-798` | `A07:2021-Identification & Auth` | `v5.0.0-V3.6.1` | `IA-2` |
| `SAST-CMD-001` | OS Command Injection | `CWE-78` | `A03:2021-Injection` | `v5.0.0-V5.2.2` | `SI-10` |
| `SAST-CODE-001`| Unsafe Deserialization & Dynamic Code Execution | `CWE-502` | `A08:2021-Integrity Failures` | `v5.0.0-V5.5.3` | `SI-10` |
| `SAST-CRYP-001`| Broken / Weak Cryptographic Algorithm (MD5/SHA1) | `CWE-327` | `A02:2021-Cryptographic Failures` | `v5.0.0-V6.2.1` | `SC-13` |
| `SAST-CRYP-002`| Insecure Pseudo-Random Number Generator (PRNG) | `CWE-338` | `A02:2021-Cryptographic Failures` | `v5.0.0-V6.3.1` | `SC-13` |
| `SAST-DEP-001` | Vulnerable Third-Party Library / Package CVE | `CWE-1395`| `A06:2021-Vulnerable Components` | `v5.0.0-V14.2.1` | `SA-12` |
| `IAC-DOCKER-001`| Docker Container Process Running as Root User | `CWE-250` | `A05:2021-Security Misconfiguration` | `v5.0.0-V1.4.4` | `AC-6` |
| `IAC-DOCKER-002`| Sensitive Secret / Token Baked into Image Layer | `CWE-522` | `A07:2021-Identification & Auth` | `v5.0.0-V3.6.2` | `IA-2` |
| `IAC-K8S-001`  | Privileged Pod / HostPID / HostNetwork Mount | `CWE-732` | `A05:2021-Security Misconfiguration` | `v5.0.0-V1.4.5` | `AC-6` |
| `IAC-TF-001`   | Publicly Exposed Cloud Storage Bucket (S3/Blob) | `CWE-732` | `A01:2021-Broken Access Control` | `v5.0.0-V1.1.3` | `AC-3` |
| `IAC-TF-002`   | Unrestricted Ingress Rule (`0.0.0.0/0`) on Sensitive Port | `CWE-284` | `A05:2021-Security Misconfiguration` | `v5.0.0-V14.1.5` | `AC-4` |
| `CICD-SEC-001` | Untrusted Pull Request Action Execution & Script Injection | `CWE-78` | `A08:2021-Integrity Failures` | `v5.0.0-V14.2.2` | `SA-10` |
| `CICD-PERM-001`| Over-Privileged CI/CD Pipeline Token (`write-all`) | `CWE-276` | `A01:2021-Broken Access Control` | `v5.0.0-V1.4.6` | `AC-6` |

---

## 3. Cryptographic Evidence Hashing

To ensure non-repudiation and evidence integrity across the vulnerability lifecycle:
- Every raw finding evidence record generates an immutable SHA-256 digest: `evidence_hash = sha256(observed_value + location)`.
- Exported reports (SARIF, JSON, HTML) include `evidence_hash` to prove evidence has not been tampered with post-detection.

---

## 4. Mandatory Multi-Stage Secret Masking

Sensitive credentials MUST be masked BEFORE storage, logging, SSE transmission, and reporting:
- **API Keys / JWTs / Bearer Tokens:** Retain first 6 and last 4 characters; mask middle with `******` (e.g., `eyJhbG******9abc`).
- **Passwords / Connection Strings:** Completely replace credential components (e.g., `postgres://user:********@db:5432/app`).
- **Private Keys:** Mask internal key material, preserving header and footer markers only.
