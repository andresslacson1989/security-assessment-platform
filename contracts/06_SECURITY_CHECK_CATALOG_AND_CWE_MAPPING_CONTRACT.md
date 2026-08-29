# Contract 06: Master Security Check Catalog & CWE / OWASP / NIST Taxonomy Contract

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 4.1.0 (Enterprise Hybrid Tool Adapter & Penetration Testing Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Canonical Security Rules, Vulnerability Taxonomy & Compliance Mapping  

---

## 1. Master Security Check Catalog (60+ Canonical Rules)

Every vulnerability or misconfiguration detected by the platform MUST reference a unique canonical `check_id` from this master catalog.

---

### 1.1 Network & TLS Infrastructure Checks (`network`)

| Check ID | Title | Severity | CVSS 3.1 | CWE ID | OWASP (2021) | NIST SP 800-53 | Detection Logic Summary |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| `NET-TLS-001` | Expired SSL/TLS Certificate | `CRITICAL` | 9.1 | CWE-295 | A02:Cryptographic Failures | SC-8, SC-13 | `notAfter` < current UTC timestamp. |
| `NET-TLS-002` | SSL/TLS Certificate Expiring Soon (< 7 Days) | `HIGH` | 7.5 | CWE-295 | A02:Cryptographic Failures | SC-8 | `notAfter` within 7 days of current UTC. |
| `NET-TLS-003` | SSL/TLS Certificate Expiring in < 30 Days | `MEDIUM` | 5.3 | CWE-295 | A02:Cryptographic Failures | SC-8 | `notAfter` within 30 days of current UTC. |
| `NET-TLS-004` | Certificate Hostname Mismatch | `HIGH` | 7.4 | CWE-297 | A02:Cryptographic Failures | SC-8 | Target domain not in Subject Alternative Names (SAN) or CN. |
| `NET-TLS-005` | Deprecated TLS 1.0 / 1.1 Protocol Enabled | `HIGH` | 7.5 | CWE-326 | A02:Cryptographic Failures | SC-13 | Server completes handshake when TLSv1.0 or TLSv1.1 is negotiated. |
| `NET-TLS-006` | Deprecated Ciphersuite Vulnerable to SWEET32 / 3DES | `MEDIUM` | 5.9 | CWE-327 | A02:Cryptographic Failures | SC-13 | Server negotiates 64-bit block cipher (3DES/DES). |
| `NET-DNS-001` | Missing or Incomplete SPF Record | `MEDIUM` | 5.3 | CWE-345 | A05:Security Misconfiguration | SI-8 | Root domain lacks `v=spf1` TXT record. |
| `NET-DNS-002` | Permissive SPF Record (`+all`) | `HIGH` | 7.5 | CWE-345 | A05:Security Misconfiguration | SI-8 | SPF TXT record contains `+all` allowing unauthorized mail sender spoofing. |
| `NET-DNS-003` | Missing DMARC Email Protection Record | `MEDIUM` | 5.3 | CWE-345 | A05:Security Misconfiguration | SI-8 | `_dmarc.{domain}` query returns `NXDOMAIN` or no `v=DMARC1` record. |
| `NET-DNS-004` | Permissive DMARC Policy (`p=none`) | `LOW` | 3.7 | CWE-345 | A05:Security Misconfiguration | SI-8 | DMARC policy set to `p=none` without quarantine or rejection enforcement. |
| `NET-DNS-005` | Missing CAA Record | `INFO` | 0.0 | CWE-1021 | A05:Security Misconfiguration | SC-8 | Domain lacks DNS `CAA` record (allows any CA to issue certificates). |
| `NET-DNS-006` | Missing MTA-STS or TLS-RPT Record | `LOW` | 3.5 | CWE-319 | A02:Cryptographic Failures | SC-8 | Missing `_mta-sts` or `_smtp._tls` TXT record for enforcing TLS in transit. |
| `NET-DNS-007` | Missing DNSSEC Deployment | `LOW` | 3.7 | CWE-345 | A05:Security Misconfiguration | SC-20, SC-21 | Domain zone lacks signed `DNSKEY` / `DS` / `RRSIG` records. |
| `NET-DNS-008` | DNS Zone Transfer (AXFR) Exposure | `HIGH` | 7.5 | CWE-200 | A01:Broken Access Control | AC-3, SC-7 | DNS server responds to AXFR request with complete zone dump. |
| `NET-PORT-001` | Exposed Database Port (MySQL 3306 / Postgres 5432) | `HIGH` | 7.5 | CWE-284 | A01:Broken Access Control | AC-3, SC-7 | TCP connection succeeds on port 3306 or 5432 from public network. |
| `NET-PORT-002` | Exposed In-Memory Cache (Redis 6379 / Mongo 27017) | `HIGH` | 7.5 | CWE-284 | A01:Broken Access Control | AC-3, SC-7 | TCP connection succeeds on port 6379, 27017, or 9200. |
| `NET-PORT-003` | Exposed Insecure Remote Management (Telnet 23 / FTP 21) | `HIGH` | 7.5 | CWE-319 | A02:Cryptographic Failures | AC-17, IA-2 | TCP connection succeeds on unencrypted port 21 or 23. |
| `NET-SVC-001` | Deprecated or Vulnerable Service Daemon Version Detected | `HIGH` | 7.5 | CWE-200 | A05:Security Misconfiguration | CM-6 | Service banner reveals outdated or vulnerable software version. |
| `NET-OSINT-001` | Dangling DNS CNAME / Subdomain Takeover Vulnerability | `CRITICAL` | 9.1 | CWE-284 | A01:Broken Access Control | AC-3, SC-7 | Subdomain CNAME points to unregistered third-party cloud service. |
| `NET-OSINT-002` | Sensitive Subdomain Discovered via Public Certificate Transparency | `MEDIUM` | 5.3 | CWE-200 | A05:Security Misconfiguration | CM-6 | Discovered public subdomain with sensitive prefix (admin, dev, staging, internal). |

---

### 1.2 Web Application & REST/GraphQL API DAST Checks (`web_dast`)

| Check ID | Title | Severity | CVSS 3.1 | CWE ID | OWASP (2021) | NIST SP 800-53 | Detection Logic Summary |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| `DAST-HDR-001` | Missing Content-Security-Policy (CSP) | `MEDIUM` | 5.0 | CWE-1021 | A05:Security Misconfiguration | SC-18, SI-10 | HTTP response headers lack `Content-Security-Policy`. |
| `DAST-HDR-002` | Missing Strict-Transport-Security (HSTS) | `MEDIUM` | 5.3 | CWE-319 | A05:Security Misconfiguration | SC-8, SC-13 | HTTPS endpoint lacks `Strict-Transport-Security` header. |
| `DAST-HDR-003` | Insufficient HSTS Max-Age Duration | `LOW` | 3.1 | CWE-319 | A05:Security Misconfiguration | SC-8 | `Strict-Transport-Security` `max-age` < 15552000 seconds (6 months). |
| `DAST-HDR-004` | Missing Anti-Clickjacking (X-Frame-Options) | `MEDIUM` | 4.3 | CWE-1021 | A05:Security Misconfiguration | SC-18 | Lacks `X-Frame-Options` and CSP lacks `frame-ancestors`. |
| `DAST-HDR-005` | Missing X-Content-Type-Options Header | `LOW` | 3.1 | CWE-79 | A05:Security Misconfiguration | SI-10 | Response lacks `X-Content-Type-Options: nosniff`. |
| `DAST-HDR-006` | Permissive Referrer-Policy Header | `LOW` | 3.1 | CWE-200 | A05:Security Misconfiguration | SC-8 | Lacks `Referrer-Policy` or set to `unsafe-url` / `no-referrer-when-downgrade`. |
| `DAST-HDR-007` | Detailed Server Version Disclosure | `LOW` | 3.1 | CWE-200 | A05:Security Misconfiguration | CM-6 | `Server` or `X-Powered-By` header exposes granular framework/version strings. |
| `DAST-COOKIE-001` | Cookie Missing HttpOnly Flag | `MEDIUM` | 5.3 | CWE-1004 | A05:Security Misconfiguration | SC-23 | Sensitive session cookie sent without `HttpOnly` flag. |
| `DAST-COOKIE-002` | Cookie Missing Secure Flag | `MEDIUM` | 5.3 | CWE-614 | A05:Security Misconfiguration | SC-8, SC-13 | Cookie set over HTTPS connection without `Secure` flag. |
| `DAST-COOKIE-003` | Cookie Missing or Permissive SameSite | `LOW` | 3.7 | CWE-1275 | A01:Broken Access Control | SC-23 | Cookie lacks `SameSite=Strict` or `SameSite=Lax`. |
| `DAST-CCH-001` | Missing Cache-Control on Sensitive Responses | `LOW` | 3.1 | CWE-524 | A05:Security Misconfiguration | SC-28 | Sensitive/authenticated page lacks `Cache-Control: no-store`. |
| `DAST-CORS-001` | Insecure CORS Origin Reflection with Credentials | `HIGH` | 8.1 | CWE-942 | A01:Broken Access Control | AC-3, SC-7 | Server reflects arbitrary `Origin` with `Access-Control-Allow-Credentials: true`. |
| `DAST-CORS-002` | Insecure CORS Wildcard with Credentials | `HIGH` | 7.5 | CWE-942 | A01:Broken Access Control | AC-3 | `Access-Control-Allow-Origin: *` configured alongside credential support. |
| `DAST-CORS-003` | CORS Trust of `null` Origin with Credentials | `HIGH` | 7.5 | CWE-942 | A01:Broken Access Control | AC-3 | Accepts `Origin: null` with `Access-Control-Allow-Credentials: true`. |
| `DAST-EXP-001` | Publicly Exposed Environment File (`.env`) | `CRITICAL` | 9.8 | CWE-552 | A01:Broken Access Control | AC-3, SC-28 | `/.env` returns HTTP 200 containing key/value configuration pairs. |
| `DAST-EXP-002` | Exposed Git Metadata Repository (`/.git/HEAD`) | `CRITICAL` | 9.8 | CWE-552 | A01:Broken Access Control | AC-3, SC-28 | `/.git/HEAD` returns HTTP 200 with `ref: refs/` signature. |
| `DAST-EXP-003` | Exposed Spring Boot Actuator API | `HIGH` | 7.5 | CWE-200 | A05:Security Misconfiguration | AC-3 | `/actuator/env` or `/actuator/health` reachable without authentication. |
| `DAST-EXP-004` | Publicly Exposed OpenAPI / Swagger Spec | `LOW` | 3.7 | CWE-200 | A05:Security Misconfiguration | AC-3 | `/swagger.json` or `/openapi.json` returns raw API definition without auth. |
| `DAST-METH-001` | Dangerous HTTP TRACE Method Enabled | `MEDIUM` | 4.3 | CWE-489 | A05:Security Misconfiguration | CM-6 | `TRACE` or `TRACK` request echoed back (Cross-Site Tracing risk). |
| `DAST-SRI-001` | Missing Subresource Integrity (SRI) on CDN Script | `LOW` | 3.7 | CWE-353 | A06:Vulnerable Components | SI-7 | Third-party `<script>` tag loaded from CDN lacks `integrity` attribute. |
| `DAST-MIX-001` | Passive Mixed Content Detected | `MEDIUM` | 4.3 | CWE-319 | A02:Cryptographic Failures | SC-8 | HTTPS page includes `http://` asset (script, image, stylesheet). |
| `DAST-GQL-001` | Public GraphQL Introspection Enabled | `MEDIUM` | 5.3 | CWE-200 | A05:Security Misconfiguration | AC-3 | GraphQL endpoint responds to `__schema` query with complete type graph. |
| `DAST-AUTH-001` | Insecure Authentication over Cleartext HTTP | `HIGH` | 7.5 | CWE-319 | A02:Cryptographic Failures | SC-8 | Login credentials or session cookies transmitted over unencrypted `http://`. |
| `DAST-AUTH-002` | Session Cookie Missing Security Flags post-Login | `HIGH` | 7.4 | CWE-614 | A05:Security Misconfiguration | SC-23 | Authenticated session cookie missing `HttpOnly`, `Secure`, or `SameSite`. |
| `DAST-AUTH-003` | Broken Access Control / Sensitive Endpoint Unprotected | `HIGH` | 8.5 | CWE-284 | A01:Broken Access Control | AC-3 | Protected authenticated endpoint returns HTTP 200 when unauthenticated. |
| `DAST-AUTH-004` | Sensitive Data in Authenticated Query Strings | `MEDIUM` | 5.3 | CWE-598 | A04:Insecure Design | SC-28 | Authenticated URL query string contains tokens, passwords, or PII. |
| `DAST-FORM-001` | Insecure Form Action Submitting over Cleartext HTTP | `HIGH` | 7.5 | CWE-319 | A02:Cryptographic Failures | SC-8 | HTML `<form>` action target points to unencrypted `http://` endpoint. |
| `DAST-FORM-002` | Missing Anti-CSRF Token in State-Changing Form | `MEDIUM` | 6.5 | CWE-352 | A01:Broken Access Control | SC-23 | HTML POST/PUT form lacks anti-CSRF hidden input field (`csrf_token`, `_token`). |
| `DAST-INJ-001` | SQL Injection Detected via Parameter Timing / Boolean Differential | `CRITICAL` | 9.8 | CWE-89 | A03:Injection | SI-10 | Response latency $\ge 2.0\text{s}$ on `SLEEP(2)` probe or differential hash divergence on `1=1` vs `1=2`. |
| `DAST-XSS-001` | Reflected Cross-Site Scripting (XSS) via Unescaped Canary Reflection | `HIGH` | 7.5 | CWE-79 | A03:Injection | SI-10 | Harmless canary token `_CYBERASSESS_XSS_<hex>_` echoed unescaped in response DOM/attributes. |
| `DAST-LFI-001` | Local File Inclusion / Path Traversal Detected | `HIGH` | 8.6 | CWE-22 | A01:Broken Access Control | AC-3, SI-10 | Traversal payload `../../../../etc/passwd` reflects `root:.*:0:0:` or `win.ini` signatures. |
| `DAST-SSTI-001` | Server-Side Template Injection (SSTI) Expression Evaluated | `CRITICAL` | 9.8 | CWE-1336 | A03:Injection | SI-10 | Mathematical probe `{{7*7}}` or `${7*7}` evaluates to `49` in rendered response. |
| `DAST-REDIR-001` | Open Redirection via Parameter Tampering | `MEDIUM` | 6.1 | CWE-601 | A01:Broken Access Control | AC-3 | Injected redirect target reflects in `Location:` header pointing to external domain. |

---

### 1.3 Static Code Analysis & Secrets SAST Checks (`code_sast`)

| Check ID | Title | Severity | CVSS 3.1 | CWE ID | OWASP (2021) | NIST SP 800-53 | Pattern / Target |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| `SAST-SEC-001` | Hardcoded AWS Access Key ID | `HIGH` | 8.6 | CWE-798 | A07:Identification & Auth | IA-5, SC-28 | `AKIA[0-9A-Z]{16}` |
| `SAST-SEC-002` | Hardcoded AWS Secret Access Key | `CRITICAL` | 9.8 | CWE-798 | A07:Identification & Auth | IA-5, SC-28 | `(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]` |
| `SAST-SEC-003` | Hardcoded GitHub Personal Access Token | `HIGH` | 8.5 | CWE-798 | A07:Identification & Auth | IA-5, SC-28 | `ghp_[0-9a-zA-Z]{36}` or `github_pat_[0-9a-zA-Z_]{82}` |
| `SAST-SEC-004` | Hardcoded Stripe Live Secret Key | `CRITICAL` | 9.1 | CWE-798 | A07:Identification & Auth | IA-5, SC-28 | `sk_live_[0-9a-zA-Z]{24,34}` |
| `SAST-SEC-005` | Hardcoded Google Cloud / Maps API Key | `HIGH` | 7.5 | CWE-798 | A07:Identification & Auth | IA-5, SC-28 | `AIza[0-9A-Za-z\\-_]{35}` |
| `SAST-SEC-006` | Hardcoded Slack Incoming Webhook URL | `MEDIUM` | 5.3 | CWE-798 | A07:Identification & Auth | IA-5 | `https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8}\/B[0-9A-Z]{8}\/[0-9a-zA-Z]{24}` |
| `SAST-SEC-007` | Unencrypted Private Cryptographic Key File | `CRITICAL` | 9.8 | CWE-321 | A02:Cryptographic Failures | SC-12, SC-28 | `-----BEGIN ((RSA\|EC\|DSA\|OPENSSH) )?PRIVATE KEY-----` |
| `SAST-SEC-008` | Hardcoded Database URI with Plaintext Password | `HIGH` | 8.6 | CWE-798 | A07:Identification & Auth | IA-5, SC-28 | `(postgres\|mysql\|mongodb\|redis):\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.-]+` |
| `SAST-SEC-009` | Hardcoded Internal IP Address / Hostname | `LOW` | 3.1 | CWE-200 | A05:Security Misconfiguration | CM-6 | Hardcoded RFC 1918 private IPs or `.corp` hostnames in code. |
| `SAST-GIT-001` | Exposed Cryptographic Secret in Historical Git Commit | `HIGH` | 8.6 | CWE-798 | A07:Identification & Auth | IA-5, SC-28 | Regex and Shannon entropy scan of git log history detects unmasked secrets in past commits. |
| `SAST-CRY-001` | Broken Cryptographic Hash Function (MD5/SHA1) | `MEDIUM` | 5.3 | CWE-328 | A02:Cryptographic Failures | SC-13 | Use of `hashlib.md5`, `hashlib.sha1`, `crypto.createHash('md5')`. |
| `SAST-CRY-002` | Insecure Pseudo-Random Number Generator (PRNG) | `HIGH` | 7.5 | CWE-338 | A02:Cryptographic Failures | SC-13 | `random.random()`, `Math.random()` used in token/auth generation. |
| `SAST-CRY-003` | Insecure Symmetric Cipher Mode (AES-ECB) | `HIGH` | 7.5 | CWE-327 | A02:Cryptographic Failures | SC-13 | AES configured in Electronic Codebook (`ECB`) mode. |
| `SAST-INJ-001` | Raw SQL Query String Formatting / Concatenation | `HIGH` | 8.5 | CWE-89 | A03:Injection | SI-10 | Direct variable interpolation into `cursor.execute(...)`. |
| `SAST-INJ-002` | Unsafe Shell Execution (`shell=True`, `system()`) | `HIGH` | 8.5 | CWE-78 | A03:Injection | SI-10 | Variable passed to `subprocess.Popen(..., shell=True)` or `os.system()`. |
| `SAST-INJ-003` | Unsafe Object Deserialization | `HIGH` | 8.5 | CWE-502 | A08:Software Integrity | SI-10 | Usage of `pickle.loads()`, `yaml.load(..., Loader=Loader)`. |
| `SAST-TAINT-001` | Unsanitized User Input Flows into Database Execution Sink | `CRITICAL` | 9.8 | CWE-89 | A03:Injection | SI-10 | Interprocedural AST taint flow from HTTP input source into database execution sink. |
| `SAST-TAINT-002` | Unsanitized User Input Flows into OS Command Execution Sink | `CRITICAL` | 9.8 | CWE-78 | A03:Injection | SI-10 | AST taint flow from user input source into `subprocess` or `os.system` execution sink. |
| `SAST-DEP-001` | Vulnerable Pinned Dependency (Known CVE) | `HIGH` | 7.5 | CWE-1395 | A06:Vulnerable Components | SA-15, SI-2 | Matching package version against vulnerability database. |
| `SAST-DEP-002` | Unpinned / Wildcard Dependency Version | `LOW` | 3.7 | CWE-1104 | A06:Vulnerable Components | SA-15 | Manifest contains `*` or `>=0.0.0` wildcard dependencies. |

---

### 1.4 Infrastructure-as-Code & Container IaC Checks (`infra_iac`)

| Check ID | Title | Severity | CVSS 3.1 | CWE ID | OWASP (2021) | NIST SP 800-53 | Detection Logic Summary |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| `IAC-DOCK-001` | Container Running as Root User | `HIGH` | 7.8 | CWE-250 | A05:Security Misconfiguration | AC-6, CM-7 | Dockerfile omits `USER` directive or specifies `USER root`. |
| `IAC-DOCK-002` | Base Image Uses Unpinned / Latest Tag | `MEDIUM` | 5.3 | CWE-1104 | A06:Vulnerable Components | SA-15, CM-6 | `FROM <image>` lacks tag or specifies `:latest`. |
| `IAC-DOCK-003` | Missing Container HEALTHCHECK Instruction | `LOW` | 3.1 | CWE-1021 | A05:Security Misconfiguration | SI-4 | Dockerfile lacks `HEALTHCHECK` directive. |
| `IAC-DOCK-004` | Plaintext Secret Embedded in ENV / ARG Instruction | `HIGH` | 7.5 | CWE-798 | A07:Identification & Auth | IA-5, SC-28 | `ENV` or `ARG` sets variable containing `SECRET`, `PASSWORD`, `API_KEY`. |
| `IAC-DOCK-005` | Package Manager Cache Retained in Layer | `LOW` | 2.5 | CWE-1021 | A05:Security Misconfiguration | CM-6 | `RUN apt-get` lacks `rm -rf /var/lib/apt/lists/*`. |
| `IAC-DOCK-006` | Insecure Usage of Sudo in RUN Command | `MEDIUM` | 6.5 | CWE-250 | A05:Security Misconfiguration | AC-6 | `RUN` command contains `sudo` execution inside container. |
| `IAC-CMP-001` | Docker Compose Service with `privileged: true` | `HIGH` | 8.5 | CWE-250 | A05:Security Misconfiguration | AC-6 | `docker-compose.yml` service specifies `privileged: true`. |
| `IAC-CMP-002` | Docker Socket Mounted in Compose (`docker.sock`) | `CRITICAL` | 9.0 | CWE-250 | A01:Broken Access Control | AC-6, SC-7 | Container mounts host `/var/run/docker.sock`. |
| `IAC-CMP-003` | Database Port Bound to Host 0.0.0.0 Interface | `HIGH` | 7.5 | CWE-284 | A01:Broken Access Control | AC-3, SC-7 | `ports: ["3306:3306"]` exposed without binding to `127.0.0.1`. |
| `IAC-K8S-001` | Kubernetes Pod with Privileged Escalation | `HIGH` | 8.5 | CWE-250 | A05:Security Misconfiguration | AC-6 | Manifest specifies `securityContext.privileged: true`. |
| `IAC-K8S-002` | Kubernetes Pod Sharing Host Namespace | `HIGH` | 7.8 | CWE-250 | A05:Security Misconfiguration | AC-6 | Manifest specifies `hostPID: true` or `hostNetwork: true`. |
| `IAC-K8S-003` | Kubernetes Pod Missing Read-Only Root Filesystem | `LOW` | 3.7 | CWE-250 | A05:Security Misconfiguration | CM-7 | Manifest omits `securityContext.readOnlyRootFilesystem: true`. |
| `IAC-K8S-004` | Kubernetes Pod Missing Resource Limits | `LOW` | 3.7 | CWE-400 | A05:Security Misconfiguration | SC-6 | Manifest omits `resources.limits.cpu` or `resources.limits.memory`. |
| `IAC-TF-001` | Terraform S3 / Storage Bucket with Public Access | `HIGH` | 8.2 | CWE-284 | A01:Broken Access Control | AC-3, SC-28 | `aws_s3_bucket_acl` set to `public-read` or missing public access block. |
| `IAC-TF-002` | Terraform Security Group Allows 0.0.0.0/0 on SSH/RDP | `HIGH` | 7.5 | CWE-284 | A01:Broken Access Control | AC-3, SC-7 | Ingress rule allows `0.0.0.0/0` on port 22 or 3389. |
| `IAC-TF-003` | Terraform Storage Volume Missing Encryption at Rest | `MEDIUM` | 5.3 | CWE-311 | A02:Cryptographic Failures | SC-28 | Storage resource sets `encrypted = false` or omits KMS encryption. |
| `IAC-TF-004` | Terraform Overly Permissive IAM Wildcard Policy | `HIGH` | 8.1 | CWE-732 | A01:Broken Access Control | AC-6 | IAM policy specifies `Action: "*"` on `Resource: "*"`. |

---

### 1.5 CI/CD Pipeline & Build Security Checks (`cicd_audit`)

| Check ID | Title | Severity | CVSS 3.1 | CWE ID | OWASP (2021) | NIST SP 800-53 | Detection Logic Summary |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| `CICD-GHA-001` | Insecure `pull_request_target` with Checkout | `HIGH` | 8.5 | CWE-829 | A08:Software Integrity | SA-10, SI-7 | Workflow triggers on `pull_request_target` and checks out untrusted PR head. |
| `CICD-GHA-002` | Unpinned Third-Party Action Version | `MEDIUM` | 5.3 | CWE-1104 | A08:Software Integrity | SA-15 | `uses: actions/...@main` or `@master` instead of immutable commit SHA. |
| `CICD-GHA-003` | Script Injection via GitHub Expression Context | `HIGH` | 8.5 | CWE-78 | A03:Injection | SI-10 | Untrusted expression (e.g. `${{ github.event.issue.title }}`) in inline `run:`. |
| `CICD-GHA-004` | Overly Permissive Default GITHUB_TOKEN | `MEDIUM` | 6.0 | CWE-250 | A05:Security Misconfiguration | AC-6 | Workflow specifies `permissions: write-all` or omits explicit permissions block. |

---

## 2. External Tool Vulnerability Normalization & Taxonomy Mapping Rules

When findings are produced by external tool adapters, they MUST be normalized into canonical `Finding` objects following these deterministic taxonomy mapping rules:

| Originating Tool | Raw Finding Source | Canonical Check ID Mapping | Target Category | Default CVSS 3.1 | Canonical CWE |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **Nmap** | Exposed Port | `NET-PORT-001` / `002` / `003` | Network Infrastructure | 7.5 | CWE-284 |
| **Nmap** | Outdated Service Banner | `NET-SVC-001` | Service Posture | 7.5 | CWE-200 |
| **Nuclei** | `http/cves/*` (CVE-YYYY-XXXX) | `DAST-INJ-001` or `DAST-EXP-001` | Web Vulnerability | From Nuclei (Mapped to 9.8/7.5/5.3) | Mapped from Nuclei metadata |
| **Nuclei** | `http/misconfiguration/*` | `DAST-HDR-xxx` or `DAST-CORS-xxx` | Misconfiguration | 5.0 - 7.5 | CWE-16 / CWE-942 |
| **Semgrep** | Rule matching SQL injection | `SAST-TAINT-001` | Code Injection | 9.8 | CWE-89 |
| **Semgrep** | Rule matching Command injection | `SAST-TAINT-002` | Code Injection | 9.8 | CWE-78 |
| **Semgrep** | Rule matching Hardcoded Key | `SAST-SEC-xxx` | Hardcoded Secrets | 7.5 - 9.8 | CWE-798 |
| **Trivy** | Package Dependency CVE | `SAST-DEP-001` | Vulnerable Dependencies | From CVE CVSS | CWE-1395 |
| **Trivy** | Dockerfile misconfiguration | `IAC-DOCK-xxx` | Container Posture | 7.8 | CWE-250 |

