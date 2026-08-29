# Contract 03: Engine Plugin Interface & Module Implementation Contract

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 3.0.0 (Comprehensive Production Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Assessment Engine Plugins, Submodules & Execution Lifecycle  

---

## 1. Abstract Engine Interface (`BaseAssessmentEngine`)

Every assessment engine MUST subclass `BaseAssessmentEngine` defined in `backend/app/engines/base.py` and implement all abstract properties and methods.

```python
from abc import ABC, abstractmethod
from typing import List, Callable, Awaitable, Optional
from app.core.models import Target, Finding, ScanConfig, LogLevel

# Asynchronous callback signatures for real-time telemetry streaming
LogCallback = Callable[[LogLevel, str], Awaitable[None]]
ProgressCallback = Callable[[int, str], Awaitable[None]]
FindingCallback = Callable[[Finding], Awaitable[None]]

class BaseAssessmentEngine(ABC):
    """
    Authoritative abstract interface for all assessment engine plugins.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique machine identifier (e.g., 'network', 'web_dast', 'code_sast', 'infra_iac', 'cicd_audit')."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable display name for dashboard UI."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Detailed description of the security domain assessed by this engine."""
        pass

    @abstractmethod
    def is_applicable(self, target: Target) -> bool:
        """
        Determines whether this engine can execute against the provided target type.
        - network: URL, DOMAIN, IP
        - web_dast: URL, DOMAIN
        - code_sast: LOCAL_PATH
        - infra_iac: DOCKERFILE, IAC_MANIFEST, LOCAL_PATH
        - cicd_audit: LOCAL_PATH
        """
        pass

    @abstractmethod
    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        emit_finding: FindingCallback
    ) -> List[Finding]:
        """
        Executes the engine's assessment checks asynchronously.
        
        Args:
            target: Validated target entity.
            config: Scan options (timeout, rate limit, headers, etc.).
            emit_log: Async callable to stream real-time log messages.
            emit_progress: Async callable to stream stage and progress percentage.
            emit_finding: Async callable to stream findings immediately when discovered.
            
        Returns:
            List of normalized Finding objects.
        """
        pass
```

---

## 2. Resilience, Error Isolation & Lifecycle Guarantees

1. **Zero Cascade Failure Guarantee:**
   - Any unhandled exception (e.g., `socket.timeout`, `httpx.ConnectError`, `dns.resolver.NXDOMAIN`, `yaml.YAMLError`) MUST be caught inside the engine check boundary.
   - The engine logs the event via `emit_log(LogLevel.WARNING, ...)` and continues remaining checks.
2. **Cancellation Responsiveness:**
   - Async loops across checks MUST check for cancellation (`asyncio.CancelledError`). When cancelled, active sockets/HTTP connections MUST be closed gracefully within 500ms.
3. **Strict Timeout Bounds:**
   - All network connections and socket operations MUST be bounded by explicit timeouts (HTTP $\le$ 10s, Socket $\le$ 2s, DNS $\le$ 3s).

---

## 3. Detailed Specifications for Core Engines & Submodules

---

### 3.1 Engine 1: Network, TLS & DNS Auditor (`network`)

**Identifier:** `network`  
**Display Name:** Network & TLS Infrastructure Auditor  
**Applicable Target Types:** `URL`, `DOMAIN`, `IP`

#### Submodules:
1. **`tls_auditor.py` (SSL/TLS Certificate, Protocols & Ciphers)**
   - **`NET-TLS-001` (Expired SSL/TLS Certificate):** Inspects `notAfter` timestamp. Triggered if expired (CRITICAL, CVSS 9.1).
   - **`NET-TLS-002` (SSL/TLS Certificate Expiring Soon):** Triggered if expiring within 7 days (HIGH, CVSS 7.5).
   - **`NET-TLS-003` (SSL/TLS Certificate Expiring in <30 Days):** Triggered if expiring in 30 days (MEDIUM, CVSS 5.3).
   - **`NET-TLS-004` (Hostname Mismatch / Self-Signed):** Validates SANs and CN (HIGH, CVSS 7.4).
   - **`NET-TLS-005` (Deprecated TLS 1.0 / 1.1 Enabled):** Handshake with TLSv1.0/1.1 context (HIGH, CVSS 7.5).
   - **`NET-TLS-006` (Insecure SSLv3 Enabled - POODLE):** Handshake with SSLv3 (CRITICAL, CVSS 9.0).
   - **`NET-TLS-007` (Weak Cipher Suites):** Detects RC4, 3DES, DES, export ciphers (HIGH, CVSS 7.5).

2. **`dns_hygiene.py` (DNS Email Security, DNSSEC & Zone Hygiene)**
   - **`NET-DNS-001` (Missing / Incomplete SPF Record):** Queries `TXT` for `v=spf1` (MEDIUM, CVSS 5.3).
   - **`NET-DNS-002` (Permissive SPF `+all`):** Detects insecure `+all` mechanism (HIGH, CVSS 7.5).
   - **`NET-DNS-003` (Missing DMARC Record):** Queries `_dmarc.{domain}` for `v=DMARC1` (MEDIUM, CVSS 5.3).
   - **`NET-DNS-004` (Permissive DMARC Policy `p=none`):** Detects unenforced policy (LOW, CVSS 3.7).
   - **`NET-DNS-005` (Missing CAA Record):** Queries `CAA` record (INFO, CVSS 0.0).
   - **`NET-DNS-006` (Missing MTA-STS / TLS-RPT):** Queries `_mta-sts.{domain}` and `_smtp._tls.{domain}` (LOW, CVSS 3.5).
   - **`NET-DNS-007` (Missing DNSSEC Deployment):** Queries `DNSKEY` and `DS` records (LOW, CVSS 3.7).
   - **`NET-DNS-008` (DNS Zone Transfer AXFR Exposure):** Sends non-destructive AXFR query to check if unauthenticated zone dump is permitted (HIGH, CVSS 7.5).
   - **`NET-DNS-009` (BIMI Email Alignment):** Queries `default._bimi.{domain}` (INFO, CVSS 0.0).

3. **`port_checker.py` (Exposed Service Port Scanner)**
   - Concurrently checks critical service ports with 1.5s non-blocking timeout:
     - `21` (FTP), `22` (SSH), `23` (Telnet), `3306` (MySQL), `5432` (PostgreSQL), `6379` (Redis), `27017` (MongoDB), `9200` (Elasticsearch), `8080` (Alt-HTTP), `8443` (Alt-HTTPS).
   - **`NET-PORT-001`:** Exposed Database Port (MySQL 3306 / Postgres 5432) (HIGH, CVSS 7.5).
   - **`NET-PORT-002`:** Exposed In-Memory Cache (Redis 6379 / Mongo 27017 / Elasticsearch 9200) (HIGH, CVSS 7.5).
   - **`NET-PORT-003`:** Exposed Insecure Remote Management (Telnet 23 / FTP 21) (HIGH, CVSS 7.5).

---

### 3.2 Engine 2: Web Application & API DAST (`web_dast`)

**Identifier:** `web_dast`  
**Display Name:** Web Application, Browser Security & REST/GraphQL API DAST  
**Applicable Target Types:** `URL`, `DOMAIN`

#### Submodules:
1. **`headers_cookies.py` (Security Headers & Cookie Flags)**
   - **`DAST-HDR-001`:** Missing `Content-Security-Policy` (MEDIUM, CVSS 5.0).
   - **`DAST-HDR-002`:** Missing `Strict-Transport-Security` (MEDIUM, CVSS 5.3).
   - **`DAST-HDR-003`:** Insufficient HSTS Max-Age (< 6 months) (LOW, CVSS 3.1).
   - **`DAST-HDR-004`:** Missing `X-Frame-Options` (MEDIUM, CVSS 4.3).
   - **`DAST-HDR-005`:** Missing `X-Content-Type-Options: nosniff` (LOW, CVSS 3.1).
   - **`DAST-HDR-006`:** Permissive `Referrer-Policy` (LOW, CVSS 3.1).
   - **`DAST-HDR-007`:** Detailed Server Version Disclosure (`Server`, `X-Powered-By`) (LOW, CVSS 3.1).
   - **`DAST-HDR-008`:** Missing `Permissions-Policy` (LOW, CVSS 3.1).
   - **`DAST-HDR-009`:** Missing Cross-Origin Isolation (`COOP`, `COEP`, `CORP`) (LOW, CVSS 3.1).
   - **`DAST-COOKIE-001`:** Cookie missing `HttpOnly` flag (MEDIUM, CVSS 5.3).
   - **`DAST-COOKIE-002`:** Cookie missing `Secure` flag on HTTPS (MEDIUM, CVSS 5.3).
   - **`DAST-COOKIE-003`:** Cookie missing or improper `SameSite` attribute (LOW, CVSS 3.7).
   - **`DAST-CCH-001`:** Missing `Cache-Control: no-store` on sensitive responses (LOW, CVSS 3.1).

2. **`cors_analyzer.py` (CORS Misconfiguration Analyzer)**
   - **`DAST-CORS-001`:** Insecure CORS Origin Reflection with Credentials (`Origin: https://evil-attacker.com`) (HIGH, CVSS 8.1).
   - **`DAST-CORS-002`:** Insecure CORS Wildcard with Credentials (HIGH, CVSS 7.5).
   - **`DAST-CORS-003`:** CORS Trust of `null` Origin with Credentials (HIGH, CVSS 7.5).

3. **`api_inspector.py` (Sensitive Exposure & Methods)**
   - **`DAST-EXP-001`:** Publicly Exposed `.env` file (CRITICAL, CVSS 9.8).
   - **`DAST-EXP-002`:** Exposed Git Metadata Repository (`/.git/HEAD`) (CRITICAL, CVSS 9.8).
   - **`DAST-EXP-003`:** Exposed Spring Boot Actuator (`/actuator/env`, `/actuator/health`) (HIGH, CVSS 7.5).
   - **`DAST-EXP-004`:** Exposed OpenAPI / Swagger Specification (`/swagger.json`, `/openapi.json`) without auth (LOW, CVSS 3.7).
   - **`DAST-METH-001`:** Dangerous HTTP `TRACE` Method Enabled (MEDIUM, CVSS 4.3).

4. **`browser_posture.py` (DOM & Asset Posture)**
   - **`DAST-SRI-001`:** Missing Subresource Integrity (`integrity=`) on external CDN scripts (LOW, CVSS 3.7).
   - **`DAST-MIX-001`:** Passive Mixed Content (HTTP assets embedded on HTTPS page) (MEDIUM, CVSS 4.3).

5. **`graphql_auditor.py` (GraphQL Posture)**
   - **`DAST-GQL-001`:** Public GraphQL Introspection Enabled (MEDIUM, CVSS 5.3).

6. **`crawler.py` (Scoped Multi-Page Discovery & BFS Spider)**
   - **Link & Route Discovery:** Discovers internal links from `<a href>`, `<link rel>`, `<script src>`, and HTML5 route triggers up to configured `max_depth` (default: 3) and `max_pages` (default: 50).
   - **Sitemap & Robots Parser:** Seeds crawl queue from `robots.txt` and `sitemap.xml` (or `sitemap_index.xml`).
   - **Same-Origin Policy Guard:** Strictly enforces domain/subdomain boundaries, rejecting third-party domains.
   - **Normalization & Deduplication:** Strips URL fragments (`#`), normalizes query parameters, and maintains SHA-256 visited set to avoid infinite crawl loops.
   - **Form Discovery:** Identifies and registers all `<form>` elements (action URL, method, input fields) for security analysis.

7. **`auth_session.py` (Authentication & State Manager)**
   - **Authentication Handlers:** Supports `HEADER` (Bearer/API Key), `COOKIE` (session cookie injection), and `FORM_LOGIN` (automated login submission).
   - **Automated Login & Anti-CSRF:** Fetches login page, extracts anti-CSRF tokens (`csrf_token`, `_csrf`, `authenticity_token`, `_token`), posts credentials, and stores session cookies.
   - **Logout Route Blacklisting:** Automatically filters out URLs matching logout patterns (`*logout*`, `*signout*`, etc.) to prevent premature session invalidation.
   - **Session Heartbeat & Recovery:** Checks response codes and `logged_in_indicator` keyword; automatically re-authenticates upon 401/403 or login redirect.
   - **`DAST-AUTH-001` (Insecure Authentication over Cleartext HTTP):** Form login submitted or authenticated over HTTP (HIGH, CVSS 7.5).
   - **`DAST-AUTH-002` (Session Cookie Lacks Security Attributes):** Session cookie missing `HttpOnly`, `Secure`, or `SameSite` post-authentication (HIGH, CVSS 7.4).
   - **`DAST-AUTH-003` (Broken Access Control / Sensitive Endpoint Unprotected):** Protected authenticated endpoint accessible unauthenticated returning HTTP 200 with sensitive payload (HIGH, CVSS 8.5).
   - **`DAST-AUTH-004` (Sensitive Data in Authenticated Query Strings):** Session tokens, passwords, or PII exposed in URL query parameters (MEDIUM, CVSS 5.3).
   - **`DAST-FORM-001` (Insecure Cleartext Form Action):** HTML `<form>` action target uses unencrypted `http://` (HIGH, CVSS 7.5).
   - **`DAST-FORM-002` (Missing Anti-CSRF Token in State-Changing Form):** POST/PUT `<form>` lacks anti-CSRF token input field (MEDIUM, CVSS 6.5).

---

### 3.3 Engine 3: Static Code Analysis, Secrets & SCA (`code_sast`)

**Identifier:** `code_sast`  
**Display Name:** Static Code Analysis, Secrets, Cryptography & Dependencies  
**Applicable Target Types:** `LOCAL_PATH`

#### Submodules:
1. **`secret_scanner.py` (40+ Regex Patterns & High-Entropy Scanner)**
   - Scans files with regex matching + Shannon Entropy ($H \ge 4.5$):
     - **`SAST-SEC-001`:** AWS Access Key ID (`AKIA...`) (HIGH, CVSS 8.6).
     - **`SAST-SEC-002`:** AWS Secret Access Key (CRITICAL, CVSS 9.8).
     - **`SAST-SEC-003`:** GitHub PAT (`ghp_...`, `github_pat_...`) (HIGH, CVSS 8.5).
     - **`SAST-SEC-004`:** Stripe Secret Key (`sk_live_...`) (CRITICAL, CVSS 9.1).
     - **`SAST-SEC-005`:** Google Cloud API Key (`AIza...`) (HIGH, CVSS 7.5).
     - **`SAST-SEC-006`:** Slack Webhook URL (MEDIUM, CVSS 5.3).
     - **`SAST-SEC-007`:** Unencrypted Private Cryptographic Key File (`-----BEGIN PRIVATE KEY-----`) (CRITICAL, CVSS 9.8).
     - **`SAST-SEC-008`:** Hardcoded Database URI with Password (HIGH, CVSS 8.6).
     - **`SAST-SEC-009`:** Hardcoded Internal IP Address / Private Hostname (LOW, CVSS 3.1).

2. **`crypto_lint.py` (Insecure Cryptography & PRNG Linting)**
   - **`SAST-CRY-001`:** Usage of Broken Hash Function (`MD5`, `SHA1` for hashing/passwords) (MEDIUM, CVSS 5.3).
   - **`SAST-CRY-002`:** Insecure Pseudo-Random Number Generator (`random.random()`, `Math.random()`) in auth/token context (HIGH, CVSS 7.5).
   - **`SAST-CRY-003`:** Insecure Symmetric Cipher Mode (AES in `ECB` mode) (HIGH, CVSS 7.5).

3. **`injection_lint.py` (Static Injection Anti-Pattern Linting)**
   - **`SAST-INJ-001`:** Raw SQL Query String Formatting / Concatenation (HIGH, CVSS 8.5).
   - **`SAST-INJ-002`:** Unsafe Shell Execution (`subprocess(..., shell=True)`, `os.system()`) (HIGH, CVSS 8.5).
   - **`SAST-INJ-003`:** Unsafe Deserialization (`pickle.loads()`, `yaml.load(Loader=Loader)`) (HIGH, CVSS 8.5).

4. **`dependency_auditor.py` (Software Composition Analysis - SCA)**
   - Parses `requirements.txt`, `Pipfile.lock`, `package.json`, `package-lock.json`, `go.mod`.
   - **`SAST-DEP-001`:** Vulnerable Pinned Dependency (Known CVE) (HIGH, CVSS 7.5).
   - **`SAST-DEP-002`:** Unpinned / Wildcard Dependency Version (`*`) (LOW, CVSS 3.7).

---

### 3.4 Engine 4: Infrastructure & Container IaC (`infra_iac`)

**Identifier:** `infra_iac`  
**Display Name:** Infrastructure-as-Code, Container & Cloud Security  
**Applicable Target Types:** `DOCKERFILE`, `IAC_MANIFEST`, `LOCAL_PATH`

#### Submodules:
1. **`dockerfile_auditor.py` (Container Hardening)**
   - **`IAC-DOCK-001`:** Container Running as Root (missing `USER` directive) (HIGH, CVSS 7.8).
   - **`IAC-DOCK-002`:** Base Image Uses Unpinned / Latest Tag (`FROM ...:latest`) (MEDIUM, CVSS 5.3).
   - **`IAC-DOCK-003`:** Missing `HEALTHCHECK` Instruction (LOW, CVSS 3.1).
   - **`IAC-DOCK-004`:** Plaintext Secret Embedded in `ENV` / `ARG` (HIGH, CVSS 7.5).
   - **`IAC-DOCK-005`:** Package Manager Cache Retained in Layer (LOW, CVSS 2.5).
   - **`IAC-DOCK-006`:** Insecure Usage of Sudo in RUN (MEDIUM, CVSS 6.5).

2. **`compose_auditor.py` (Docker Compose Posture)**
   - **`IAC-CMP-001`:** Container Configured with `privileged: true` (HIGH, CVSS 8.5).
   - **`IAC-CMP-002`:** Dangerous Docker Socket Mount (`/var/run/docker.sock`) (CRITICAL, CVSS 9.0).
   - **`IAC-CMP-003`:** Database Port Bound to `0.0.0.0` Host Interface (HIGH, CVSS 7.5).

3. **`k8s_manifest_auditor.py` (Kubernetes Security)**
   - **`IAC-K8S-001`:** Privileged Container / Privilege Escalation Enabled (`privileged: true`) (HIGH, CVSS 8.5).
   - **`IAC-K8S-002`:** Host Namespace Sharing (`hostPID: true`, `hostNetwork: true`) (HIGH, CVSS 7.8).
   - **`IAC-K8S-003`:** Root Filesystem Not Read-Only (missing `readOnlyRootFilesystem: true`) (LOW, CVSS 3.7).
   - **`IAC-K8S-004`:** Missing CPU / Memory Resource Limits (DoS risk) (LOW, CVSS 3.7).

4. **`terraform_auditor.py` (Cloud IaC Security)**
   - **`IAC-TF-001`:** S3 Bucket / Storage Blob with Public Read Access (HIGH, CVSS 8.2).
   - **`IAC-TF-002`:** Security Group Inbound Rule Allows `0.0.0.0/0` on Management Port (SSH/RDP) (HIGH, CVSS 7.5).
   - **`IAC-TF-003`:** Unencrypted Storage Volume at Rest (MEDIUM, CVSS 5.3).
   - **`IAC-TF-004`:** Wildcard IAM Policy (`Action: "*"` on `Resource: "*"`) (HIGH, CVSS 8.1).

---

### 3.5 Engine 5: CI/CD Pipeline & Build Security (`cicd_audit`)

**Identifier:** `cicd_audit`  
**Display Name:** CI/CD Pipeline & Workflow Security  
**Applicable Target Types:** `LOCAL_PATH`

#### Submodules:
1. **`github_actions_auditor.py` (GitHub Actions Security)**
   - **`CICD-GHA-001`:** Insecure `pull_request_target` Trigger with Code Checkout (HIGH, CVSS 8.5).
   - **`CICD-GHA-002`:** Unpinned Third-Party Action Version (`@main`/`@master` instead of commit SHA) (MEDIUM, CVSS 5.3).
   - **`CICD-GHA-003`:** Script Injection via Expression Context (`${{ github.event.issue.title }}`) (HIGH, CVSS 8.5).
   - **`CICD-GHA-004`:** Overly Permissive Default GITHUB_TOKEN (`permissions: write-all`) (MEDIUM, CVSS 6.0).
