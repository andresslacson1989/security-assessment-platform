# Contract 03: Engine Plugin Interface & Module Implementation Contract

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 5.0.0 (Enterprise Adapters First-in-Line & Penetration Testing Architecture Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Assessment Engine Plugins, Submodules, Tool Adapters & Execution Lifecycle  

---

## 1. Abstract Engine Interface (`BaseAssessmentEngine`)

Every assessment engine MUST subclass `BaseAssessmentEngine` defined in `backend/app/engines/base.py` and implement all abstract properties and methods.

```python
from abc import ABC, abstractmethod
from typing import List, Callable, Awaitable, Optional
from app.core.models import Target, Finding, ScanConfig, LogLevel, DiscoveredEndpoint, DiscoveredSubdomain

# Asynchronous callback signatures for real-time telemetry streaming
LogCallback = Callable[[LogLevel, str], Awaitable[None]]
ProgressCallback = Callable[[int, str], Awaitable[None]]
FindingCallback = Callable[[Finding], Awaitable[None]]
AuthStatusCallback = Callable[[dict], Awaitable[None]]
EndpointDiscoveredCallback = Callable[[DiscoveredEndpoint], Awaitable[None]]
SubdomainDiscoveredCallback = Callable[[DiscoveredSubdomain], Awaitable[None]]

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
        emit_finding: FindingCallback,
        **kwargs,
    ) -> List[Finding]:
        """
        Executes the engine's assessment checks asynchronously.
        Follows the 3-Stage Pipeline:
        1. Primary Adapters First (if available and enabled)
        2. Proprietary Native Enrichment (AST Taint, CT OSINT, Active Fuzzing, DNS)
        3. Resilient Native Fallback (if external tools are missing)
        """
        pass
```

---

## 2. Resilience, Error Isolation & Lifecycle Guarantees

1. **Zero Cascade Failure Guarantee:**
   - Any unhandled exception (e.g., `socket.timeout`, `httpx.ConnectError`, `dns.resolver.NXDOMAIN`, `yaml.YAMLError`, or tool subprocess failure) MUST be caught inside the engine/adapter boundary.
   - The engine logs the event via `emit_log(LogLevel.WARNING, ...)` and continues remaining checks.
2. **Cancellation Responsiveness:**
   - Async loops and subprocess execution MUST check for cancellation (`asyncio.CancelledError`). When cancelled, active sockets, HTTP connections, and child subprocesses MUST be terminated gracefully within 500ms.
3. **Strict Timeout Bounds:**
   - All network connections and socket operations MUST be bounded by explicit timeouts (HTTP $\le$ 10s, Socket $\le$ 2s, DNS $\le$ 3s, crt.sh $\le$ 10s, Tool Adapters $\le$ 60s).

---

## 3. Detailed Specifications for Core Engines & Submodules

---

### 3.1 Engine 1: Network, TLS, DNS & OSINT Auditor (`network`)

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
   - **`NET-TLS-006` (Deprecated Ciphersuite Vulnerable to SWEET32 / 3DES):** Probes for 64-bit block ciphers like 3DES/DES (MEDIUM, CVSS 5.9).

2. **`dns_hygiene.py` (DNS Email Security, DNSSEC & Zone Hygiene)**
   - **`NET-DNS-001` (Missing / Incomplete SPF Record):** Queries `TXT` for `v=spf1` (MEDIUM, CVSS 5.3).
   - **`NET-DNS-002` (Permissive SPF `+all`):** Detects insecure `+all` mechanism (HIGH, CVSS 7.5).
   - **`NET-DNS-003` (Missing DMARC Record):** Queries `_dmarc.{domain}` for `v=DMARC1` (MEDIUM, CVSS 5.3).
   - **`NET-DNS-004` (Permissive DMARC Policy `p=none`):** Detects unenforced policy (LOW, CVSS 3.7).
   - **`NET-DNS-005` (Missing CAA Record):** Queries `CAA` record (INFO, CVSS 0.0).
   - **`NET-DNS-006` (Missing MTA-STS / TLS-RPT):** Queries `_mta-sts.{domain}` and `_smtp._tls.{domain}` (LOW, CVSS 3.5).
   - **`NET-DNS-007` (Missing DNSSEC Deployment):** Queries `DNSKEY` and `DS` records (LOW, CVSS 3.7).
   - **`NET-DNS-008` (DNS Zone Transfer AXFR Exposure):** Sends non-destructive AXFR query to check if unauthenticated zone dump is permitted (HIGH, CVSS 7.5).

3. **`port_checker.py` & `banner_grabber.py` (Exposed Ports & Service Banners)**
   - Concurrently checks critical service ports with 1.5s non-blocking timeout:
     - `21` (FTP), `22` (SSH), `23` (Telnet), `3306` (MySQL), `5432` (PostgreSQL), `6379` (Redis), `27017` (MongoDB), `9200` (Elasticsearch).
   - **`NET-PORT-001`:** Exposed Database Port (MySQL 3306 / Postgres 5432) (HIGH, CVSS 7.5).
   - **`NET-PORT-002`:** Exposed In-Memory Cache (Redis 6379 / Mongo 27017 / Elasticsearch 9200) (HIGH, CVSS 7.5).
   - **`NET-PORT-003`:** Exposed Insecure Remote Management (Telnet 23 / FTP 21) (HIGH, CVSS 7.5).
   - **`NET-SVC-001`:** Deprecated or Vulnerable Service Daemon Version Detected via Banner (HIGH, CVSS 7.5).

4. **`subdomain_recon.py` (Passive OSINT & Takeover Detection)**
   - Queries Certificate Transparency logs (`https://crt.sh/?q=%25.{domain}&output=json`) with timeout and deduplication.
   - Resolves discovered subdomains and evaluates CNAME pointers for dangling takeover targets (AWS S3, GitHub Pages, Heroku, Azure CDN).
   - **`NET-OSINT-001` (Dangling DNS CNAME / Subdomain Takeover Vulnerability):** Subdomain CNAME points to unregistered third-party service (CRITICAL, CVSS 9.1).
   - **`NET-OSINT-002` (Sensitive Subdomain Discovered on Public Infrastructure):** Discovered subdomains like `admin.*`, `dev.*`, `staging.*`, `internal.*` (MEDIUM, CVSS 5.3).

---

### 3.2 Engine 2: Web Application & API DAST (`web_dast`)

**Identifier:** `web_dast`  
**Display Name:** Web Application, Browser Security & REST/GraphQL API DAST  
**Applicable Target Types:** `URL`, `DOMAIN`

#### Submodules:
1. **`headers_cookies.py` (Security Headers & Cookie Flags)**
   - `DAST-HDR-001` (CSP), `DAST-HDR-002` (HSTS), `DAST-HDR-003` (HSTS Max-Age), `DAST-HDR-004` (X-Frame-Options), `DAST-HDR-005` (nosniff), `DAST-HDR-006` (Referrer-Policy), `DAST-HDR-007` (Server Version), `DAST-COOKIE-001` (HttpOnly), `DAST-COOKIE-002` (Secure), `DAST-COOKIE-003` (SameSite), `DAST-CCH-001` (Cache-Control).

2. **`cors_analyzer.py` (CORS Misconfiguration Analyzer)**
   - `DAST-CORS-001` (Origin Reflection + Credentials), `DAST-CORS-002` (Wildcard + Credentials), `DAST-CORS-003` (Null Origin + Credentials).

3. **`api_inspector.py` (Sensitive Exposure & Methods)**
   - `DAST-EXP-001` (`.env`), `DAST-EXP-002` (`/.git/HEAD`), `DAST-EXP-003` (Spring Boot Actuator), `DAST-EXP-004` (OpenAPI Swagger), `DAST-METH-001` (`TRACE` method).

4. **`browser_posture.py` & `graphql_auditor.py`**
   - `DAST-SRI-001` (Subresource Integrity), `DAST-MIX-001` (Mixed Content), `DAST-GQL-001` (GraphQL Introspection).

5. **`crawler.py` & `auth_session.py` (Scoped BFS Crawler & Authentication)**
   - BFS link discovery with static bundle filtering.
   - Session login (Header/Cookie/Form) with CSRF extraction and heartbeat monitor.
   - `DAST-AUTH-001` (Cleartext Auth), `DAST-AUTH-002` (Insecure Session Cookie), `DAST-AUTH-003` (Broken Access Control), `DAST-AUTH-004` (Sensitive Query Strings), `DAST-FORM-001` (Insecure Form Action), `DAST-FORM-002` (Missing CSRF Token).

6. **`parameter_fuzzer.py` (Active Parameter Fuzzing & Benign Injection Probes)**
   - `DAST-INJ-001` (Time-based & Boolean SQLi), `DAST-XSS-001` (Canary Reflected XSS), `DAST-LFI-001` (Path Traversal), `DAST-SSTI-001` (Template Injection `{{7*7}}`), `DAST-REDIR-001` (Open Redirect).

---

### 3.3 Engine 3: Static Code Analysis, Secrets, SCA & Taint AST (`code_sast`)

**Identifier:** `code_sast`  
**Display Name:** Static Code Analysis, Secrets, Cryptography, SCA & Taint Analysis  
**Applicable Target Types:** `LOCAL_PATH`

#### Submodules:
1. **`secret_scanner.py` & `git_history_scanner.py` (Pattern & Historical Git Secrets)**
   - `SAST-SEC-001` to `009` (AWS, GitHub, Stripe, GCP, Slack, Private Key, Database URI, RFC1918 IP).
   - `SAST-GIT-001` (Historical Git Commit Secret).

2. **`crypto_lint.py` & `injection_lint.py` (Insecure Cryptography, PRNG & Injection)**
   - `SAST-CRY-001` (MD5/SHA1), `SAST-CRY-002` (Insecure PRNG), `SAST-CRY-003` (AES ECB Mode).
   - `SAST-INJ-001` (Raw SQL Format), `SAST-INJ-002` (Shell Injection), `SAST-INJ-003` (Unsafe Deserialization).

3. **`ast_taint_analyzer.py` (AST Interprocedural Taint Flow)**
   - `SAST-TAINT-001` (AST User Input -> SQL Sink), `SAST-TAINT-002` (AST User Input -> Command Sink).

4. **`dependency_auditor.py` (Software Composition Analysis - SCA)**
   - `SAST-DEP-001` (Vulnerable Pinned Dependency), `SAST-DEP-002` (Unpinned Wildcard Dependency).

---

### 3.4 Engine 4: Infrastructure & Container IaC (`infra_iac`)

**Identifier:** `infra_iac`  
**Display Name:** Infrastructure-as-Code, Container & Cloud Security  
**Applicable Target Types:** `DOCKERFILE`, `IAC_MANIFEST`, `LOCAL_PATH`

#### Submodules:
- `dockerfile_auditor.py` (`IAC-DOCK-001` to `006`)
- `compose_auditor.py` (`IAC-CMP-001` to `003`)
- `k8s_manifest_auditor.py` (`IAC-K8S-001` to `004`)
- `terraform_auditor.py` (`IAC-TF-001` to `004`)

---

### 3.5 Engine 5: CI/CD Pipeline & Build Security (`cicd_audit`)

**Identifier:** `cicd_audit`  
**Display Name:** CI/CD Pipeline & Workflow Security  
**Applicable Target Types:** `LOCAL_PATH`

#### Submodules:
- `github_actions_auditor.py` (`CICD-GHA-001` to `004`)

---

## 4. Adapters First-in-Line Plugin Architecture (`backend/app/adapters/`)

To combine enterprise-grade penetration testing power with zero-dependency portability, the platform defines the `BaseToolAdapter` interface.

### 4.1 Abstract Tool Adapter Interface
```python
from abc import ABC, abstractmethod
import shutil
from typing import Optional, List, Callable, Awaitable
from app.core.models import Target, Finding, ScanConfig, LogLevel

class BaseToolAdapter(ABC):
    """
    Abstract contract for external tool adapters.
    Supported enterprise tools:
    - Network / TLS: Nmap, SSLyze
    - Web DAST: Nuclei, FFuF, Nikto
    - SAST / Secrets: Semgrep, Gitleaks, Bandit
    - SCA / IaC: Trivy, Checkov
    """

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name of executable: 'nmap', 'sslyze', 'nuclei', 'ffuf', 'nikto', 'semgrep', 'gitleaks', 'bandit', 'trivy', 'checkov'."""
        pass

    @abstractmethod
    def resolve_binary_path(self, custom_path: Optional[str] = None) -> Optional[str]:
        """Resolves executable path using custom_path or system PATH via shutil.which()."""
        pass

    @abstractmethod
    async def is_available(self, custom_path: Optional[str] = None) -> bool:
        """Checks if tool executable is present and executable."""
        pass

    @abstractmethod
    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        """Retrieves CLI tool version string (e.g. 'Nmap 7.94', 'nuclei v3.2.0')."""
        pass

    @abstractmethod
    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
    ) -> List[Finding]:
        """
        Executes CLI command asynchronously as primary first-in-line stage,
        parses stdout/JSON/XML, and normalizes findings into canonical Finding models.
        """
        pass
```

### 4.2 Adapter Specifications, Priority & Fallback Mapping

| Tool Adapter | Binary | Execution Command | Output Format | Priority & Execution Role | Resilient Native Fallback | Finding Normalization |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`NmapAdapter`** | `nmap` | `nmap -sV -sC --version-light -T4 -oX - <target>` | XML (`-oX -`) | **Primary** Network & Port Scanner | `port_checker.py` + `banner_grabber.py` | Maps open ports, daemon versions, and NSE script output into `NET-PORT-xxx` and `NET-SVC-001`. `source_tool="nmap"`. |
| **`SslyzeAdapter`** | `sslyze` | `sslyze --json_out=- <host>:<port>` | JSON (`--json_out=-`) | **Primary** Deep TLS/SSL Auditor | `tls_auditor.py` | Maps deprecated TLS protocols, weak ciphers, and cert issues to `NET-TLS-xxx`. `source_tool="sslyze"`. |
| **`NucleiAdapter`** | `nuclei` | `nuclei -u <target> -j -silent -tags cve,misconfig` | JSON Lines (`-j`) | **Primary** DAST Vulnerability Engine | `parameter_fuzzer.py` + `headers_cookies.py` | Maps Nuclei template IDs and severity to canonical CWEs and `DAST-xxx`. `source_tool="nuclei"`. |
| **`FfufAdapter`** | `ffuf` | `ffuf -u <target>/FUZZ -w <wordlist> -mc 200,204,301,302,307,401,403 -o - -of json -t 5 -rate 10` | JSON (`-of json`) | **Primary** Endpoint & Content Discovery | `crawler.py` | Discovers hidden routes, backup files, and endpoints, emitting `DAST-EXP-xxx` findings and `DiscoveredEndpoint` models. `source_tool="ffuf"`. |
| **`NiktoAdapter`** | `nikto` | `nikto -h <target> -Format json -output - -Tuning 1,2,3,4,8,9,a,b,c` | JSON (`-Format json`) | **Primary** Server Misconfiguration Scanner | `headers_cookies.py` + `api_inspector.py` | Maps outdated server components, dangerous HTTP methods, and insecure headers to `DAST-HDR-xxx` / `DAST-EXP-xxx`. `source_tool="nikto"`. |
| **`SemgrepAdapter`** | `semgrep` | `semgrep scan --config auto --json <dir>` | JSON (`--json`) | **Primary** Multi-Language AST SAST | `injection_lint.py` + `crypto_lint.py` | Normalizes Semgrep rules into `SAST-xxx` with line numbers and evidence diffs. `source_tool="semgrep"`. |
| **`GitleaksAdapter`** | `gitleaks` | `gitleaks detect --source <dir> --report-format json --report-path -` | JSON (`--report-format json`) | **Primary** Dedicated Git Secret Scanner | `secret_scanner.py` + `git_history_scanner.py` | Extracts hardcoded tokens, private keys, and API secrets with mandatory masking to `SAST-SEC-xxx`. `source_tool="gitleaks"`. |
| **`BanditAdapter`** | `bandit` | `bandit -r <dir> -f json` | JSON (`-f json`) | **Primary** Python AST Security Linter | `crypto_lint.py` + `injection_lint.py` | Maps high/medium confidence AST flaws to `SAST-CRY-xxx` and `SAST-INJ-xxx`. `source_tool="bandit"`. |
| **`TrivyAdapter`** | `trivy` | `trivy fs --format json <dir>` | JSON (`--format json`) | **Primary** SCA & Container Vulnerability Engine | `dependency_auditor.py` + `dockerfile_auditor.py` | Maps package and container vulnerabilities to `SAST-DEP-001` and `IAC-DOCK-xxx`. `source_tool="trivy"`. |
| **`CheckovAdapter`** | `checkov` | `checkov -d <dir> -o json --compact` | JSON (`-o json`) | **Primary** Infrastructure-as-Code Policy Engine | `compose_auditor.py` + `k8s_manifest_auditor.py` + `terraform_auditor.py` | Maps failed IaC checks (Terraform, K8s, Compose) to `IAC-TF-xxx`, `IAC-K8S-xxx`, `IAC-CMP-xxx`. `source_tool="checkov"`. |

