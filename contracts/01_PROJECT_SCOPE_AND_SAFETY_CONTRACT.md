# Contract 01: Project Scope, Safety, Legal Boundaries & Operational Limits

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 9.0.0 (Enterprise ASPM & EASM Suite, 21-Tool Fleet, Zero-Trust Hardening, SSRF Gateway, Dual-Mode Persistence & Contextual Risk Architecture Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Platform Core Architecture, Safety Standards, Zero-Trust Security Controls & Operations  

---

## 1. System Vision & Purpose

The **Automated Security Assessment & Vulnerability Management Platform (CyberAssess)** is an enterprise-grade, automated, defensive penetration testing, Application Security Posture Management (ASPM), and External Attack Surface Management (EASM) platform. Designed for security architects, professional penetration testers, DevSecOps pipelines, and application developers, the platform provides deep, calculated, and mathematically verified security assessments across the complete modern software stack.

When pointed to a target (Web URL, Domain Name, Host IP Address, Source Code Repository, Container Specification, Kubernetes Cluster, Cloud Account, or Infrastructure-as-Code Template), the platform automatically orchestrates a comprehensive battery of non-destructive, high-fidelity, and deterministic security checks across five core security domains:
1. **Network Perimeter, EASM, TLS/SSL, DNS Infrastructure & Passive OSINT** (`network`):
   - External asset mapping, multi-source subdomain enumeration, active HTTP probing, port auditing, and deep TLS protocol/cipher inspection.
2. **Web Application, Headless SPA Crawling, Authenticated DAST, API Contract Fuzzing & Parameter Fuzzing** (`web_dast`):
   - Chromium-driven SPA crawling, template-driven DAST, content discovery, server configuration audits, property-based OpenAPI/GraphQL contract testing, and benign parameter fuzzing.
3. **Static Code Analysis, Interprocedural AST Taint Flow, Verified Secrets & Multi-Language SAST** (`code_sast`):
   - Syntactic/semantic AST scanning, interprocedural taint propagation analysis, high-entropy secret detection, live API credential verification, and client-side JavaScript CVE auditing.
4. **Software Supply Chain Security, SBOM Generation & Dependency Vulnerability Auditing** (`supply_chain` / `code_sast`):
   - Standardized SBOM generation (CycloneDX 1.5, SPDX 2.3), vulnerability scanning from SBOM files, and precise commit-hash dependency vulnerability matching via Google OSV.
5. **Infrastructure-as-Code, Container Hardening, Cloud Posture (CSPM) & CIS Benchmarks** (`infra_iac`):
   - Static IaC template scanning, container image CIS Docker linter, official CIS Kubernetes Benchmark auditing, and multi-cloud security assessment (AWS, Azure, GCP).

The platform operates on an **"Adapters First-in-Line" Enterprise Hybrid Architecture** spanning a fleet of **21 authoritative modern security tools** backed by native proprietary engines:
- **EASM & Recon Fleet:** `nmap`, `sslyze`, `subfinder`, `httpx`
- **Web DAST & Crawling Fleet:** `nuclei`, `ffuf`, `katana`
- **SAST & Secret Fleet:** `semgrep`, `bandit`, `gitleaks`, `trufflehog`, `retire`
- **Supply Chain & SCA Fleet:** `trivy`, `syft`, `grype`, `osv-scanner`
- **Cloud, K8s & API Posture Fleet:** `checkov`, `prowler`, `kube-bench`, `dockle`, `schemathesis`

- **Stage 1 (Primary Front-Line Tool Adapters):** When industry-standard CLI pentesting tools are present on the host system or container image, they fire first as the primary authoritative assessment engines.
- **Stage 2 (Proprietary Native Enrichment):** Deep specialized modules run concurrently or following adapter runs to enrich the assessment with proprietary capabilities external tools do not provide (e.g. interprocedural AST taint flow tracing, active time/boolean SQLi fuzzing with reproduction cURLs, Certificate Transparency OSINT, CNAME takeover detection, and strict DNS hygiene).
- **Stage 3 (Resilient Zero-Failure Native Fallbacks):** If any external tool binary is absent on the host or encounters an error, the system seamlessly falls back to its built-in pure Python engines, guaranteeing 100% operational portability on clean systems with zero dropped assessments.
- **Production Container Distribution:** The platform ships as a hardened multi-stage Docker container pre-packaged with all 21 tools, CPAN Perl modules, and runtime dependencies, publishable to GitHub Container Registry (`ghcr.io`) for 1-command cloud/server deployment.
- **Integrated In-App Installation:** Users running on bare metal can install missing tool adapters with a single click directly from the web interface or REST API without leaving the platform or manually editing system configuration files.

The platform calculates deterministic CVSS v3.1-aligned security scores and letter grades (`A+` to `F`), streams real-time execution logs and vulnerability findings over Server-Sent Events (SSE), enables interactive HTTP request repeating, provides one-click standalone `curl` reproduction PoC commands, and exports industry-standard reports (Interactive Standalone HTML, OASIS SARIF v2.1.0 for GitHub Code Scanning, and structured JSON).

---

## 2. Strict Safety & Non-Destructive Operations Contract

### 2.1 The Zero-Harm Non-Destructive Mandate
Every scanning engine, check module, and network probe in this system MUST operate strictly within a **zero-harm, non-destructive, non-disruptive** operational framework:

1. **Strictly Non-Destructive Inspection & Benign Mutation:**
   - Modules MUST NOT transmit destructive payloads (e.g., SQL `DROP`/`DELETE`/`UPDATE`, command injection execution, filesystem modification, memory corruption exploits, or data exfiltration).
   - Dynamic tests and parameter mutations are strictly restricted to:
     - Passive HTTP header and cookie observation.
     - Standard HTTP request method inspection (`OPTIONS`, `HEAD`, `GET`).
     - Safe probe requests (e.g., testing if a sensitive path returns `403` vs `200`).
     - Safe SSL/TLS handshake metadata negotiation, cipher enumeration, and TLS vulnerability probes (Heartbleed, SWEET32, POODLE).
     - Passive DNS record resolution (`TXT`, `MX`, `A`, `AAAA`, `CAA`, `DNSKEY`, `DS`) and Certificate Transparency (`crt.sh`) passive subdomain reconnaissance.
     - Safe, non-saturating TCP socket connection checks (`connect()` and immediate `close()`) with daemon banner extraction.
     - Read-only GraphQL introspection queries.
     - **Benign Parameter Fuzzing:**
       - *Time-based SQLi Probes:* Benign delay queries (e.g., `SLEEP(2)` / `pg_sleep(2)`) to measure latency differentials without altering table records.
       - *Boolean Differential SQLi:* Read-only comparison of responses between truthy (`1=1`) and falsy (`1=2`) queries.
       - *Reflected XSS Canary Tokens:* Injecting unique harmless non-executable alphanumeric tokens (`_CYBERASSESS_XSS_<random_hex>_`) and verifying unescaped reflection in the HTML body or attributes.
       - *Local File Inclusion (LFI) / Path Traversal Probes:* Read-only traversal sequences (`../../../../etc/passwd` or `..\..\..\..\windows\win.ini`) detecting operating system signature patterns without writing to disk.
       - *Server-Side Template Injection (SSTI):* Mathematical expression evaluation (e.g., `{{7*7}}` or `${7*7}`) verifying rendering of `49`.
       - *Open Redirect Probes:* Checking for external hostname reflection in HTTP `Location:` response headers.
2. **No Denial of Service (DoS) or Resource Exhaustion:**
   - Packet flooding, stress testing, high-concurrency fuzzing, slowloris attacks, and brute-force password cracking are strictly prohibited.
   - Concurrency per target is capped by default to 5 workers (configurable up to a hard ceiling of 15).
3. **No Authentication Bypassing or Brute Forcing:**
   - Scanners MUST NOT attempt credential stuffing, dictionary attacks, or automated brute-forcing of login forms.
   - When authenticated scanning is configured, the system uses user-supplied credentials, API keys, or session cookies strictly for authorized session maintenance.

### 2.2 Scoped Multi-Page Web Crawling Safety Rules
When crawling web applications across multiple internal routes:
1. **Strict Same-Origin Policy (SOP) Enforcement:**
   - The crawler MUST NOT traverse links outside the target scheme, host, and port (e.g. if target is `https://example.com`, links to `https://auth.example.com` or `https://cdn.example.com` are marked out-of-scope unless explicitly whitelisted).
2. **Depth & Volume Constraints:**
   - Maximum crawling depth $D \le 5$ (default: 3 levels).
   - Maximum discovered page limit $N \le 200$ (default: 50 pages).
3. **Loop & Dynamic Parameter Guardrails:**
   - URLs are normalized (fragments stripped, parameters sorted, path traversals resolved).
   - URLs are deduplicated via canonical SHA-256 state tracking to prevent infinite recursion on dynamic calendars or pagination traps.
4. **Dangerous Path Exclusions:**
   - Endpoints matching destructive patterns (e.g., `*delete*`, `*destroy*`, `*purge*`, `*drop*`, `*checkout*`, `*pay*`, `*charge*`) are automatically blocked from automated submission.

### 2.3 Authenticated DAST Session Safety Rules
When conducting authenticated scans inside protected application areas:
1. **Logout Path Blacklisting:**
   - The crawler and DAST engines MUST automatically blacklist and skip any URL or form matching logout/sign-out patterns (e.g., `/logout`, `/signout`, `/sign_out`, `/auth/exit`, `/session/destroy`) to ensure the active session is not prematurely invalidated.
2. **Form Interaction Safety:**
   - Forms discovered during authenticated crawls are analyzed passively (action target, method, input fields, CSRF protection). Mutating state-changing requests (`POST`/`PUT`/`DELETE`) MUST NOT be submitted with randomized data.

### 2.4 Headless SPA Crawling Safety Rules (`katana`)
When executing headless Chromium-driven single-page application (SPA) crawling:
1. **Isolated Sandbox & Resource Boundaries:**
   - Headless browser processes execute with resource limits (maximum 10 concurrent tabs, memory ceiling 1.5 GB per process).
   - Form auto-submission is strictly disabled for mutating HTTP methods (`POST`, `PUT`, `DELETE`).
   - Browser navigation is locked to the explicit target domain origin. External script execution is sandboxed.
2. **Deterministic Execution Timeout:**
   - Maximum rendering wait time per DOM mutation: 5.0 seconds. Total crawl phase timeout: 120.0 seconds.

### 2.6 Verified Secret Probing Constraints (`trufflehog`)
When conducting live API key and secret verification:
1. **Non-Destructive Metadata Probes:**
   - Secret verification detectors MUST perform read-only identity queries (e.g. `aws sts get-caller-identity`, `GET /v1/me`, `users.identity`).
   - The engine MUST NEVER perform state-changing or billing-incurring API requests.
2. **Zero Credential Persistence:**
   - Discovered raw secrets are held in volatile process memory only long enough to evaluate validity and generate masked evidence (`AKIA*************PLE`), then immediately dereferenced.

### 2.7 Read-Only Cloud & Cluster Assessment Mandate (`prowler`, `kube-bench`, `dockle`)
When auditing Cloud infrastructure, Kubernetes clusters, or Docker images:
1. **Strictly Read-Only Permissions:**
   - Audits operate exclusively with `ReadOnlyAccess` / `SecurityAudit` cloud policies and Kubernetes `view` / `ClusterRole` permissions (`Get`, `List`, `Watch`).
   - The engine MUST NOT alter IAM policies, security groups, routing tables, Kubernetes manifests, or cluster state.
2. **Local CIS Docker Linter Safety:**
   - `dockle` inspects image tarballs and filesystem layers locally without spawning interactive containers or running privileged code.

### 2.8 Property-Based API Contract Testing Safety (`schemathesis`)
When testing OpenAPI / Swagger / GraphQL endpoints:
1. **Safe Method Prioritization:**
   - Automated property generation is restricted to safe idempotent methods (`GET`, `HEAD`, `OPTIONS`) by default.
   - Mutating methods (`POST`, `PUT`, `PATCH`) execute only against synthetic sandbox test objects and require explicit user opt-in.
   - `DELETE` endpoints are automatically excluded from automated property-based fuzzing.

---

## 3. Comprehensive Target Scoping & Validation Rules

The platform validates every target input against strict syntactic and semantic safety rules prior to queueing any scan:

| Target Type | Validation Rule | Allowed Formats / Examples | Rejected Formats |
| :--- | :--- | :--- | :--- |
| **`URL`** | Valid RFC 3986 URI with `http` or `https` scheme. Hostname must be FQDN or valid IP. | `https://app.example.com/api`, `http://192.168.1.50:8080` | `ftp://server`, `javascript:alert(1)`, `file:///etc/passwd` |
| **`DOMAIN`** | Valid FQDN conforming to RFC 1035 (1-253 chars, valid TLD). | `example.com`, `sub.staging.internal` | `http://example.com`, `example..com`, `-invalid.com` |
| **`IP`** | Valid IPv4 (RFC 791) or IPv6 (RFC 4291) address string. | `198.51.100.1`, `2001:db8::1` | `999.999.999.999`, `192.168.1.1/24` (single host only) |
| **`LOCAL_PATH`** | Absolute or sanitized relative path existing on the local filesystem. | `E:\repos\my-app`, `/var/www/project` | Path traversal attempts outside authorized roots |
| **`DOCKERFILE`** | Valid local path to a file named `Dockerfile` or `*.dockerfile`. | `./Dockerfile`, `/app/build.Dockerfile` | Non-dockerfile binaries |
| **`IAC_MANIFEST`** | Valid local path to Kubernetes (`.yaml`/`.yml`), Terraform (`.tf`), or Compose (`docker-compose.yml`). | `./deploy/k8s.yaml`, `./infra/main.tf` | Arbitrary executables |

### 3.1 Scope Isolation & Third-Party Boundaries
- **Crawl Boundary:** When auditing web applications, external links pointing to third-party domains (e.g. CDNs, payment processors, external analytics) are marked as out-of-scope and NEVER traversed.
- **Subdomain Boundary:** Scans targeted at `app.example.com` do NOT traverse to `admin.example.com` unless explicitly configured under Wildcard domain mode.
- **Private Network Protection:** RFC 1918 private IP subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and loopback addresses (`127.0.0.1`, `localhost`) are permitted ONLY when explicitly targeted for local development auditing.

---

## 4. Enterprise Adapters First-in-Line Architecture & Safe Subprocess Boundaries

To combine zero-dependency portability with enterprise-grade penetration testing power, the platform operates on an **"Adapters First-in-Line" Execution Architecture**:

```
                               ┌───────────────────────────────────────────────┐
                               │            CYBERASSESS ORCHESTRATOR           │
                               └──────────────────────┬────────────────────────┘
                                                      │
                ┌─────────────────────────────────────┴─────────────────────────────────────┐
                │                                                                           │
                ▼                                                                           ▼
┌─────────────────────────────┐                                             ┌─────────────────────────────┐
│  STAGE 1: ADAPTERS FIRST    │                                             │ STAGE 2: NATIVE ENRICHMENT  │
│  (Authoritative Front-Line) │                                             │ (Proprietary Deep Analysis) │
├─────────────────────────────┤                                             ├─────────────────────────────┤
│ • Nmap (Network & Ports)    │                                             │ • AST Taint Flow Tracer     │
│ • SSLyze (Deep TLS Ciphers) │                                             │ • Git History Secret Mining │
│ • Nuclei (CVE Templates)    │                                             │ • Active Parameter Fuzzing  │
│ • FFuF (Endpoint Discovery) │                                             │ • CT Subdomain OSINT crt.sh │
│ • Katana (Headless SPA Crawl│                                             │ • Dangling CNAME Takeover   │
│ • Semgrep (AST Code Rules)  │                                             │ • Authoritative DNS Hygiene │
│ • Gitleaks (Git Secrets)    │                                             │ • Auth Session Management   │
│ • Bandit (Python AST SAST)  │                                             └──────────────┬──────────────┘
│ • Trivy (Container/Lock SCA)│                                                            │
│ • Checkov (Cloud/IaC Audit) │                                                            │
└──────────────┬──────────────┘                                                            │
               │                                                                           │
               │◄─────────────[Stage 3: Resilient Fallback if Binary Absent]───────────────┘
               ▼
┌─────────────────────────────┐
│ CANONICAL NORMALIZER (SARIF)│
│   (Single Unified Schema)   │
└─────────────────────────────┘
```

### 4.1 Zero-Failure Fallback Guarantee & Priority Model
1. **Host Discovery & Priority Resolution:** The orchestrator automatically probes system `PATH`, local managed binaries directory (`backend/bin/`), and configured custom paths at startup and scan initialization. When an adapter is active, it runs first to establish baseline findings.
2. **Transparent Native Fallback:** If an external binary (`nmap`, `sslyze`, `nuclei`, `ffuf`, `semgrep`, `gitleaks`, `bandit`, `trivy`, `checkov`) is not installed or errors during execution, the platform automatically and seamlessly falls back to its built-in pure Python engines. The scan NEVER crashes due to missing external binaries.
3. **Execution Mode Reporting:** Every finding records its `source_tool` (`"native"`, `"nmap"`, `"sslyze"`, `"nuclei"`, `"ffuf"`, `"semgrep"`, `"gitleaks"`, `"bandit"`, `"trivy"`, `"checkov"`) for audit transparency.

### 4.2 Safe Non-Destructive Subprocess Execution Flags
External tools MUST be invoked with strictly bounded, non-destructive arguments:
- **Nmap (`NmapAdapter`):**
  - Command: `nmap -sV -sC --version-light -T4 -oX - <target_host>`
  - Prohibitions: No `-A`, no `--script=exploit`, no `--script=dos`, no packet flooding.
- **SSLyze (`SslyzeAdapter`):**
  - Command: `sslyze --json_out=- <target_host>:<port>`
- **Nuclei (`NucleiAdapter`):**
  - Command: `nuclei -u <target_url> -j -silent -tags cve,misconfig -severity low,medium,high,critical`
  - Prohibitions: No `-tags dos,fuzz,intrusive`.
- **FFuF (`FfufAdapter`):**
  - Command: `ffuf -u <target_url>/FUZZ -w <wordlist> -mc 200,204,301,302,307,401,403 -o - -of json -t 5 -rate 10`
  - Prohibitions: Max rate capped at 10 RPS to preserve target stability.
- **Semgrep (`SemgrepAdapter`):**
  - Command: `semgrep scan --config auto --json <target_dir>`
- **Gitleaks (`GitleaksAdapter`):**
  - Command: `gitleaks detect --source <target_dir> --report-format json --report-path -`
- **Bandit (`BanditAdapter`):**
  - Command: `bandit -r <target_dir> -f json`
- **Trivy (`TrivyAdapter`):**
  - Command: `trivy fs --format json <target_dir>`
- **Checkov (`CheckovAdapter`):**
  - Command: `checkov -d <target_dir> -o json --compact`

### 4.3 Subprocess Isolation & Lifecycle Bounds
- All CLI processes are spawned via `asyncio.create_subprocess_exec()` with strict memory/timeout limits.
- Maximum execution timeout per tool: 60.0 seconds.
- Subprocesses are assigned to dedicated process groups and are immediately terminated on scan cancellation or timeout.

### 4.4 In-App Tool Installation & Lifecycle Management Safety Rules
1. **User-Space Binary Isolation:**
   - Standalone binaries downloaded in-app (`nuclei`, `ffuf`, `gitleaks`, `trivy`) MUST be placed in an isolated managed directory `backend/bin/` with strictly verified executable permissions (`0o755` on POSIX).
   - Dynamic binary downloads MUST originate exclusively from official verified HTTPS release assets (e.g. GitHub Releases under official vendor repositories: `projectdiscovery/nuclei`, `ffuf/ffuf`, `gitleaks/gitleaks`, `aquasecurity/trivy`).
2. **Safe Python Package Installation:**
   - Python-based tools (`sslyze`, `bandit`, `semgrep`, `checkov`) MUST be installed by executing the active interpreter (`sys.executable -m pip install --upgrade <package>`) without elevating privileges.
3. **Privilege Boundary Enforcement:**
   - Tools requiring system-level network drivers or root privileges (e.g., Nmap needing Npcap on Windows or `sudo` raw sockets on Linux) MUST NOT attempt silent privilege escalation. The platform MUST guide the user with clear, copyable OS package manager commands (`winget`, `brew`, `apt`) or launch the official vendor setup installer with explicit OS user confirmation.
4. **Archive Extraction Path Traversal Protection:**
   - All `.zip` and `.tar.gz` archive extractions MUST validate target file paths to prevent directory traversal (`Zip Slip`) attacks outside `backend/bin/`.
5. **Real-time Telemetry & Bounded Timeouts:**
   - Tool installation tasks run asynchronously and stream output line-by-line over SSE (`event: install_progress`, `event: install_log`).
   - Maximum download and installation timeout: 180.0 seconds per tool.

---

## 5. Rate Limiting, Throttling & Circuit Breakers

### 5.1 Token Bucket Rate Limiting
- Every network-touching engine routes requests through an asynchronous Token Bucket Rate Limiter.
- **Default Rate:** 5 requests per second (RPS).
- **Configurable Range:** 1 RPS to 20 RPS.
- **Burst Limit:** Maximum burst of 10 requests.

### 5.2 Automated Circuit Breakers & Backoff Policy
- **Consecutive Error Trigger:** If a target returns **5 consecutive 5xx Server Errors** or **3 consecutive connection timeouts (>10s)**:
  1. The scanner transitions to `THROTTLED` state, pausing outbound requests for 10 seconds.
  2. Rate limit is automatically halved.
  3. A `WARNING` log is emitted to the real-time event stream.
- **Fatal Abort Trigger:** If errors persist after backoff, the engine trips the circuit breaker:
  1. Active scan stage safely aborts with status `COMPLETED_WITH_WARNINGS` or `FAILED`.
  2. A finding is registered: `"Target Unresponsive / Rate-Limited: Scan Aborted Safely to Protect Target"`.

### 5.3 Strict Network Timeout Bounds
- **HTTP Request Timeout:** 10.0 seconds maximum.
- **TLS Handshake Timeout:** 5.0 seconds maximum.
- **TCP Socket Connect Timeout:** 2.0 seconds maximum.
- **DNS Query Timeout:** 3.0 seconds maximum.
- **Tool Adapter Subprocess Timeout:** 60.0 seconds maximum.
- Unbounded blocking calls are strictly prohibited across all code paths.

---

## 6. Data Privacy, Local Execution & Redaction

1. **100% Local Execution:**
   - All scan orchestration, rule evaluation, AST parsing, scoring, and report rendering execute exclusively on the host system.
   - Zero telemetry, metrics, target URLs, source code, or discovered secrets are transmitted to external servers.
2. **Automatic Secret Masking in Evidence:**
   - All high-entropy secrets, API tokens, and private keys discovered by `code_sast` or `infra_iac` MUST be masked in findings (e.g. `AKIAIOSFODNN7EXAMPLE` -> `AKIA*************PLE`).
   - Plaintext secrets MUST NEVER be written in plain readable format in logs, HTML exports, or SARIF output.
3. **Local Storage Lifecycle:**
   - Scan jobs, findings, and logs are persisted to local JSON files under `data/scans/{scan_id}.json`.
   - Users can delete individual scans or clear the entire history at any time.

---

## 8. Platform Defense, Zero-Trust Access Control & SSRF Gateway

To guarantee that CyberAssess itself cannot be weaponized or compromised when deployed on private intranets or cloud environments:

### 8.1 Strict Server-Side Request Forgery (SSRF) Protection Gateway
All arbitrary outbound request facilities (including the HTTP Repeater `/api/tools/repeater` and dynamic network probes) MUST pass through the centralized `SSRFProtector` gateway before socket connection:
1. **CIDR Denylist Validation:**
   - `127.0.0.0/8` (IPv4 Loopback)
   - `::1/128` (IPv6 Loopback)
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 Private Intranets)
   - `169.254.0.0/16`, `fe80::/10` (Link-Local & Cloud Instance Metadata e.g. AWS/GCP/Azure `169.254.169.254`)
   - `100.64.0.0/10` (Carrier-Grade NAT)
   - `0.0.0.0/8`, `fc00::/7` (Unique Local Unicast)
2. **DNS Pre-Resolution & Rebinding Protection:**
   - The target hostname is resolved to IP addresses via trusted DNS resolvers.
   - Every resolved IP address is verified against the CIDR blocklist.
   - If any resolved IP is blocked, the request is immediately aborted with `HTTP 400 Bad Request: SSRF Protection Blocked`.
   - Outbound HTTP connections bind directly to the pre-verified IP while injecting the original `Host` header to eliminate Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding vulnerabilities.
3. **Redirect Chain Interception:**
   - All HTTP redirect targets (`Location:` headers) are validated against the SSRF policy before following.
4. **Authorized Intranet Override Gate:**
   - Scanning internal infrastructure is permitted ONLY when authenticated under the `ADMIN` role with the explicit flag `allow_internal_target=true`.

### 8.2 Zero-Trust Authentication & Role-Based Access Control (RBAC)
1. **Authentication Boundary:**
   - All REST and SSE API endpoints (`/api/scans/*`, `/api/tools/*`, `/api/assets/*`, `/api/findings/*`) require signed JWT Bearer tokens or verified `X-API-Key` headers.
   - Password hashing uses standard PBKDF2-HMAC-SHA256 with cryptographic salt ($\ge 100,000$ iterations).
2. **Multi-Tiered RBAC Matrix:**
   - `ADMIN`: Full administrative control, user/organization provisioning, tool lifecycle, SSRF policy overrides.
   - `SECURITY_ANALYST`: Scan creation, HTTP Repeater, full finding triage, report exports.
   - `DEVELOPER`: Scans restricted to assigned assets/projects, finding remediation updates.
   - `VIEWER`: Read-only access to completed scan dashboards and compliance reports.
3. **CORS Hardening:**
   - Production deployments restrict `Access-Control-Allow-Origin` to configured trusted origins (disallowing wildcard `*` with credentials).

---

## 9. Target Path Sandboxing & Workspace Containment

When scanning local filesystem targets (`LOCAL_PATH`, `DOCKERFILE`, `IAC_MANIFEST`):
1. **Workspace Boundary Enforcement:**
   - Target paths MUST resolve within allowed workspace roots (e.g. `data/workspaces/`, configured `ALLOWED_SCAN_ROOTS`, or relative project roots).
2. **Sensitive System Directory Denylist:**
   - The platform strictly rejects scanning of system-critical paths:
     - POSIX: `/etc`, `/root`, `/var/run`, `/proc`, `/sys`, `/dev`, `~/.ssh`, `~/.aws`, `~/.kube`
     - Windows: `C:\Windows`, `C:\Program Files`, `C:\Users\*\AppData`, `~/.ssh`, `~/.aws`
3. **Symlink Resolution & Canonical Path Verification:**
   - Real filesystem paths are resolved with `realpath()` prior to inspection. Traversal sequences (`../`) resolving outside permitted roots are rejected immediately.

---

## 10. Tool Supply Chain Integrity & Cryptographic Verification

1. **Manifest-Pinned Versioning:**
   - All downloadable external tool binaries are cataloged in an authoritative `ToolManifest` defining exact semantic versions and official repository sources.
2. **Cryptographic SHA-256 Checksum Verification:**
   - Downloaded release archives MUST be cryptographically validated against pre-computed SHA-256 digests across all supported OS/CPU combinations (`windows_amd64`, `linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64`).
   - Any archive with a mismatched hash is immediately discarded and logged as a security alert.
3. **Quarantine Extraction:**
   - Archives are unpacked in isolated temporary quarantine directories before atomic deployment to `backend/bin/`.

