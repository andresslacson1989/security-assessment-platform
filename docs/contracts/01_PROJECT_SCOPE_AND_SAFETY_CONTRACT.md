# Contract 01: Project Scope, Safety, Legal Boundaries & Operational Limits

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 4.1.0 (Enterprise Hybrid Tool Adapter & Penetration Testing Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Platform Core Architecture, Safety Standards & Security Operations  

---

## 1. System Vision & Purpose

The **Automated Security Assessment & Vulnerability Management Platform** is an enterprise-grade, automated, defensive penetration testing and vulnerability management platform. Designed for security architects, professional penetration testers, DevSecOps pipelines, and application developers, the platform provides deep, calculated, and mathematically verified security assessments across the complete modern software stack.

When pointed to a target (Web URL, Domain Name, Host IP Address, Source Code Repository, Container Specification, or Infrastructure-as-Code Template), the platform automatically orchestrates a comprehensive battery of non-destructive, high-fidelity, and deterministic security checks across five core security domains:
1. **Network Perimeter, TLS/SSL & DNS Infrastructure & Passive OSINT** (`network`)
2. **Web Application, Scoped Crawling, Authenticated DAST & Active Parameter Fuzzing** (`web_dast`)
3. **Static Code Analysis, Interprocedural AST Taint Flow, Git Secrets & Software Composition** (`code_sast`)
4. **Infrastructure-as-Code, Container & Cloud Posture (IaC)** (`infra_iac`)
5. **CI/CD Pipeline & Build Automation Security** (`cicd_audit`)

The platform operates on a **Tiered Hybrid Engine Architecture**:
- **Tier 1 (Native Async Core):** Zero-prerequisite, 100% portable Python async engines that execute instantly out of the box on any standard OS without external dependencies.
- **Tier 2 (Pluggable Tool Adapters):** Dynamic adapters that detect and orchestrate battle-tested CLI tools (**Nmap**, **Nuclei**, **Semgrep**, **Trivy**) when present on the host system or container image, augmenting depth with seamless native fallback.

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
3. **Session Heartbeat & Graceful Recovery:**
   - The engine periodically evaluates a configurable `logged_in_indicator` (HTTP status code, response header, or body regex). If session invalidation or 401/403 status is observed, the engine re-authenticates automatically or logs a session expiry event without crashing.

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

## 4. Enterprise Hybrid Tool Adapter Architecture & Safe Subprocess Boundaries

To combine zero-dependency portability with enterprise-grade penetration testing power, the platform operates a **Tiered Hybrid Adapter Model**:

```
                              ┌───────────────────────────────────────────────┐
                              │            CYBERASSESS ORCHESTRATOR           │
                              └──────────────────────┬────────────────────────┘
                                                     │
                     ┌───────────────────────────────┴───────────────────────────────┐
                     ▼                                                               ▼
        ┌─────────────────────────┐                                     ┌─────────────────────────┐
        │  NATIVE ASYNC ENGINES   │                                     │  TOOL ADAPTER PLUGINS   │
        │ (Zero-Prerequisite Core)│                                     │ (Enhanced Enterprise)   │
        ├─────────────────────────┤                                     ├─────────────────────────┤
        │ • Native TLS / DNS      │◄────────[Graceful Fallback]─────────┤ • Nmap / Npcap Adapter  │
        │ • Native HTTP DAST      │◄────────[Graceful Fallback]─────────┤ • Nuclei Engine Adapter │
        │ • Native BFS Crawler    │                                     │ • Semgrep SAST Adapter  │
        │ • Native AST Taint Flow │◄────────[Graceful Fallback]─────────┤ • Trivy SCA Adapter     │
        └─────────────────────────┘                                     └─────────────────────────┘
                     │                                                               │
                     └───────────────────────────────┬───────────────────────────────┘
                                                     ▼
                                      ┌─────────────────────────────┐
                                      │ CANONICAL NORMALIZER (SARIF)│
                                      │   (Single Unified Schema)   │
                                      └─────────────────────────────┘
```

### 4.1 Zero-Failure Fallback Guarantee
1. **Host Discovery:** The orchestrator automatically probes system `PATH` and configured paths via `shutil.which` at startup and scan initialization.
2. **Transparent Fallback:** If an external binary (`nmap`, `nuclei`, `semgrep`, `trivy`) is not installed or errors during startup, the platform automatically and silently falls back to its built-in native Python engine. The scan NEVER crashes due to missing external binaries.
3. **Execution Mode Reporting:** Every finding records its `source_tool` (`"native"`, `"nmap"`, `"nuclei"`, `"semgrep"`, `"trivy"`) for audit transparency.

### 4.2 Safe Non-Destructive Subprocess Execution Flags
External tools MUST be invoked with strictly bounded, non-destructive arguments:
- **Nmap (`NmapAdapter`):**
  - Command: `nmap -sV -sC --version-light -T4 -oX - <target>`
  - Prohibitions: No `-A`, no `--script=exploit`, no `--script=dos`, no packet flooding.
- **Nuclei (`NucleiAdapter`):**
  - Command: `nuclei -u <target> -j -silent -tags cve,misconfig -severity low,medium,high,critical`
  - Prohibitions: No `-tags dos,fuzz,intrusive`.
- **Semgrep (`SemgrepAdapter`):**
  - Command: `semgrep scan --config auto --json <target_dir>`
- **Trivy (`TrivyAdapter`):**
  - Command: `trivy fs --format json <target_dir>`

### 4.3 Subprocess Isolation & Lifecycle Bounds
- All CLI processes are spawned via `asyncio.create_subprocess_exec()` with strict memory/timeout limits.
- Maximum execution timeout per tool: 60.0 seconds.
- Subprocesses are assigned to dedicated process groups and are immediately terminated on scan cancellation or timeout.

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

## 7. Audit Trail & Legal Authorization Contract

- **User Consent Notice:** The platform UI displays a permanent notice: *"Only run security assessments against targets you own or have explicit written authorization to test."*
- **Audit Logging:** Every scan record persistently logs:
  - Unique UUID v4 `scan_id`
  - Exact target identifier and resolved IP
  - Selected profile, enabled engine list, and active tool adapters
  - User agent / scanner identifier used
  - Start timestamp, completion timestamp, and duration
  - Total request count and bytes transferred
