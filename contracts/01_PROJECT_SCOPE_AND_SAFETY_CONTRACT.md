# Contract 01: Project Scope, Safety, Legal Boundaries & Operational Limits

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 3.0.0 (Comprehensive Production Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Platform Core Architecture, Safety Standards & Security Operations  

---

## 1. System Vision & Purpose

The **Automated Security Assessment & Vulnerability Management Platform** is an enterprise-grade, fully automated, non-destructive security auditing and vulnerability management platform. Designed for security architects, DevSecOps pipelines, and application developers, the platform provides deep, calculated, and mathematically verified security assessments across the complete modern software stack.

When pointed to a target (Web URL, Domain Name, Host IP Address, Source Code Repository, Container Specification, or Infrastructure-as-Code Template), the platform automatically orchestrates a comprehensive battery of non-intrusive, non-disruptive, and deterministic security checks across five core security domains:
1. **Network Perimeter, TLS/SSL & DNS Infrastructure** (`network`)
2. **Web Application, Modern Browser & REST/GraphQL API Security (DAST)** (`web_dast`)
3. **Static Code Analysis, Secrets, Cryptography & Software Composition (SAST/SCA)** (`code_sast`)
4. **Infrastructure-as-Code, Container & Cloud Posture (IaC)** (`infra_iac`)
5. **CI/CD Pipeline & Build Automation Security** (`cicd_audit`)

The platform calculates deterministic CVSS v3.1-aligned security scores and letter grades (`A+` to `F`), streams real-time execution logs and vulnerability findings over Server-Sent Events (SSE), and exports industry-standard reports (Interactive Standalone HTML, OASIS SARIF v2.1.0 for GitHub Code Scanning, and structured JSON).

---

## 2. Strict Safety & Non-Destructive Operations Contract

### 2.1 The Zero-Harm Non-Destructive Mandate
Every scanning engine, check module, and network probe in this system MUST operate strictly within a **zero-harm, non-destructive, non-disruptive** operational framework:

1. **Strictly Non-Destructive Inspection:**
   - Modules MUST NOT transmit destructive payloads (e.g., SQL `DROP`/`DELETE`, command injection triggers, filesystem tampering, or memory corruption exploits).
   - Dynamic tests are strictly restricted to:
     - Passive HTTP header and cookie observation
     - Standard HTTP request method inspection (`OPTIONS`, `HEAD`, `GET`)
     - Safe probe requests (e.g., testing if a sensitive path returns `403` vs `200` with known headers)
     - Safe SSL/TLS handshake metadata negotiation and cipher enumeration
     - Passive DNS record resolution (`TXT`, `MX`, `A`, `AAAA`, `CAA`, `DNSKEY`, `DS`)
     - Safe, non-saturating TCP socket connection checks (`connect()` and immediate `close()`)
     - Read-only GraphQL introspection queries
2. **No Denial of Service (DoS) or Resource Exhaustion:**
   - Packet flooding, stress testing, high-concurrency fuzzing, slowloris attacks, and brute-force password cracking are strictly prohibited.
   - Concurrency per target is capped by default to 5 workers (configurable up to a hard ceiling of 15).
3. **No Authentication Bypassing or Brute Forcing:**
   - Scanners MUST NOT attempt credential stuffing, dictionary attacks, or automated brute-forcing of login forms.
   - When authenticated scanning is configured, the system uses user-supplied API keys or bearer tokens strictly as read-only audit credentials.

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

## 4. Rate Limiting, Throttling & Circuit Breakers

### 4.1 Token Bucket Rate Limiting
- Every network-touching engine routes requests through an asynchronous Token Bucket Rate Limiter.
- **Default Rate:** 5 requests per second (RPS).
- **Configurable Range:** 1 RPS to 20 RPS.
- **Burst Limit:** Maximum burst of 10 requests.

### 4.2 Automated Circuit Breakers & Backoff Policy
- **Consecutive Error Trigger:** If a target returns **5 consecutive 5xx Server Errors** or **3 consecutive connection timeouts (>10s)**:
  1. The scanner transitions to `THROTTLED` state, pausing outbound requests for 10 seconds.
  2. Rate limit is automatically halved.
  3. A `WARNING` log is emitted to the real-time event stream.
- **Fatal Abort Trigger:** If errors persist after backoff, the engine trips the circuit breaker:
  1. Active scan stage safely aborts with status `COMPLETED_WITH_WARNINGS` or `FAILED`.
  2. A finding is registered: `"Target Unresponsive / Rate-Limited: Scan Aborted Safely to Protect Target"`.

### 4.3 Strict Network Timeout Bounds
- **HTTP Request Timeout:** 10.0 seconds maximum.
- **TLS Handshake Timeout:** 5.0 seconds maximum.
- **TCP Socket Connect Timeout:** 2.0 seconds maximum.
- **DNS Query Timeout:** 3.0 seconds maximum.
- Unbounded blocking calls are strictly prohibited across all code paths.

---

## 5. Data Privacy, Local Execution & Redaction

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

## 6. Audit Trail & Legal Authorization Contract

- **User Consent Notice:** The platform UI displays a permanent notice: *"Only run security assessments against targets you own or have explicit written authorization to test."*
- **Audit Logging:** Every scan record persistently logs:
  - Unique UUID v4 `scan_id`
  - Exact target identifier and resolved IP
  - Selected profile and enabled engine list
  - User agent / scanner identifier used
  - Start timestamp, completion timestamp, and duration
  - Total request count and bytes transferred
