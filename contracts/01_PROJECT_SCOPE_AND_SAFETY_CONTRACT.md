# Contract 01: Project Scope, Safety, Legal Boundaries & Enterprise Security Architecture

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 10.0.0 (Enterprise Security Architecture, Control/Execution Plane Separation, Zero-Trust Invariants, Multi-Tenancy & ASVS Baseline)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Platform Core Architecture, Safety Standards, Zero-Trust Security Controls, Multi-Tenant Governance & Operational Boundaries  

---

## 1. System Vision & Purpose

The **CyberAssess Security Assessment & Vulnerability Management Platform** is an enterprise-grade, automated, defensive security assessment, Application Security Posture Management (ASPM), and External Attack Surface Management (EASM) platform. Designed for security architects, professional penetration testers, DevSecOps pipelines, and application developers, the platform provides calculated, deterministic, and verifiable security assessments across the complete modern software stack.

CyberAssess is logically separated into:
1. **Control Plane:** FastAPI web application providing identity, authentication, multi-tenant Role-Based Access Control (RBAC), asset inventory, canonical finding lifecycle, contextual risk evaluation, audit logging, and scan scheduling. The control plane is NOT a privileged execution environment.
2. **Execution Plane:** Isolated worker execution environment running containerized or sandboxed workers (DAST, SAST, Infra/Cloud) with strict workspace confinement, egress network controls, resource limits, and real-time process lifecycle governance.
3. **Evidence & Persistence Layer:** Authoritative relational database (PostgreSQL for enterprise, SQLite WAL for single-node standalone) and encrypted object storage for reproducible, cryptographically hashed evidence artifacts.

The platform orchestrates a fleet of **21 authoritative security tool adapters** backed by native fallback engines across five security domains:
- **Network Perimeter & EASM:** `nmap`, `sslyze`, `subfinder`, `httpx`
- **Web DAST & Crawling:** `nuclei`, `ffuf`, `katana`
- **SAST & Secrets:** `semgrep`, `bandit`, `gitleaks`, `trufflehog`, `retire`
- **Supply Chain & SCA:** `trivy`, `syft`, `grype`, `osv-scanner`
- **Cloud, K8s & IaC Posture:** `checkov`, `prowler`, `kube-bench`, `dockle`, `schemathesis`

---

## 2. Standards Baseline

CyberAssess is engineered in conformance with the following international security and development standards:

### 2.1 Application Security
- **OWASP ASVS 5.0.0 (Application Security Verification Standard):** Version-qualified controls (`v5.0.0-V1` through `v5.0.0-V14`) covering architecture, authentication, session management, access control, input validation, cryptography, error handling, data protection, communications, and malicious code search.
- **OWASP SSRF Prevention Guidance:** Strict pre-resolution, CIDR denylisting, DNS-rebinding prevention, and hop-by-hop redirect verification.
- **OWASP Authentication and Password Storage Guidance:** Elimination of default credentials, minimum password lengths, and PBKDF2/Argon2id hashing.

### 2.2 Secure Software Development
- **NIST SP 800-218 (Secure Software Development Framework - SSDF v1.1):** Protect Software (PW), Produce Well-Secured Software (PW), Respond to Vulnerabilities (RV).
- **NIST SP 800-53 Rev. 5 / 5.2.0:** Access Control (AC), Identification and Authentication (IA), Audit and Accountability (AU), System and Communications Protection (SC), System and Information Integrity (SI).

### 2.3 Cryptography & Token Standards
- **RFC 8725 (JWT Best Current Practices):** Explicit algorithm allowlist (`HS256`, `RS256`), algorithm confusion denial (`alg=none` forbidden), cryptographic key separation, expiration enforcement, subject/issuer/audience validation.

### 2.4 Software Supply Chain
- **SLSA (Supply-chain Levels for Software Artifacts) & CycloneDX:** Pinned release tags, cryptographically verified SHA-256 binaries, quarantine pipelines, and standardized CycloneDX 1.5 / SPDX 2.3 SBOM generation.

---

## 3. Global Security Invariants

The platform enforces five non-negotiable security invariants across all subsystems:

1. **Zero Trust (ASVS v5.0.0-V1.4.1):** No request, internal component, or client parameter is trusted implicitly. Every request must present valid authentication and authorization credentials.
2. **Least Privilege (NIST SP 800-53 AC-6):** Every user, service key, worker process, container, filesystem path, and network socket operates strictly with the minimum permissions required.
3. **Fail Closed (ASVS v5.0.0-V1.1.2):** Any security exception, missing authentication context, unresolved target, ambiguous tenant ownership, unverified tool artifact, or malformed token results in immediate denial.
4. **No Silent Security Degradation:** The platform shall never silently downgrade authenticated sessions to anonymous, sandboxed execution to unrestricted, database persistence to memory-only, or verified hashes to unverified bypasses.
5. **Authoritative Multi-Layer Enforcement:** Security boundaries are enforced authoritatively in the service and data access layers, never exclusively in routing or UI components.

---

## 4. Operating Modes

The platform supports two explicit operational configurations:

### 4.1 Standalone Mode (Single-Node)
- **Persistence:** Relational SQLite with Write-Ahead Logging (`WAL` mode) at `data/cyberassess.db`.
- **Execution:** In-process asynchronous task queue with bounded worker concurrency semaphore (`MAX_CONCURRENT_SCANS`).
- **Use Case:** Local security researcher, single penetration tester, air-gapped laptop, developer workstation.

### 4.2 Enterprise Mode (Distributed Multi-Tenant)
- **Persistence:** Enterprise PostgreSQL cluster with connection pooling and schema migrations.
- **Execution:** Durable message queue (Redis / RabbitMQ / Celery worker pool) dispatching to dedicated container sandboxes.
- **Identity:** Multi-tenant organization isolation with OIDC / SAML SSO integration readiness.
- **Use Case:** Corporate DevSecOps pipelines, multi-tenant ASPM, large-scale continuous attack surface monitoring.

---

## 5. Resource Governance & Operational Boundaries

To prevent denial of service and server resource exhaustion:
- **Concurrency Caps:** Global maximum concurrent scans (`MAX_CONCURRENT_SCANS = 5` default) and per-tenant scan limits.
- **Execution Timeouts:** Hard timeout per scan job (`GLOBAL_SCAN_TIMEOUT_SECONDS = 300.0` default) and per tool adapter execution (`60.0s`).
- **Process Governance:** Scan cancellation strictly terminates the entire process tree (orchestrator task, child processes, and grandchild tool binaries).
- **Filesystem Quotas:** Maximum workspace upload size (100 MB) and maximum scan output log buffer size (10 MB).
- **Network Rate Limiting:** Token-bucket rate limiters restricting outgoing HTTP probes (default 5 req/sec) with automatic backoff.

---

## 6. Safety & Non-Destructive Operations

All assessment engines operate strictly within a non-destructive framework:
- **No Destructive Payloads:** Prohibits SQL `DROP`/`DELETE`/`UPDATE`, live shell commands, filesystem wiping, memory corruption, or real data exfiltration.
- **Benign Probes Only:** SQL injection uses timing delays (`SLEEP(2)`) and benign boolean reflections (`1=1`). XSS uses inert elements (`<script>/*probe*/</script>`).
- **Active Parameter Fuzzing:** Rate-bounded, non-destructive parameter probes with full reproduction `curl` generation.
