# Contract 01: Project Scope, Safety, Legal Boundaries & Enterprise Security Architecture

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 11.0.0 (Security Invariant Closure, Trust-Boundary Enforcement, Authoritative State & Independent Assurance)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Platform Core Architecture, Safety Standards, Zero-Trust Security Controls, Multi-Tenant Governance & Operational Boundaries  

---

## 1. System Vision & Purpose

The **CyberAssess Security Assessment & Vulnerability Management Platform** is an enterprise-grade, automated, defensive security assessment, Application Security Posture Management (ASPM), and External Attack Surface Management (EASM) platform. Designed for security architects, professional penetration testers, DevSecOps pipelines, and application developers, the platform provides calculated, deterministic, and verifiable security assessments across the complete modern software stack.

CyberAssess is logically separated into:
1. **Control Plane:** FastAPI web application providing identity, authentication, multi-tenant Role-Based Access Control (RBAC), asset inventory, canonical finding lifecycle, contextual risk evaluation, audit logging, and scan scheduling. The control plane is NOT a privileged execution environment.
2. **Execution Plane:** Isolated worker execution environment running containerized or sandboxed workers (DAST, SAST, Infra/Cloud) with strict workspace confinement, egress network controls, resource limits, and real-time process lifecycle governance via `ProcessSupervisor`.
3. **Evidence & Persistence Layer:** Authoritative relational database (PostgreSQL for enterprise, SQLite WAL for single-node standalone) and encrypted object storage for reproducible, cryptographically hashed evidence artifacts. JSON storage is strictly for exports/backups and never serves as runtime persistence authority.

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
- **OWASP SSRF Prevention Guidance:** Strict pre-resolution, CIDR denylisting, DNS-rebinding prevention, connection-level destination binding, and hop-by-hop redirect verification.
- **OWASP Authentication and Password Storage Guidance:** Elimination of default credentials, minimum password lengths, PBKDF2/Argon2id hashing, and authoritative token/key revocation state.

### 2.2 Secure Software Development
- **NIST SP 800-218 (Secure Software Development Framework - SSDF v1.1):** Protect Software (PW), Produce Well-Secured Software (PW), Respond to Vulnerabilities (RV).
- **NIST SP 800-53 Rev. 5 / 5.2.0:** Access Control (AC), Identification and Authentication (IA), Audit and Accountability (AU), System and Communications Protection (SC), System and Information Integrity (SI).

### 2.3 Cryptography & Token Standards
- **RFC 8725 (JWT Best Current Practices):** Library-backed verification (PyJWT), explicit algorithm allowlist (`HS256`, `RS256`), algorithm confusion denial (`alg=none` forbidden), cryptographic key separation, expiration enforcement, and strict claim validation (`iss`, `aud`, `sub`, `exp`, `iat`, `nbf`). Production startup fails closed if signing keys are unconfigured.

### 2.4 Software Supply Chain
- **SLSA (Supply-chain Levels for Software Artifacts) & CycloneDX:** Pinned release tags (`/releases/tags/{version}`), cryptographically verified SHA-256 binaries, quarantine pipelines, atomic promotion, and standardized CycloneDX 1.5 SBOM generation.

---

## 3. Global Security Invariants

The platform enforces eight non-negotiable security invariants across all subsystems:

1. **Identity Invariant (ASVS v5.0.0-V1.4.1):** A request is authorized ONLY when authenticated, identity is active (`is_active=True`), credential is valid and not revoked (`revoked_at is None`), required permission/scope is present, tenant ownership is valid, and resource state permits operation.
2. **Tenant Invariant (NIST SP 800-53 AC-3):** Every tenant-owned object MUST have a non-null `organization_id`. `organization_id IS NULL` is prohibited from conferring global or default access. Explicit principal classification separates `SYSTEM_PRINCIPAL` from `TENANT_PRINCIPAL`.
3. **Target Invariant (ASVS v5.0.0-V5.1.1):** Every scan target must pass through the authoritative target security gateway (`assert_safe_target()`) covering `URL`, `DOMAIN`, `IP`, `LOCAL_PATH`, `DOCKERFILE`, `IAC_MANIFEST`. Fail-closed DNS resolution, connection-level IP binding, and hop-by-hop redirect validation are strictly enforced.
4. **Workspace Invariant (ASVS v5.0.0-V5.3.4):** Local scan paths must be strictly confined to server-derived authorized workspace roots (`resolved_path ∈ authorized_workspace_root`). Clients cannot supply arbitrary roots; symlink traversal escapes are rejected; missing workspace configurations fail closed.
5. **Supply-Chain Invariant (NIST SP 800-218 PW.4):** A binary is trusted only when exact release, exact asset, platform, architecture, and trusted SHA-256 digest match. Tool installation uses quarantine extraction and atomic promotion; unpinned or digest-less tools fail closed.
6. **Persistence Invariant (ASVS v5.0.0-V1.1.2):** Exactly one authoritative relational database source of truth. JSON files are strictly export/backup artifacts and never resurrect deleted or alternate database records. Database failures are never swallowed.
7. **Execution Invariant (NIST SP 800-53 SC-2):** A scan cancellation or timeout strictly terminates the entire process tree (orchestrator task, child subprocesses, and grandchild binaries) via `ProcessSupervisor`. Concurrency is strictly bounded.
8. **Evidence & Audit Invariant (NIST SP 800-53 AU-9):** Security evidence is sanitized at data boundaries, hashed, and attributable. Audit logs are tamper-evident using cryptographically chained SHA-256 hashes (`event_hash = SHA256(canonical_payload + previous_event_hash)`). SLA clocks never reset on redetections.

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
