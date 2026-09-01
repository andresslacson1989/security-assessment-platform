# Contract 09: Authoritative Enterprise Security Tool Implementation Contract & Execution Specifications

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 14.3.0 (Authoritative 21-Tool Fleet Implementation Specifications, Normative Destination Binding, Strict Provenance Governance & Multi-Tier Execution State Architecture)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Authority:** Platform Core Architecture, Tool Adapter Layer, Process Supervisor & Verification Pipeline  
**Scope:** Canonical implementation specifications, invocation boundaries, failure semantics, output error handling, rate/timing governance, normative schemas, and security classifications for all 21 supported external security tools.  
**Dependencies:** Contract 01 (Scope & Safety), Contract 02 (Data Schemas), Contract 03 (Engine & Plugin Interface), Contract 04 (API & Streaming), Contract 05 (Deliverables & Acceptance), Contract 06 (Check Catalog & CWE Mapping), Contract 07 (Frontend UI/UX), Contract 08 (Technical Implementation & Test Vectors).

---

# Part I: Architecture, Invariants & Generic Tool Contract Model

## 1. Executive Purpose & Governance Invariants

This authoritative contract governs the integration, execution, sandboxing, parsing, normalization, and supply-chain governance of every external security tool in CyberAssess.

No security tool may execute within the CyberAssess ecosystem unless it strictly satisfies the 41-point specification, normative schemas, and foundational invariants defined in this contract.

### 1.1 The Ten Fundamental Tool Execution Invariants

1. **The Target Validation & Normative Target Binding Invariant (Contract 01 §3, Contract 08 §2):**
   No tool adapter may ever receive raw, unvalidated user input strings. Network-capable tools receive ONLY an authoritative, immutable `ValidatedTarget`.
   - **Normative `ValidatedTarget` Schema:**
     ```python
     class ValidatedTarget(BaseModel):
         model_config = ConfigDict(frozen=True, extra="forbid")
         target_id: str                 # Cryptographic resource identity: sha256(canonical_value + ":" + selected_destination)
         authorization_decision_id: str # Cryptographic authorization token: sha256(org_id + ":" + project_id + ":" + asset_id + ":" + target_id + ":" + policy_version)
         integrity_seal: str            # Cryptographic signature/HMAC from Target Security Gateway
         organization_id: str           # Tenant isolation boundary (UUID)
         project_id: str                # Project isolation boundary (UUID)
         asset_id: str                  # Asset identity in inventory (UUID)
         target_type: TargetType        # URL, DOMAIN, IP, LOCAL_PATH, DOCKERFILE, IAC_MANIFEST
         raw_value: str                 # Original user-supplied input string
         canonical_value: str           # Normalized string (e.g. lowercase FQDN, normalized URL)
         authorized_scope: List[str]    # Authorized CIDRs / root domain wildcards
         resolved_addresses: List[str]  # All resolved IPv4/IPv6 addresses from pre-resolution
         selected_destination: str      # Specific pinned IP address selected for connection
         port: Optional[int] = None     # Target port (e.g. 443, 80, 22)
         scheme: Optional[str] = None   # Protocol scheme (http, https, tcp, udp)
         validation_timestamp: datetime # ISO-8601 UTC validation timestamp
         policy_version: str            # Target Security Gateway policy version (e.g. "14.3.0")
     ```
   - **Operational Immutability Definition:** `ValidatedTarget` is a frozen data structure (`frozen=True`). Once constructed and cryptographically sealed by the Target Security Gateway (`assert_safe_target()`), no attribute may be modified. Any target mutation, hostname change, or redirect resolution strictly requires instantiating a NEW `ValidatedTarget` instance through the gateway.
   - **Tool-Specific Destination Binding Invariant:** Pre-resolving DNS is necessary but insufficient to defeat Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding. Adapters MUST enforce connection-level destination binding using tool-native mechanisms:
     - **Nmap:** Targets `ValidatedTarget.selected_destination` (IP) with `--script-args http.host=<canonical_value>`.
     - **httpx:** Invoked with `httpx -u http://<selected_destination> -H "Host: <canonical_value>" -sni <canonical_value>`.
     - **Nuclei:** Invoked with `nuclei -u http://<selected_destination> -H "Host: <canonical_value>" -sni <canonical_value>`.
     - **Katana:** Invoked with `katana -u http://<selected_destination> -H "Host: <canonical_value>"`.
     - **FFuF:** Invoked with `ffuf -u http://<selected_destination>/FUZZ -H "Host: <canonical_value>"`.
     - **Schemathesis:** Uses a custom Python HTTP transport adapter binding direct socket connections to `selected_destination` with overridden `Host` headers.
     - **SSLyze:** Connects directly to `<selected_destination>:<port>` with `--sni=<canonical_value>` for SNI.

2. **The Workspace Confinement Invariant (Contract 01 §3, Contract 08 §3):**
   Filesystem and source analysis tools must execute strictly within the server-derived authorized workspace root. Symlink traversal escapes, sensitive system directories (`/etc`, `/root`, `C:\Windows`, `.ssh`, `.aws`), and arbitrary host paths fail closed.

3. **The Supply-Chain Trust Boundary Invariant (Contract 03 §2, Contract 08 §4):**
   Every tool artifact must declare its exact supply-chain trust mode:
   - **`DIRECT_ARTIFACT_MODE` (GitHub Release Standalone Binaries):** Must match exact approved release tag AND verify against canonical SHA-256 archive digest in `PINNED_TOOL_MANIFEST` before quarantine promotion.
   - **`PACKAGE_MANAGER_MODE` (System Binaries & Pip Wheels):** Trust delegated to verified OS package manager (WinGet / apt / brew) or pip locked hashes in `requirements.txt`. Explicitly classified as `[UNVERIFIED (Package Manager Delegated)]` for raw artifact hashes, relying on package manager transport and repository trust.
   - **Exact Version Enforcement:** The adapter MUST enforce `actual_version == approved_version` during runtime probe. Any version discrepancy triggers `INVALID_VERSION` and blocks tool execution.

4. **The Process Supervision & Non-Destructive Invariant (Contract 03 §3, Contract 05 §2):**
   All subprocess executions are governed exclusively through `ProcessSupervisor` with isolated process groups, strict execution timeouts (default 60s), 10MB output buffers, and recursive process tree termination on cancellation or timeout. Destructive exploits and data dumps are prohibited in automated modes.

5. **The Deterministic Output & Parser Invariant (Contract 06 §1, Contract 06 §2):**
   Tool output is untrusted input. Every adapter must validate schema integrity and transform raw observations into canonical `Finding` objects mapped to explicit CWE, OWASP Top 10, ASVS 5.0, and NIST SP 800-53 controls with cryptographic SHA-256 evidence digests (`evidence_hash`).

6. **The Explicit Coverage Degradation & Fallback Preservation Invariant (Contract 05 §1):**
   A tool failure, missing binary, timeout, or cancellation MUST NEVER be erased or hidden by fallback execution.
   - The failure event (`tool_failed`) is permanently recorded in scan telemetry and database logs.
   - The assessment status transitions to `coverage_status = COVERAGE_DEGRADED`.
   - The native engine executes to provide **Partial Baseline Coverage**.
   - Findings generated by the native fallback are tagged with `source_tool: "native"`, `is_fallback: true`, and `primary_tool_failed: "<tool_id>"`.
   - The scan summary explicitly documents the **Coverage Loss**.

7. **The Three-Tier Authorization Invariant for Intrusive Operations:**
   No tool may execute `ACTIVE_INTRUSIVE` or `STATE_CHANGING` operations (such as active fuzzing, intrusive NSE scripts, or POST/DELETE mutation testing) unless three independent gates pass:
   1. `TOOL_CAPABILITY`: Tool adapter supports the requested probe.
   2. `PROFILE_AUTHORIZATION`: Scan profile allows intrusive actions (e.g. `FULL_STACK`, `API_FOCUSED`).
   3. `TENANT_SCOPE_AUTHORIZATION`: Tenant asset ownership explicitly grants active intrusive assessment permissions (`active_probing_granted == True`).

8. **The Multi-Dimensional Security Classification Invariant:**
   Every tool execution must declare its exact operational security classes:
   - `PASSIVE`: Zero network traffic sent to target (e.g., Subfinder, Syft).
   - `ACTIVE_READ_ONLY`: Non-state-changing network requests (e.g., SSLyze, httpx, Katana).
   - `ACTIVE_INTRUSIVE`: Fuzzing, active port probing, default scripts (e.g., Nmap with `-sC`, FFuF, Nuclei).
   - `STATE_CHANGING`: POST/PUT/DELETE fuzzing or auth creation (e.g., Schemathesis).
   - `CREDENTIAL_AWARE`: Ingests or verifies credentials/tokens (e.g., TruffleHog, Prowler).
   - `PRIVILEGED`: Requires elevated host/cluster capabilities (e.g., in-cluster Kube-Bench).
   - `CODE_ANALYSIS`: Reads local repository files (e.g., Semgrep, Bandit, Gitleaks).
   - `SUPPLY_CHAIN`: Analyzes third-party packages/SBOMs (e.g., Trivy, Grype, OSV-Scanner, Retire.js).

9. **The Dual Execution State Architecture:**
   Tool execution cleanly separates:
   - **`Upstream Process Exit Code`:** Raw integer returned by the OS process (`0`, `1`, `2`, `-9`, etc.).
   - **`CyberAssess Normalized Execution State`:** Normalized assessment state (`COMPLETED_WITH_FINDINGS`, `COMPLETED_NO_FINDINGS`, `PARTIAL_RESULTS_WITH_WARNING`, `TOOL_EXECUTION_FAILED`, `EXECUTION_TIMED_OUT`, `EXECUTION_CANCELLED`, `EXECUTION_BLOCKED`).

10. **The Explicit Capability Taxonomy Invariant:**
    All tool capabilities must be explicitly classified into one of:
    - `SUPPORTED`: Implemented, tested, and verified in CyberAssess adapter.
    - `LIMITED`: Partially implemented with explicit boundary constraints.
    - `DEFERRED`: Planned for future roadmap milestones (e.g. E12).
    - `NOT_SUPPORTED`: Excluded by design or safety policy.
    - `UNVERIFIED`: Upstream feature claim pending empirical verification.

---

## 2. Rate Limiting, Timing & Concurrency Architecture

To prevent ambiguity, tool execution distinguishes between five distinct operational boundaries:

1. **Tool Timing Profile (e.g., Nmap `-T4`):** `[UPSTREAM_VERIFIED]` Internal engine parameters controlling probe delays, packet timeouts, and retransmission backoffs. This does NOT constitute an application-level rate limit.
2. **Platform Request Rate (e.g., `rate_limit_rps: 5`):** `[DESIGN_DECISION]` Platform-enforced ceiling restricting the maximum number of network requests dispatched per second.
3. **Assessment Rate Budget:** `[DESIGN_DECISION]` Total network throughput allocated to a single scan job across all concurrent engines.
4. **Organization Rate Budget:** `[DESIGN_DECISION]` Global throughput limit across all active assessments within a tenant organization.
5. **Network Safety Ceiling:** `[DESIGN_DECISION]` Maximum concurrent connections (e.g. max 10 sockets) opened against any single destination IP/port.

---

## 3. Generic Tool Contract Schema (41-Point Specification Model)

Every supported tool integration is defined across 41 standardized fields with explicit operational classifications (`[REPOSITORY_VERIFIED]`, `[UPSTREAM_VERIFIED]`, `[CYBERASSESS_REQUIRED]`, `[DESIGN_DECISION]`, `[UNVERIFIED]`):

```text
ToolDefinition
  ├── 1. Identity
  ├── 2. Security Purpose
  ├── 3. Role (PRIMARY | VALIDATION | SPECIALIZED | FALLBACK)
  ├── 4. Security Classification (PASSIVE | ACTIVE_READ_ONLY | ACTIVE_INTRUSIVE | etc.)
  ├── 5. Supported CyberAssess Profiles
  ├── 6. Supported Target Types
  ├── 7. Upstream Version Policy (Exact Pinned Tag & Version Enforcement)
  ├── 8. Artifact / Installation Method & Supply-Chain Trust Mode
  ├── 9. Supply-Chain Integrity & Provenance (SHA-256 / Attestation)
  ├── 10. Required Permissions & Privileges
  ├── 11. Credential Requirements & Injection Method
  ├── 12. Workspace Requirements & Confinement
  ├── 13. Network Requirements & Destination Binding Mechanism
  ├── 14. Safety Policy & Scope-Specific Script Policy
  ├── 15. Rate Limit vs Timing Profile (Platform Rate vs Engine Timing)
  ├── 16. Concurrency Policy
  ├── 17. Timeout Policy
  ├── 18. Resource Limits
  ├── 19. Invocation Contract (Exact Command Line)
  ├── 20. Allowed Arguments
  ├── 21. Forbidden Arguments
  ├── 22. Input Schema
  ├── 23. Output Format
  ├── 24. Output Schema & Error Handling (Missing fields, malformed data)
  ├── 25. Exit Code Semantics (Upstream Exit Code vs CyberAssess Execution State)
  ├── 26. Failure Semantics & Coverage Impact
  ├── 27. Fallback Coverage Level & Coverage Loss
  ├── 28. Cancellation Protocol
  ├── 29. Cleanup Policy
  ├── 30. Parser Specification
  ├── 31. Finding Normalization
  ├── 32. Severity Mapping
  ├── 33. Taxonomy Mapping (CWE / OWASP / ASVS / NIST)
  ├── 34. Evidence Mapping & Cryptographic Hashing
  ├── 35. Secret Handling & Masking
  ├── 36. Correlation Strategy
  ├── 37. Validation Role
  ├── 38. Reproducibility Record
  ├── 39. Update & Upgrade Policy
  ├── 40. Deprecation Policy
  └── 41. Required Tests & Verification Status
```

---

# Part II: Tool Implementation Specifications (All 21 Tools)

## TOOL 01: Nmap

### 1. Identity
- **Tool ID:** `TOOL-NMAP`
- **Display Name:** Nmap (Network Mapper)
- **Upstream Project:** Insecure.Org (https://nmap.org)
- **Security Domain:** Network Perimeter & EASM
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/nmap_adapter.py`) & `[UPSTREAM_VERIFIED]` (Nmap Reference Guide)

### 2. Security Purpose
- **Problem Solved:** Discovers open TCP/UDP network ports, fingerprints listening services and versions, detects legacy operating systems, and identifies exposed administrative/database services on perimeter assets.
- **What It Detects:** Open network ports, service banners, SSL/TLS certificates on non-standard ports, basic script indicators (`http-title`, `ssl-cert`).
- **What It Does NOT Detect:** Deep web application logic flaws, authenticated API vulnerabilities, source code secrets.
- **Why Present:** Industry standard for reliable, low-overhead port scanning and banner identification.

### 3. Role
- **Classification:** `PRIMARY` network port scanner.
- **Overlap Strategy:** Complemented by `sslyze` (for deep TLS ciphers) and `httpx` (for web service probing).

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `ACTIVE_INTRUSIVE` when `-sC` or custom scripts are executed; `ACTIVE_READ_ONLY` when running `-sV` version probe only.
- `[CYBERASSESS_REQUIRED]` Classified as `ACTIVE_SERVICE_DISCOVERY` for standard `-sV` port sweeps; classified as `ACTIVE_INTRUSIVE` when executing NSE default scripts. Requires explicit 3-tier authorization before execution.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`: `[CYBERASSESS_REQUIRED]` ALLOWED (Full port sweep)
- `QUICK`: `[CYBERASSESS_REQUIRED]` ALLOWED (Top 100 ports)
- `NETWORK_ONLY`: `[CYBERASSESS_REQUIRED]` ALLOWED (Primary engine)
- `DAST_ONLY`: `[CYBERASSESS_REQUIRED]` DENIED (Web application focus only)
- `SAST_ONLY`: `[CYBERASSESS_REQUIRED]` DENIED (Filesystem code focus only)

### 6. Supported Target Types
- `IP`: `[REPOSITORY_VERIFIED]` Supported (IPv4, IPv6)
- `DOMAIN`: `[REPOSITORY_VERIFIED]` Supported (Resolved via Target Security Gateway)
- `URL`: `[REPOSITORY_VERIFIED]` Supported (Hostname extracted prior to invocation)
- `LOCAL_PATH`: `[CYBERASSESS_REQUIRED]` PROHIBITED

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Pinned to Nmap `7.95` (Exact Release).
- **Version Enforcement:** `[CYBERASSESS_REQUIRED]` Runtime probe checks `actual_version == "Nmap 7.95"`. Discrepancies fail closed with `INVALID_VERSION`.
- **Version Detection:** `[REPOSITORY_VERIFIED]` `nmap --version` -> Regex `Nmap version\s+([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `PACKAGE_MANAGER_MODE` (System binary installed via WinGet / apt / yum / brew) or managed binary in `backend/bin/nmap.exe`.
- **Resolver Path:** Tier 1: `config.adapters.nmap_path`, Tier 2: `backend/bin/nmap.exe`, Tier 4: `shutil.which("nmap")`, Tier 5: Windows `C:\Program Files (x86)\Nmap\nmap.exe`.

### 9. Supply-Chain Integrity & Provenance
- **Version Verification:** `[REPOSITORY_VERIFIED]` `nmap --version` runtime probe.
- **Artifact Integrity (SHA-256):** `[CYBERASSESS_REQUIRED]` `PACKAGE_MANAGER_MODE` delegates binary verification to the OS package manager trust boundary. Raw release archive digest is `[UNVERIFIED (Package Manager Delegated)]`.
- **Provenance / Attestation:** `[UPSTREAM_VERIFIED]` Insecure.Org GPG signing key (`43D0F654`).
- **Resolution Source:** `[CYBERASSESS_REQUIRED]` Authenticated system package manager or verified local binary directory.

### 10. Required Permissions & Privileges
- `[UPSTREAM_VERIFIED]` Unprivileged TCP connect scanning (`-sT` mode via standard user socket). Root/Administrator raw socket privileges (`-sS` SYN stealth) are strictly PROHIBITED in automated background scans to prevent privilege escalation risks.

### 11. Credential Requirements & Injection Method
- `NOT APPLICABLE` (Unauthenticated network probing).

### 12. Workspace Requirements & Confinement
- `NOT APPLICABLE` (Network operations only; no filesystem artifacts stored outside temporary stdout pipe).

### 13. Network Requirements & Destination Binding Mechanism
- **Destination Binding Mechanism:** `[CYBERASSESS_REQUIRED]` The adapter invokes Nmap targeting `ValidatedTarget.selected_destination` (the pre-resolved IP address). When testing HTTP/TLS services via scripts, the adapter injects `--script-args http.host=<canonical_value>`, ensuring all socket connections target the verified IP while preserving hostname contexts. Egress to private/loopback subnets is blocked unless explicit `scan:internal` scope is verified.

### 14. Safety Policy & Scope-Specific Script Policy
- **Approved Script Allowlist:** `[CYBERASSESS_REQUIRED]` In automated scans, script execution is strictly restricted to the explicit allowlist:
  - `banner`: Permitted on all target types (`IP`, `DOMAIN`, `URL`).
  - `ssl-cert`: Permitted on all target types with TLS services.
  - `http-title`: Permitted on all target types with HTTP/HTTPS services.
  - `ssh2-enum-algos`: Permitted on all target types with SSH services.
  - `dns-nsec-enum`: `[CYBERASSESS_REQUIRED]` Permitted ONLY on `DOMAIN` target types with explicit DNS zone assessment authorization; strictly FORBIDDEN on raw `IP` targets.
- **Forbidden Script Categories:** Exploitative or intrusive script categories (`exploit`, `dos`, `fuzzer`, `intrusive`, `brute`) are strictly FORBIDDEN.

### 15. Rate Limit vs Timing Profile
- **Tool Timing Profile:** `[UPSTREAM_VERIFIED]` `-T4` (Aggressive timing template: 500ms max RTT timeout, 10ms initial probe delay, 1.25s max scan delay).
- **Platform Request Rate:** `[DESIGN_DECISION]` Capped by platform rate governor (`rate_limit_rps: 5` default).
- **Network Safety Ceiling:** `[DESIGN_DECISION]` Max 100 concurrent port probe sockets per destination IP.

### 16. Concurrency Policy
- `[REPOSITORY_VERIFIED]` Single subprocess instance per scan job; internal probe parallelism managed by Nmap engine.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup timeout: 5.0s. Execution timeout: 60.0s (or `min(60.0, config.timeout_seconds * 6)`).

### 18. Resource Limits
- `[DESIGN_DECISION]` Max stdout buffer: 10 MB. Max memory: 256 MB.

### 19. Invocation Contract
```text
Executable: <resolved_nmap_path>
Command Line: nmap -sV -sC --version-light -T4 -oX - [-p <port_list>] <validated_target_ip>
Working Directory: Server-derived temporary execution directory
Stdin: Closed
Stdout: Captures XML output for stream parsing
Stderr: Captures runtime diagnostics and errors
```

### 20. Allowed Arguments
- `-sV`, `-sC`, `--version-light`, `-T4`, `-oX -`, `-p <port_list>`, `<validated_target_ip>`, `--script-args http.host=<canonical_value>`.

### 21. Forbidden Arguments
- `--script exploit`, `--script dos`, `--script fuzzer`, `--script intrusive`, `--interactive`, `--privileged`, `--system-commands`, `-oN <path>`, `-iL <path>`.

### 22. Input Schema
- Validated target IP string extracted via `ValidatedTarget.selected_destination`.

### 23. Output Format
- Standard Nmap XML (`-oX -`) emitted to stdout.

### 24. Output Schema & Error Handling
- **Valid Schema:** Root `<nmaprun>` containing child `<host><ports><port>` elements.
- **Missing Fields:** If `<service>` tag is omitted, service defaults to `"unknown"`. If `<state>` is missing, port is skipped.
- **Malformed XML:** If `xml.etree.ElementTree.ParseError` occurs, the adapter logs `PARSER_ERROR`, discards partial bytes, and activates native fallback.
- **Unexpected Structures:** Unknown XML tags are safely ignored without throwing unhandled exceptions.

### 25. Exit Code Semantics
- **Upstream Exit Codes:**
  - `0`: Process completed normally.
  - `1`: Invalid command-line arguments.
  - `2` / `Non-zero`: Fatal execution error, permission failure, or network route unreachable.
- **CyberAssess Normalized Execution States:**
  - If exit code is `0` and parseable ports found -> `COMPLETED_WITH_FINDINGS`
  - If exit code is `0` and no open ports found -> `COMPLETED_NO_FINDINGS`
  - If exit code is non-zero but partial XML parsed -> `PARTIAL_RESULTS_WITH_WARNING`
  - If exit code is non-zero and no XML parsed -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- `[CYBERASSESS_REQUIRED]` Missing binary, non-zero fatal exit, or timeout triggers `COVERAGE_DEGRADED` status. The failed tool event (`tool_failed`) is permanently recorded, and the orchestrator seamlessly activates the native port checker.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native Python `asyncio` TCP socket port checker & banner grabber.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native fallback tests configured top ports and extracts plain text banners, but lacks Nmap's comprehensive OS fingerprinting database, complex protocol probes (e.g. SMB, RPC, RDP negotiation), and NSE script execution.

### 28. Cancellation Protocol
- Managed by `ProcessSupervisor`. Sends `SIGTERM` / `taskkill /F /T /PID <pid>` to terminate the entire process tree recursively.

### 29. Cleanup Policy
- No persistent output files written to disk (`-oX -` uses memory stream). Temporary process descriptors closed upon exit.

### 30. Parser Specification
- **Engine:** `[REPOSITORY_VERIFIED]` Python `xml.etree.ElementTree`.
- **Extraction:** Iterates `.findall(".//ports/port")`, extracts `portid`, `protocol`, `state`, `service.name`, `service.product`, `service.version`, `script.output`.

### 31. Finding Normalization
- Exposed Database Port (3306, 5432, 27017, 6379): Check ID `NET-PORT-001`, Severity `HIGH`, CVSS 7.5, CWE-284.
- Exposed Admin Management Port (22, 3389, 23, 21): Check ID `NET-PORT-002`, Severity `MEDIUM`, CVSS 5.3, CWE-284.
- Discovered Active Service: Check ID `NET-SVC-001`, Severity `INFO`, CVSS 0.0, CWE-200.

### 32. Severity Mapping
- Database Exposure -> `Severity.HIGH` (7.5)
- Management Port Exposure -> `Severity.MEDIUM` (5.3)
- Generic Open Port -> `Severity.INFO` (0.0)

### 33. Taxonomy Mapping
- `CWE-284`: Improper Access Control
- `CWE-200`: Exposure of Sensitive Information
- `OWASP A05:2021`: Security Misconfiguration
- `NIST SP 800-53`: `AC-17` (Remote Access), `CM-7` (Least Functionality)

### 34. Evidence Mapping & Cryptographic Hashing
- `observed_value`: Port number, protocol, service product, version string.
- `script_output`: Formatted text of script responses (`ssl-cert`, `http-title`).
- `evidence_hash`: SHA-256 digest of `f"{selected_destination}:{port}:{service_name}:{version}"`.

### 35. Secret Handling & Masking
- Sanitizes banner strings for any embedded credentials or private tokens before persistence.

### 36. Correlation Strategy
- Correlates with native `port_checker` and `banner_grabber` findings using `(selected_destination, port, protocol)` tuple.

### 37. Validation Role
- `PRIMARY` network discovery authority.

### 38. Reproducibility Record
- Records Nmap version, execution timestamp, port arguments, target IP, and XML evidence hash.

### 39. Update & Upgrade Policy
- Managed via package manager updates with regression validation in `tests/test_adapters.py`.

### 40. Deprecation Policy
- Core foundational tool; not scheduled for deprecation.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestNmapAdapter` passing.
- **Capability Taxonomy:**
  - Port Scanning: `SUPPORTED`
  - Banner Grabbing: `SUPPORTED`
  - Approved NSE Scripts: `SUPPORTED`
  - OS Fingerprinting (Raw Sockets): `NOT_SUPPORTED` (Requires root privileges)
  - Intrusive Exploit Scripts: `NOT_SUPPORTED` (Safety policy violation)
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/nmap_adapter.py`); approved managed `7.95` runtime execution is `UNAVAILABLE` because the host reports `7.991`.

---

## TOOL 02: SSLyze

### 1. Identity
- **Tool ID:** `TOOL-SSLYZE`
- **Display Name:** SSLyze
- **Upstream Project:** Nabla C0d3 (https://github.com/nabla-c0d3/sslyze)
- **Security Domain:** Network Perimeter & TLS
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/sslyze_adapter.py`) & `[UPSTREAM_VERIFIED]`

### 2. Security Purpose
- **Problem Solved:** Fast and comprehensive TLS/SSL configuration analysis to identify broken protocols, deprecated ciphers, and certificate validation flaws.
- **What It Detects:** SSLv2, SSLv3, TLS 1.0, TLS 1.1 enablement, weak ciphers (RC4, 3DES, EXPORT, NULL, CBC mode vulnerabilities), expired/untrusted certificates, missing OCSP stapling.
- **What It Does NOT Detect:** Web application injection bugs, operating system vulnerabilities.
- **Why Present:** Authoritative engine for complete cryptographic protocol compliance (NIST SP 800-52r2 / ASVS 5.0 V9).

### 3. Role
- **Classification:** `PRIMARY` TLS security analysis engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `ACTIVE_READ_ONLY`. Initiates standard non-destructive TLS handshakes.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`: `[CYBERASSESS_REQUIRED]` ALLOWED
- `NETWORK_ONLY`: `[CYBERASSESS_REQUIRED]` ALLOWED
- `DAST_ONLY`: `[CYBERASSESS_REQUIRED]` ALLOWED
- `QUICK`: `[CYBERASSESS_REQUIRED]` ALLOWED
- `SAST_ONLY`: `[CYBERASSESS_REQUIRED]` DENIED

### 6. Supported Target Types
- `URL`: `[REPOSITORY_VERIFIED]` Supported (Hostname & port extracted)
- `DOMAIN`: `[REPOSITORY_VERIFIED]` Supported
- `IP`: `[REPOSITORY_VERIFIED]` Supported

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` SSLyze `5.2.0` (Exact PyPI Release - September 2023).
- **Runtime Compatibility Matrix:**
  - Python: 3.8 to 3.12 (Supported runtime environment; Python 3.13 / OpenSSL 3.0+ TLS renegotiation/cryptography bindings must be evaluated in isolated venv).
  - OpenSSL: OpenSSL 1.1.1 or OpenSSL 3.0 compatible bindings.
  - OS Platform: Linux / POSIX container / Windows.
- **Version Enforcement:** Runtime probe checks `actual_version == "sslyze 5.2.0"`.
- **Version Detection:** `[REPOSITORY_VERIFIED]` `sslyze --version` -> Regex `([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `PACKAGE_MANAGER_MODE` (Installed via `pip` into isolated virtualenv with hash-checking mode `--require-hashes`).

### 9. Supply-Chain Integrity & Provenance
- **Version Verification:** `[REPOSITORY_VERIFIED]` Checked via `importlib.metadata.version("sslyze")`.
- **Authoritative Artifact Integrity (SHA-256):** `[CYBERASSESS_REQUIRED]`
  - Source tarball (`sslyze-5.2.0.tar.gz`): `15ecb471b251dfbd003ba81a57d36865a93f18b74c7e7883a00d8bbddd365e03` (Size: 968,952 bytes; authoritative PyPI release artifact).
  - Wheel artifact: `NOT_APPLICABLE` (SSLyze 5.2.0 release on PyPI is distributed exclusively as an sdist tarball).
- **Provenance / Attestation:**
  - Attestation Status: `NOT_AVAILABLE` (Legacy upload via Twine 4.0.2 / CPython 3.8.10 on 2023-09-24 without PEP 740 attestations).
  - Provenance Enforcement: Cryptographic SHA-256 pinning against authoritative PyPI TLS distribution channel.
- **Resolution Source:** `[CYBERASSESS_REQUIRED]` Authoritative PyPI repository over TLS.

### 10. Required Permissions & Privileges
- Unprivileged user socket access.

### 11. Credential Requirements & Injection Method
- `NOT APPLICABLE`

### 12. Workspace Requirements & Confinement
- `NOT APPLICABLE`

### 13. Network Requirements & Destination Binding Mechanism
- **Destination Binding Mechanism:** `[CYBERASSESS_REQUIRED]` Invoked targeting `<selected_destination>:<port>` with `--sni=<canonical_value>` (SNI), ensuring the socket connects directly to the pre-resolved IP while passing canonical hostname to the TLS Server Name Indication extension.

### 14. Safety Policy & Bounded Probing
- Safe, non-destructive TLS handshakes and capability-segmented probes.

### 15. Rate Limit vs Timing Profile
- **Tool Timing Profile:** Internal handshake timeout (5s per probe).
- **Platform Request Rate:** `[DESIGN_DECISION]` Bounded to 5 concurrent handshake probes per host.
- **Network Safety Ceiling:** `[DESIGN_DECISION]` Max 5 simultaneous TLS sockets.

### 16. Concurrency Policy
- Managed via internal thread pool; capped at 1 subprocess/thread per scan job.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup timeout: 5.0s. Execution timeout: 45.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 256 MB.

### 19. Invocation Contract
```text
Executable: <resolved_python_path> -m sslyze
Command Line: sslyze --json_out=- <target_host>:<target_port> --sni=<canonical_hostname> [<config_flags>]
Stdout: Captures JSON results stream
Stderr: Diagnostic logs
```

### 20. Allowed Arguments & Capability Segmentation
- **Baseline Configuration Assessment Flags (Default Least-Privilege):** `--json_out=-`, `<target_host>:<target_port>`, `--sni=<name>`, `--sni`, `--certinfo`, `--sslv2`, `--sslv3`, `--tlsv1`, `--tlsv1_1`, `--tlsv1_2`, `--tlsv1_3`, `--reneg`, `--resum`, `--early_data`.
- **Targeted Vulnerability Probing Flags (Profile / Explicit Override Only):** `--heartbleed`, `--robot`, `--openssl_ccs`.
- **Least-Privilege Policy:** Default baseline TLS sweeps execute exclusively Configuration Assessment modules. Vulnerability probing flags require explicit authorization (`FULL_STACK` or configuration request).

### 21. Forbidden Arguments
- Arbitrary file write flags (`--json_out=<path>`).

### 22. Input Schema
- `<target_host>:<target_port>` derived from `ValidatedTarget`.

### 23. Output Format
- JSON structure parsed from stdout.

### 24. Output Schema & Error Handling
- **Valid Schema:** `server_scan_results[].scan_result` JSON object.
- **Missing Fields:** If a protocol section is absent, it is marked as `UNSUPPORTED`.
- **Malformed JSON:** Emits `PARSER_ERROR` and triggers native TLS fallback.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (Success), `Non-zero` (Connection refused or TLS error).
- **CyberAssess Normalized Execution States:**
  - Exit `0` with valid findings -> `COMPLETED_WITH_FINDINGS`
  - Exit `0` with clean TLS profile -> `COMPLETED_NO_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and permanently logs `tool_failed` event before activating native TLS fallback.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native Python `ssl.SSLContext` protocol sweeper.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native fallback tests TLS 1.0/1.1/1.2/1.3 and basic cert expiry, but lacks SSLyze's granular cipher suite enumeration (e.g. CBC, export, 3DES ciphers) and deep certificate chain validation.

### 28. Cancellation Protocol
- Standard process group termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- In-memory stream processing; no disk artifacts retained.

### 30. Parser Specification
- Extracts `ssl_2_0_cipher_suites`, `ssl_3_0_cipher_suites`, `tls_1_0_cipher_suites`, `tls_1_1_cipher_suites`, `certificate_deployments`.

### 31. Finding Normalization
- Deprecated Protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1): Check ID `NET-TLS-001`, Severity `HIGH`, CVSS 7.5, CWE-326.
- Weak Ciphers (RC4, 3DES, NULL): Check ID `NET-TLS-002`, Severity `MEDIUM`, CVSS 5.9, CWE-327.
- Expired/Untrusted Certificate: Check ID `NET-TLS-003`, Severity `HIGH`, CVSS 7.5, CWE-295.

### 32. Severity Mapping
- Deprecated TLS 1.0/1.1 -> `Severity.HIGH`
- Weak Ciphers -> `Severity.MEDIUM`
- Certificate Expired -> `Severity.HIGH`

### 33. Taxonomy Mapping
- `CWE-326`, `CWE-327`, `CWE-295`, `ASVS 5.0 v5.0.0-V9.1.1`, `NIST SP 800-53 SC-8, SC-13`.

### 34. Evidence Mapping & Cryptographic Hashing
- Observed cipher suite lists, protocol names, certificate expiry timestamps, and SHA-256 evidence hash.

### 35. Secret Handling & Masking
- Redacts private keys if accidentally returned in server certificate fields.

### 36. Correlation Strategy
- Correlates with native `tls_auditor` findings.

### 37. Validation Role
- `PRIMARY` TLS cryptographic authority.

### 38. Reproducibility Record
- Records SSLyze version, TLS endpoints scanned, and JSON result hash.

### 39. Update & Upgrade Policy
- Managed via `pip` package upgrades in locked environment.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestSslyzeAdapter` passing.
- **Capability Taxonomy:**
  - Protocol Sweeping (SSLv2–TLS 1.3): `SUPPORTED`
  - Cipher Suite Enumeration: `SUPPORTED`
  - Certificate Chain Trust: `SUPPORTED`
  - Early Data (0-RTT) Probing: `DEFERRED`
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/sslyze_adapter.py`); approved managed `5.2.0` runtime execution is `UNAVAILABLE` because the host reports `6.3.1`.

---

## TOOL 03: Subfinder

### 1. Identity
- **Tool ID:** `TOOL-SUBFINDER`
- **Display Name:** Subfinder
- **Upstream Project:** ProjectDiscovery (https://github.com/projectdiscovery/subfinder)
- **Security Domain:** Perimeter / EASM
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/subfinder_adapter.py`) & `[UPSTREAM_VERIFIED]`

### 2. Security Purpose
- **Problem Solved:** Fast passive subdomain enumeration using Certificate Transparency logs, search engines, and passive DNS datasets without sending traffic to the target.
- **What It Detects:** Valid organizational subdomains, forgotten staging environments, legacy domains.
- **What It Does NOT Detect:** Active service vulnerabilities, application logic bugs.
- **Why Present:** Essential reconnaissance engine for establishing total attack surface breadth.

### 3. Role
- **Classification:** `PRIMARY` passive reconnaissance tool.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `PASSIVE`. Queries third-party passive aggregators only; zero direct network connection to target domain.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`: `[CYBERASSESS_REQUIRED]` ALLOWED
- `NETWORK_ONLY`: `[CYBERASSESS_REQUIRED]` ALLOWED
- `PASSIVE_OSINT`: `[CYBERASSESS_REQUIRED]` ALLOWED
- `DAST_ONLY`: `[CYBERASSESS_REQUIRED]` ALLOWED only as a passive prerequisite when `include_subdomains=True`; discoveries do not become DAST targets automatically.
- `SAST_ONLY`: `[CYBERASSESS_REQUIRED]` DENIED

### 6. Supported Target Types
- `DOMAIN`: Supported
- `URL`: Supported (Apex domain extracted)
- `IP`: PROHIBITED

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Subfinder `v2.6.5` (Exact GitHub Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "subfinder v2.6.5"`.
- **Version Detection:** `[REPOSITORY_VERIFIED]` `subfinder -version` -> boundary-aware exact semantic-version parsing; substring versions such as `v2.6.50` are rejected.

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `DIRECT_ARTIFACT_MODE` (Standalone binary downloaded via `github_release_installer.py`).

### 9. Supply-Chain Integrity & Provenance
- **Version Verification:** `[REPOSITORY_VERIFIED]` Runtime probe.
- **Artifact Integrity (SHA-256):** `[REPOSITORY_VERIFIED]` Verified in `PINNED_TOOL_MANIFEST`:
  - `windows_amd64`: `382a5c54ec5a7cfeb60ad4fae3c321fa4ba5b6028a05c6ea4d49a751682ea576`
  - `linux_amd64`: `5ea58ceea06ea64e5aa06b12f68bc7aa3f63e6396da197825d19ec6ad06b2e3e`
- **Provenance / Attestation:** `[UPSTREAM_VERIFIED]` ProjectDiscovery GitHub Release Attestation.
- **Resolution Source:** `[CYBERASSESS_REQUIRED]` Official GitHub releases over HTTPS.

### 9.1 Runtime Executable Trust Boundary
- **Enterprise-assured mode:** Only a CyberAssess-managed installation may execute as an assured Subfinder tool. The installation record must bind `TOOL-SUBFINDER`, approved version, release artifact filename and archive SHA-256, executable relative path and executable SHA-256, platform, architecture, installer version, installation timestamp, and a valid trust state.
- **Runtime authorization:** Immediately before process creation, the resolver must verify that the resolved path is the managed executable, that its current SHA-256 matches the installation record, and that its reported version matches `v2.6.5`. Missing records, path changes, hash mismatches, version mismatches, missing files, and invalid trust states fail closed.
- **Non-assured mode:** Custom, PATH, Python-environment, package-manager, or otherwise unmanaged binaries may be detected for diagnostics where permitted, but must not satisfy the enterprise-assured Subfinder execution contract.
- **Evidence distinction:** `ARCHIVE_INTEGRITY_VERIFIED`, `EXECUTABLE_INTEGRITY_VERIFIED`, and `UPSTREAM_PROVENANCE_VERIFIED` are separate evidence claims and must not be collapsed into a generic trusted boolean.
- **TOCTOU control:** Verification must occur as close as practical to process creation; a startup-only hash check is insufficient.

### 10. Required Permissions & Privileges
- Unprivileged user network access.

### 11. Credential Requirements & Injection Method
- Baseline integration uses public `crtsh` only and accepts no provider credentials. Credentialed providers are disabled until tenant-scoped secret injection and provider-egress policy are implemented.

### 12. Workspace Requirements & Confinement
- `NOT APPLICABLE`

### 13. Network Requirements & Destination Binding Mechanism
- **Destination Binding Mechanism:** Outbound HTTPS access to public passive API endpoints, governed by provider-egress policy when enabled. The adapter performs no DNS queries or direct traffic to target hosts.

### 14. Safety Policy & Bounded Probing
- 100% passive; zero active network interaction with target servers.

### 15. Rate Limit vs Timing Profile
- Bounded to upstream provider limits.

### 16. Concurrency Policy
- Single process per scan job.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 256 MB. Max stdout: 10 MB.

### 19. Invocation Contract
```text
Executable: <resolved_subfinder_path>
Command Line: subfinder -d <authorized_root> -s crtsh -silent -json -timeout 10 -max-time 1
Stdout: Captures JSON Lines stream
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- Server-generated `-d <authorized_root>`, `-s crtsh`, `-silent`, `-json`, `-timeout 10`, and `-max-time 1`. Only the public `crtsh` source is enabled by the baseline policy; client-supplied providers, credentials, resolvers, active mode, paths, and extra arguments are prohibited.

### 21. Forbidden Arguments
- Arbitrary file write (`-o <path>`), execution wrappers.

### 22. Input Schema
- Validated root domain string (`example.com`).

### 23. Output Format
- Line-delimited JSON (JSON Lines).

### 24. Output Schema & Error Handling
- **Valid Schema:** `{"host": "sub.example.com", "input": "example.com", "sources": [...]}`.
- **Missing Fields:** If `sources` is missing, defaults to `["unknown"]`.
- **Malformed Lines:** Unparseable lines are skipped and recorded in `PARSER_WARNING` logs.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (Success), `Non-zero` (Fatal error).
- **CyberAssess Normalized Execution States:**
  - Exit `0` with subdomains discovered -> `COMPLETED_WITH_FINDINGS`
  - Exit `0` with no subdomains discovered -> `COMPLETED_NO_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and records the failed Subfinder state. The later native Certificate Transparency component is an independent enrichment path, not a claim that Subfinder fallback executed.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native `crt.sh` client.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native client queries `crt.sh` exclusively; lacks Subfinder's 30+ multi-source passive aggregators.

### 28. Cancellation Protocol
- Immediate process tree termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Process termination cleans up all temporary memory descriptors.

### 30. Parser Specification
- Parses JSON Lines, normalizes and scope-classifies `host`, and constructs an untrusted `DiscoveredSubdomain` observation with `dns_status=UNRESOLVED`. DNS resolution requires a separate authorized stage.

### 31. Finding Normalization
- Populates `scan.discovered_subdomains` list and emits `NET-OSINT-001` informational findings.

### 32. Severity Mapping
- `Severity.INFO` (0.0 CVSS).

### 33. Taxonomy Mapping
- `CWE-200`, `OWASP A05:2021`, `NIST CM-8`.

### 34. Evidence Mapping & Cryptographic Hashing
- Canonical FQDN, source list, authorized root, scope classification, timestamp, and evidence hash. Active IP/CNAME data is outside this passive adapter.

### 35. Secret Handling & Masking
- Redacts any API tokens passed to external providers in debug logs.

### 36. Correlation Strategy
- Merged into unified attack surface inventory with native CT findings.

### 37. Validation Role
- Produces discovery observations/candidate assets only. It does not produce `ValidatedTarget` objects, authorize assets, admit inventory, or directly feed `httpx`/`katana`.

### 38. Reproducibility Record
- Records Subfinder version, query timestamp, domain seed, and discovered host count.

### 39. Update & Upgrade Policy
- Automated manifest bump with SHA-256 verification in `tool_manifest.py`.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestSubfinderAdapter` passing.
- **Capability Taxonomy:**
  - Passive CT Log Enumeration: `SUPPORTED`
  - Multi-Source Aggregator API Queries: `NOT_SUPPORTED` (Current governed baseline is public `crtsh` only; credentialed providers require a future tenant-scoped egress and secret-injection control)
  - Active DNS Brute-Forcing: `NOT_SUPPORTED` (Passive scope constraint)
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/subfinder_adapter.py`); approved managed `v2.6.5` runtime execution is `UNAVAILABLE` in the current environment.

---

## TOOL 04: httpx

### 1. Identity
- **Tool ID:** `TOOL-HTTPX`
- **Display Name:** httpx
- **Upstream Project:** ProjectDiscovery (https://github.com/projectdiscovery/httpx)
- **Security Domain:** HTTP Probing & Discovery
- **CyberAssess Role:** `VALIDATION`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/httpx_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Rapid multi-point HTTP service validation, technology stack identification, and status code verification across large lists of hosts.
- **What It Detects:** Live web servers, HTTP response status codes, page titles, web servers (Nginx, Apache, Cloudflare), web technologies, TLS SANs.
- **What It Does NOT Detect:** Deep DAST vulnerabilities (SQLi, XSS).
- **Why Present:** Bridges perimeter subdomain enumeration and active web crawling by validating live HTTP services at high speed.

### 3. Role
- **Classification:** `VALIDATION` engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `ACTIVE_READ_ONLY`. Sends standard HTTP GET/HEAD requests.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`, `NETWORK_ONLY`, `DAST_ONLY`, `QUICK`.

### 6. Supported Target Types
- `URL`, `DOMAIN`, `IP`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` httpx `v1.6.0` (Exact GitHub Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "httpx v1.6.0"`.
- **Version Detection:** `httpx -version` -> Regex `v?([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `DIRECT_ARTIFACT_MODE` (Standalone GitHub release binary downloaded via `github_release_installer.py`).

### 9. Supply-Chain Integrity & Provenance
- `windows_amd64`: `4a129d20c57c44db8fca539e0839f8f2b3ec48ee5f8e65fa1a4e9b9809930f76`
- `linux_amd64`: `9fa0cb78fe664bd9f0cb18a4d79a29e4eb589a19c72e2cf5ec9aeebbb85da570`
- Provenance: ProjectDiscovery GitHub Release Attestation.

### 10. Required Permissions & Privileges
- Unprivileged HTTP/HTTPS network access.

### 11. Credential Requirements & Injection Method
- `NOT APPLICABLE`

### 12. Workspace Requirements & Confinement
- `NOT APPLICABLE`

### 13. Network Requirements & Destination Binding Mechanism
- **Destination Binding Mechanism:** `[CYBERASSESS_REQUIRED]` Invoked targeting `http://<selected_destination>` with `-H "Host: <canonical_value>"` and `-sni <canonical_value>`, pinning outbound socket connections directly to the pre-resolved IP.

### 14. Safety Policy & Bounded Probing
- Enforces SSRF target validation; denies private CIDR sweeps.

### 15. Rate Limit vs Timing Profile
- `[DESIGN_DECISION]` Bounded to 20 requests/sec. Max 10 concurrent connections.

### 16. Concurrency Policy
- Capped at `-threads 10`.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 256 MB.

### 19. Invocation Contract
```text
Executable: <resolved_httpx_path>
Command Line: httpx -u http://<selected_destination> -H "Host: <canonical_value>" -sni <canonical_value> -silent -json -title -tech-detect -status-code
Stdout: Captures JSON Lines stream
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `-u <url>`, `-H <header>`, `-sni <sni>`, `-silent`, `-json`, `-title`, `-tech-detect`, `-status-code`, `-threads <int>`, `-timeout <int>`.

### 21. Forbidden Arguments
- Arbitrary file execution, raw unsanitized request files.

### 22. Input Schema
- Validated target URL derived from `ValidatedTarget`.

### 23. Output Format
- JSON Lines stream.

### 24. Output Schema & Error Handling
- **Valid Schema:** `url`, `status_code`, `title`, `technologies`, `webserver`, `host`, `port`.
- **Missing Fields:** `technologies` defaults to empty array; `title` defaults to empty string.
- **Malformed Lines:** Unparseable lines skipped with warning logs.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (Success), `Non-zero` (Network failure).
- **CyberAssess Normalized Execution States:**
  - Exit `0` with live web services -> `COMPLETED_WITH_FINDINGS`
  - Exit `0` with no HTTP responses -> `COMPLETED_NO_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native Python HTTP probe.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native Python `httpx` async library.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native probe captures status codes and basic headers, but lacks ProjectDiscovery's comprehensive Wappalyzer-based tech detection ruleset.

### 28. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Memory descriptors closed on exit.

### 30. Parser Specification
- Parses JSON Lines stream and enriches `DiscoveredEndpoint` models.

### 31. Finding Normalization
- Emits technology fingerprinting records and validates reachable HTTP endpoints.

### 32. Severity Mapping
- `Severity.INFO` (0.0 CVSS).

### 33. Taxonomy Mapping
- `CWE-200`, `OWASP A05:2021`, `NIST CM-8`.

### 34. Evidence Mapping & Cryptographic Hashing
- Response headers, title, detected technologies, status code, evidence hash.

### 35. Secret Handling & Masking
- Sanitizes cookies and Authorization headers in output.

### 36. Correlation Strategy
- Enriches endpoint inventory before DAST crawl execution.

### 37. Validation Role
- Confirms live web service reachability.

### 38. Reproducibility Record
- Records httpx version, input URLs, and technology match list.

### 39. Update & Upgrade Policy
- Pinned manifest updates.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestHttpxAdapter` passing.
- **Capability Taxonomy:**
  - HTTP Probe & Status: `SUPPORTED`
  - Technology Fingerprinting: `SUPPORTED`
  - Raw Request Fuzzing: `NOT_SUPPORTED` (Handled by FFuF)
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/httpx_adapter.py`); approved managed `v1.6.0` runtime execution is `UNAVAILABLE` in the current environment.

---

## TOOL 05: Nuclei

### 1. Identity
- **Tool ID:** `TOOL-NUCLEI`
- **Display Name:** Nuclei
- **Upstream Project:** ProjectDiscovery (https://github.com/projectdiscovery/nuclei)
- **Security Domain:** Web DAST & Vulnerability Assessment
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/nuclei_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Fast, deterministic template-driven vulnerability scanning for known CVEs, security misconfigurations, default credentials, and exposed sensitive panels.
- **What It Detects:** Known CVEs across web frameworks, unauthenticated admin portals, exposed `.env` files, git repositories, CORS misconfigurations, GraphQL introspection.
- **What It Does NOT Detect:** Complex business logic flaws requiring multi-step state machines.
- **Why Present:** Authoritative modern DAST scanner with community-driven, curated CVE templates.

### 3. Role
- **Classification:** `PRIMARY` DAST vulnerability scanner.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `ACTIVE_INTRUSIVE`. Dispatches active HTTP probes matching known CVE patterns.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`, `DAST_ONLY`, `QUICK`, `API_FOCUSED`.

### 6. Supported Target Types
- `URL`, `DOMAIN`, `IP`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Nuclei `v3.2.0` (Exact GitHub Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "nuclei v3.2.0"`.
- **Version Detection:** `nuclei -version` -> Regex `v?([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `DIRECT_ARTIFACT_MODE` (Standalone GitHub release binary downloaded via `github_release_installer.py`).

### 9. Supply-Chain Integrity & Provenance
- `windows_amd64`: `64d0a3ec74f63cbb2f97f740a6b98686fba7fa01f5c6adbc81c81ef4554b5ec9`
- `linux_amd64`: `e2c39e248b613c0efcfd1d575c3db6fb8260b43521b44ec5fdfdfc845ad35e80`
- Provenance: ProjectDiscovery GitHub Release Attestation.

### 10. Required Permissions & Privileges
- Unprivileged HTTP/HTTPS network access.

### 11. Credential Requirements & Injection Method
- External assured mode does not inject tenant credentials into CLI arguments; authenticated coverage is handled by the governed native HTTP session until secret-safe subprocess injection is implemented.

### 12. Workspace Requirements & Confinement
- `NOT APPLICABLE`

### 13. Network Requirements & Destination Binding Mechanism
- **Destination Binding Mechanism:** `[CYBERASSESS_REQUIRED]` Invoked with `nuclei -u http://<selected_destination> -H "Host: <canonical_value>" -sni <canonical_value>`, forcing direct IP connection.

### 14. Safety Policy & Bounded Probing
- Strict template classification: only non-destructive tags (`cve`, `misconfig`, `exposure`) are enabled. Destructive exploit or DoS templates are forbidden.

### 15. Rate Limit vs Timing Profile
- `[DESIGN_DECISION]` Bounded to 10 requests/sec (`-rate-limit 10`).

### 16. Concurrency Policy
- Capped at `-c 5`.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 90.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 512 MB. Max stdout: 10 MB.

### 19. Invocation Contract
```text
Executable: <resolved_nuclei_path>
Command Line: nuclei -u http://<selected_destination> -H "Host: <canonical_value>" -sni <canonical_value> -j -silent -tags cve,misconfig -severity low,medium,high,critical
Stdout: Captures JSON Lines stream
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `-u <url>`, `-j`, `-silent`, `-tags <tags>`, `-severity <severities>`, `-H <header>`, `-sni <sni>`, `-timeout <sec>`, `-rate-limit <rps>`.

### 21. Forbidden Arguments
- `-update-templates` (uncontrolled network pull in production), `-t <untrusted_local_path>`.

### 22. Input Schema
- Normalized target URL string (`http://` or `https://`).

### 23. Output Format
- Line-delimited JSON stream.

### 24. Output Schema & Error Handling
- **Valid Schema:** `template-id`, `info.name`, `info.severity`, `info.classification.cwe-id`, `info.classification.cvss-score`, `matched-at`, `curl-command`.
- **Missing Fields:** `cwe-id` defaults to inferred CWE; `cvss-score` defaults to severity base score.
- **Malformed Lines:** Skipped with `PARSER_WARNING` log.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (Success), `Non-zero` (Template error or network failure).
- **CyberAssess Normalized Execution States:**
  - Exit `0` with vulnerability findings -> `COMPLETED_WITH_FINDINGS`
  - Exit `0` with no vulnerabilities -> `COMPLETED_NO_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native DAST heuristic checks.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native Python DAST rules (`headers_cookies`, `cors_analyzer`, `parameter_fuzzer`).
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native DAST tests core headers, CORS, basic SQLi/XSS reflection, and exposed endpoints, but CANNOT reproduce Nuclei's 5,000+ specialized CVE templates.

### 28. Cancellation Protocol
- Immediate process tree termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Process termination cleans up all memory streams.

### 30. Parser Specification
- Parses JSON Lines stream, maps `template-id` to canonical check catalog, extracts `reproduction_curl`, and generates `Finding` models.

### 31. Finding Normalization
- Maps Nuclei findings to canonical check IDs (`DAST-INJ-001`, `DAST-XSS-001`, `DAST-EXP-001`, `DAST-CORS-001`, etc.).

### 32. Severity Mapping
- `critical` -> `Severity.CRITICAL` (9.8)
- `high` -> `Severity.HIGH` (7.5)
- `medium` -> `Severity.MEDIUM` (5.3)
- `low` -> `Severity.LOW` (3.1)
- `info` -> `Severity.INFO` (0.0)

### 33. Taxonomy Mapping
- Populates exact CWE ID from `info.classification.cwe-id`, maps to OWASP Top 10 (2021) and NIST SP 800-53 controls (`AC-3`, `SI-10`, `SC-8`).

### 34. Evidence Mapping & Cryptographic Hashing
- Matched URL, HTTP request/response snippets, reproduction curl command, and SHA-256 evidence digest.

### 35. Secret Handling & Masking
- Masks credentials in `reproduction_curl` and response bodies before persistence.

### 36. Correlation Strategy
- Clustered with native DAST findings on identical endpoints and check IDs.

### 37. Validation Role
- `PRIMARY` automated CVE discovery authority.

### 38. Reproducibility Record
- Records Nuclei version, template ID, matched URL, and evidence hash.

### 39. Update & Upgrade Policy
- Version and template manifest bumps with regression verification.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestNucleiAdapter` passing.
- **Capability Taxonomy:**
  - Curated CVE Scanning: `SUPPORTED`
  - Misconfiguration Detection: `SUPPORTED`
  - Custom Remote Templates: `DEFERRED`
- **Verification Status:** Repository controls verified; managed runtime execution is `UNAVAILABLE` in the current environment (`backend/app/adapters/nuclei_adapter.py`).

---

## TOOL 06: FFuF

### 1. Identity
- **Tool ID:** `TOOL-FFUF`
- **Display Name:** FFuF (Fuzz Faster U Fool)
- **Upstream Project:** FFuF (https://github.com/ffuf/ffuf)
- **Security Domain:** Web Fuzzing & Parameter Discovery
- **CyberAssess Role:** `SPECIALIZED`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/ffuf_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** High-speed fuzzing for hidden web routes, directories, URL query parameters, and HTTP headers.
- **What It Detects:** Unlinked administrative portals, hidden debug parameters, backup files (`.bak`, `.old`), unindexed API routes.
- **What It Does NOT Detect:** Static source code vulnerabilities, TLS cipher configuration.
- **Why Present:** High-performance Go fuzzer with advanced response filtering (size, words, lines).

### 3. Role
- **Classification:** `SPECIALIZED` parameter and directory discovery engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `ACTIVE_INTRUSIVE`. Dispatches high-volume HTTP fuzzing requests.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`, `DAST_ONLY`, `API_FOCUSED`.

### 6. Supported Target Types
- `URL`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` FFuF `v2.1.0` (Exact GitHub Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "ffuf v2.1.0"`.
- **Version Detection:** `ffuf -V` -> Regex `v?([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `DIRECT_ARTIFACT_MODE` (Standalone GitHub release binary downloaded via `github_release_installer.py`).

### 9. Supply-Chain Integrity & Provenance
- `windows_amd64`: `c62b66236b281bf77bb0b57e7eb3b7235a8bc33b28b58a1ee2e94625b597c5e2`
- `linux_amd64`: `426be0eb2a297e6be9ea83664746f34586db30188aa1d3824ee18c15668db8c0`

### 10. Required Permissions & Privileges
- Unprivileged HTTP/HTTPS network access.

### 11. Credential Requirements & Injection Method
- Tenant session cookies/auth headers are not passed to FFuF CLI arguments; authenticated coverage remains in the governed native session until secret-safe subprocess injection is implemented.

### 12. Workspace Requirements & Confinement
- Temporary wordlist files created in sandboxed temp directory.

### 13. Network Requirements & Destination Binding Mechanism
- **Destination Binding Mechanism:** `[CYBERASSESS_REQUIRED]` Invoked with `ffuf -u http://<selected_destination>/FUZZ -H "Host: <canonical_value>"`, pinning fuzzing requests directly to the pre-resolved IP.

### 14. Safety Policy & Bounded Probing
- Restrictive wordlists; exclusion patterns for logout and destructive actions (`*logout*`, `*delete*`, `*purge*`).

### 15. Rate Limit vs Timing Profile
- `[DESIGN_DECISION]` Bounded to `-rate 10` requests/sec. Max 5 concurrent worker threads.

### 16. Concurrency Policy
- Capped at `-t 5` threads.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 256 MB. Max stdout: 10 MB.

### 19. Invocation Contract
```text
Executable: <resolved_ffuf_path>
Command Line: ffuf -u http://<selected_destination>/FUZZ -H "Host: <canonical_value>" -w <wordlist_path> -mc 200,204,301,302,307,401,403 -o - -of json -t 5 -rate 10 -s
Stdout: Captures JSON output
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `-u <url>`, `-H <header>`, `-w <path>`, `-mc <codes>`, `-ms <size>`, `-fs <size>`, `-o -`, `-of json`, `-t <threads>`, `-rate <rps>`, `-s`.

### 21. Forbidden Arguments
- Non-standard HTTP methods (`-X DELETE`), arbitrary file writes.

### 22. Input Schema
- Validated target URL with `FUZZ` placeholder.

### 23. Output Format
- JSON output emitted to stdout.

### 24. Output Schema & Error Handling
- **Valid Schema:** `results[].url`, `results[].status`, `results[].length`, `results[].words`, `results[].input.FUZZ`.
- **Missing Fields:** Defaults to standard zero/empty representations.
- **Malformed JSON:** Emits `PARSER_ERROR` and falls back to native fuzzer.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (Success), `Non-zero` (Wordlist error or connectivity loss).
- **CyberAssess Normalized Execution States:**
  - Exit `0` with discovered routes -> `COMPLETED_WITH_FINDINGS`
  - Exit `0` with no discovered routes -> `COMPLETED_NO_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native parameter fuzzer.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native Python BFS crawler and parameter fuzzer.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native fuzzer tests standard top 50 common parameters; lacks FFuF's raw throughput and dynamic calibration.

### 28. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Temporary wordlist files deleted immediately upon execution completion.

### 30. Parser Specification
- Parses JSON results, extracts discovered paths/parameters, and constructs `DiscoveredEndpoint` models.

### 31. Finding Normalization
- Emits `DAST-EXP-001` (Exposed Administrative Endpoint) or `DAST-PARAM-001` (Hidden Parameter).

### 32. Severity Mapping
- Exposed Admin Route -> `Severity.MEDIUM` (5.3)
- Information Disclosure -> `Severity.LOW` (3.1)

### 33. Taxonomy Mapping
- `CWE-200`, `CWE-284`, `OWASP A01:2021`, `NIST AC-3`.

### 34. Evidence Mapping & Cryptographic Hashing
- Discovered URL, status code, response length, fuzz word, evidence hash.

### 35. Secret Handling & Masking
- Sanitizes request headers in stored evidence.

### 36. Correlation Strategy
- Feeds newly discovered endpoints into the live assessment dossier.

### 37. Validation Role
- `SPECIALIZED` fuzzing authority.

### 38. Reproducibility Record
- Records wordlist hash, target URL, and FFuF version.

### 39. Update & Upgrade Policy
- Manifest digest verification.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestFfufAdapter` passing.
- **Capability Taxonomy:**
  - Route / Directory Fuzzing: `SUPPORTED`
  - Query Parameter Fuzzing: `SUPPORTED`
  - Destructive Method Fuzzing (DELETE/PUT): `NOT_SUPPORTED`
- **Verification Status:** Repository controls verified; managed runtime execution is `UNAVAILABLE` in the current environment (`backend/app/adapters/ffuf_adapter.py`).

---

## TOOL 07: Katana

### 1. Identity
- **Tool ID:** `TOOL-KATANA`
- **Display Name:** Katana
- **Upstream Project:** ProjectDiscovery (https://github.com/projectdiscovery/katana)
- **Security Domain:** Web Crawling & Attack Surface Discovery
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/katana_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Next-generation web crawler supporting both standard HTTP DOM parsing and headless Chromium crawling for Single Page Applications (SPAs).
- **What It Detects:** Hyperlinks, API routes in JavaScript bundles, HTML forms, input parameters, endpoint trees.
- **What It Does NOT Detect:** Static source code vulnerabilities, network port status.
- **Why Present:** Deep crawling capabilities for modern JavaScript-heavy frontend applications.

### 3. Role
- **Classification:** `PRIMARY` web crawler.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `ACTIVE_READ_ONLY`. Traverses links and parses DOM structures.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`, `DAST_ONLY`, `QUICK`.

### 6. Supported Target Types
- `URL`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Katana `v1.0.5` (Exact GitHub Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "katana v1.0.5"`.
- **Version Detection:** `katana -version` -> Regex `v?([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `DIRECT_ARTIFACT_MODE` (Standalone GitHub release binary downloaded via `github_release_installer.py`).

### 9. Supply-Chain Integrity & Provenance
- `windows_amd64`: `806a6b574a44b94f1c713beeafe9be2bb53a5c6ca8858e999905f15d9715bf85`
- `linux_amd64`: `00f07bf266ce2da4a6c4c95f19069d5fb3fbffac4fe6d24f0cba160b73df7816`

### 10. Required Permissions & Privileges
- Unprivileged HTTP/HTTPS network access.

### 11. Credential Requirements & Injection Method
- Tenant cookies are not passed to Katana CLI arguments; authenticated coverage remains in the governed native session until secret-safe subprocess injection is implemented.

### 12. Workspace Requirements & Confinement
- `NOT APPLICABLE`

### 13. Network Requirements & Destination Binding Mechanism
- **Destination Binding Mechanism:** `[CYBERASSESS_REQUIRED]` Invoked with `katana -u http://<selected_destination> -H "Host: <canonical_value>"`, strictly binding crawling requests to the pre-resolved IP.

### 14. Safety Policy & Bounded Probing
- Depth capped at `-d 3`, maximum crawl limit enforced, out-of-scope domain traversal blocked.

### 15. Rate Limit vs Timing Profile
- `[DESIGN_DECISION]` Bounded to 10 requests/sec. Max 5 concurrent crawler workers.

### 16. Concurrency Policy
- Capped at `-c 5`.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 90.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 512 MB.

### 19. Invocation Contract
```text
Executable: <resolved_katana_path>
Command Line: katana -u http://<selected_destination> -H "Host: <canonical_value>" -silent -json -d 3 -jc
Stdout: Captures JSON Lines stream
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `-u <url>`, `-H <header>`, `-silent`, `-json`, `-d <depth>`, `-jc`, `-c <concurrency>`, `-ct <timeout>`.

### 21. Forbidden Arguments
- Unrestricted crawling without depth caps.

### 22. Input Schema
- Validated target URL string derived from `ValidatedTarget`.

### 23. Output Format
- JSON Lines stream.

### 24. Output Schema & Error Handling
- **Valid Schema:** `request.endpoint`, `request.method`, `request.tag`, `response.status_code`.
- **Missing Fields:** `tag` defaults to `"link"`.
- **Malformed Lines:** Skipped safely.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (Success), `Non-zero` (Browser crash or connectivity error).
- **CyberAssess Normalized Execution States:**
  - Exit `0` with crawled endpoints -> `COMPLETED_WITH_FINDINGS`
  - Exit `0` with no new links -> `COMPLETED_NO_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native Python crawler.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native Python BFS HTML crawler.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native crawler parses static HTML `<a>` and `<form>` tags, but cannot execute dynamic client-side JavaScript or extract routes from compiled SPA bundles.

### 28. Cancellation Protocol
- Process tree termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Memory descriptors closed on exit.

### 30. Parser Specification
- Parses JSON Lines stream, normalizes endpoints, and populates `DiscoveredEndpoint` models.

### 31. Finding Normalization
- Enriches endpoint inventory and records discovered forms and parameters.

### 32. Severity Mapping
- `Severity.INFO` (0.0 CVSS).

### 33. Taxonomy Mapping
- `CWE-200`, `OWASP A05:2021`, `NIST CM-8`.

### 34. Evidence Mapping & Cryptographic Hashing
- Endpoint URL, HTTP method, discovery tag, parent page URL, evidence hash.

### 35. Secret Handling & Masking
- Sanitizes request headers in stored records.

### 36. Correlation Strategy
- Feeds crawled endpoints directly into the assessment dossier.

### 37. Validation Role
- `PRIMARY` web endpoint discovery engine.

### 38. Reproducibility Record
- Records Katana version, crawl depth, and discovered endpoint count.

### 39. Update & Upgrade Policy
- Manifest digest updates.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestKatanaAdapter` passing.
- **Capability Taxonomy:**
  - Standard DOM Crawling: `SUPPORTED`
  - JavaScript Endpoint Extraction: `SUPPORTED`
  - Headless Browser Rendering: `LIMITED` (Requires system Chromium)
- **Verification Status:** Repository controls verified; managed runtime execution is `UNAVAILABLE` in the current environment (`backend/app/adapters/katana_adapter.py`).

---

## TOOL 08: Schemathesis

### 1. Identity
- **Tool ID:** `TOOL-SCHEMATHESIS`
- **Display Name:** Schemathesis
- **Upstream Project:** Schemathesis (https://github.com/schemathesis/schemathesis)
- **Security Domain:** API Contract Security & Fuzzing
- **CyberAssess Role:** `SPECIALIZED`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/schemathesis_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Property-based testing for OpenAPI, Swagger, and GraphQL APIs to detect server crashes (HTTP 500), schema violations, and input validation failures.
- **What It Detects:** Server-side unhandled exceptions (HTTP 500), missing input validation, boundary violations, status code mismatches.
- **What It Does NOT Detect:** Static source code vulnerabilities, network port exposure.
- **Why Present:** Enterprise API contract security and robust automated boundary fuzzing.

### 3. Role
- **Classification:** `SPECIALIZED` API testing engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `STATE_CHANGING` when fuzzing mutation methods (POST/PUT/PATCH/DELETE); `ACTIVE_INTRUSIVE` when executing property-based boundary checks.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`, `API_FOCUSED`, `DAST_ONLY`.

### 6. Supported Target Types
- `URL` (OpenAPI schema URL or base API URL).

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Schemathesis `3.20.0` (Exact PyPI Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "schemathesis 3.20.0"`.
- **Version Detection:** `schemathesis --version` -> Regex `([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `PACKAGE_MANAGER_MODE` (Installed via `pip_installer.py` in isolated venv).

### 9. Supply-Chain Integrity & Provenance
- PyPI package hashes in `requirements.txt` with PEP 740 verifiable provenance.

### 10. Required Permissions & Privileges
- Unprivileged HTTP/HTTPS network access.

### 11. Credential Requirements & Injection Method
- External Schemathesis execution does not receive tenant bearer tokens in CLI arguments; state-changing authenticated coverage requires a future secret-safe injection path and is fail-closed until then.

### 12. Workspace Requirements & Confinement
- `NOT APPLICABLE`

### 13. Network Requirements & Destination Binding Mechanism
- **Destination Binding Mechanism:** `[CYBERASSESS_REQUIRED]` Invoked with custom Python transport adapter binding direct socket connections to `ValidatedTarget.selected_destination` while passing original `Host` headers.

### 14. Safety Policy & Bounded Probing
- Read-only operations prioritized; state-changing endpoints strictly bounded.

### 15. Rate Limit vs Timing Profile
- `[DESIGN_DECISION]` Bounded to 10 requests/sec.

### 16. Concurrency Policy
- Single subprocess instance.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 512 MB.

### 19. Invocation Contract
```text
Executable: <resolved_python_path> -m schemathesis
Command Line: schemathesis run <openapi_url> --format=json --workers=1 --hypothesis-max-examples=10
Stdout: Captures JSON test runner report
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `run <schema_url>`, `--format=json`, `--workers=1`, `--hypothesis-max-examples=<int>`, `--header=<header>`.

### 21. Forbidden Arguments
- Unbounded example generation (`--hypothesis-max-examples=10000`).

### 22. Input Schema
- Validated OpenAPI / Swagger URL.

### 23. Output Format
- JSON report structure.

### 24. Output Schema & Error Handling
- **Valid Schema:** `errors`, `checks`, `interactions`.
- **Malformed Data:** Emits `PARSER_ERROR` and falls back to API inspector.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (Tests passed), `1` (Schema violations/crashes found), `Non-zero` (Fatal error).
- **CyberAssess Normalized Execution States:**
  - Exit `0` -> `COMPLETED_NO_FINDINGS`
  - Exit `1` -> `COMPLETED_WITH_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native API Inspector.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native Python API Inspector.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native inspector checks basic OpenAPI route reachability and auth headers, but lacks Schemathesis's Hypothesis-driven mathematical property generation and crash fuzzing.

### 28. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- In-memory processing; descriptors closed.

### 30. Parser Specification
- Parses JSON report, extracts HTTP 500 errors and schema failures, maps to `DAST-API-003`.

### 31. Finding Normalization
- Unhandled 500 Server Error: Check ID `DAST-API-003`, Severity `MEDIUM`, CVSS 5.3, CWE-754.

### 32. Severity Mapping
- Server 500 Crash -> `Severity.MEDIUM` (5.3)
- Schema Mismatch -> `Severity.LOW` (3.1)

### 33. Taxonomy Mapping
- `CWE-754`, `OWASP A05:2021`, `NIST SI-11`.

### 34. Evidence Mapping & Cryptographic Hashing
- Failing HTTP request body, response status, schema error message, evidence hash.

### 35. Secret Handling & Masking
- Masks auth tokens in request/response dumps.

### 36. Correlation Strategy
- Grouped with API Inspector endpoint findings.

### 37. Validation Role
- `SPECIALIZED` API robustness authority.

### 38. Reproducibility Record
- Records Schemathesis version, schema URL, seed, and failed test cases.

### 39. Update & Upgrade Policy
- Pip package lockfile management.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestSchemathesisAdapter` passing.
- **Capability Taxonomy:**
  - OpenAPI Schema Fuzzing: `SUPPORTED`
  - GraphQL Schema Fuzzing: `DEFERRED`
- **Verification Status:** Repository controls verified; managed runtime execution is `UNAVAILABLE` in the current environment (`backend/app/adapters/schemathesis_adapter.py`).
- **State-Changing Gate:** State-changing execution requires an API-focused profile and an explicit tenant authorization grant in the validated target context; absent either gate, the adapter records `EXECUTION_BLOCKED` and does not launch.

---

## TOOL 09: Semgrep

### 1. Identity
- **Tool ID:** `TOOL-SEMGREP`
- **Display Name:** Semgrep
- **Upstream Project:** Semgrep Inc. (https://github.com/semgrep/semgrep)
- **Security Domain:** Source Code SAST
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/semgrep_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Fast, polyglot static analysis and AST pattern matching across Python, JavaScript, TypeScript, Go, Java, C#, PHP, and Ruby.
- **What It Detects:** SQL injection, command injection, XSS, insecure deserialization, cryptographic failures, broken authentication, hardcoded secrets.
- **What It Does NOT Detect:** Dynamic runtime configurations, network port states.
- **Why Present:** Premier multi-language AST static analysis engine for modern application codebases.

### 3. Role
- **Classification:** `PRIMARY` SAST engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `CODE_ANALYSIS`. Reads local source files without execution.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`, `QUICK`.

### 6. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Semgrep `1.65.0` (Exact PyPI Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "1.65.0"`.
- **Version Detection:** `semgrep --version` -> Regex `([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `PACKAGE_MANAGER_MODE` (Installed via `pip_installer.py` in virtual environment).

### 9. Supply-Chain Integrity & Provenance
- PyPI package verification in `requirements.txt` with cryptographic digest locking.

### 10. Required Permissions & Privileges
- Read-only access to authorized workspace repository directory.

### 11. Credential Requirements & Injection Method
- `NOT APPLICABLE`

### 12. Workspace Requirements & Confinement
- Server-derived authorized workspace jail (`Path.resolve().startswith(workspace_root)`).

### 13. Network Requirements & Destination Binding Mechanism
- 100% offline execution (uses local ruleset or cached rules).

### 14. Safety Policy & Bounded Probing
- Read-only static analysis; no code execution or file modifications.

### 15. Rate Limit vs Timing Profile
- `NOT APPLICABLE` (Local computation).

### 16. Concurrency Policy
- Multi-core CPU parallel analysis managed by Semgrep engine.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s (or `config.timeout_seconds * 6`).

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 1024 MB. Max stdout: 10 MB.

### 19. Invocation Contract
```text
Executable: <resolved_semgrep_path>
Command Line: semgrep scan --config auto --json <authorized_workspace_path>
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `scan`, `--config auto`, `--config <local_rules_path>`, `--json`, `<authorized_workspace_path>`.

### 21. Forbidden Arguments
- External telemetry uploads (`--send-metrics`), code modification flags.

### 22. Input Schema
- Validated absolute filesystem path within authorized workspace.

### 23. Output Format
- Standard Semgrep JSON report.

### 24. Output Schema & Error Handling
- **Valid Schema:** `results[].check_id`, `results[].path`, `results[].start.line`, `results[].extra.message`, `results[].extra.severity`, `results[].extra.lines`.
- **Missing Lines:** Fallback to line 1.
- **Malformed JSON:** Emits `PARSER_ERROR` and activates native AST taint analyzer.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (Clean scan), `1` (Findings present), `Non-zero` (Syntax error/fatal).
- **CyberAssess Normalized Execution States:**
  - Exit `0` -> `COMPLETED_NO_FINDINGS`
  - Exit `1` -> `COMPLETED_WITH_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native AST taint analyzer.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native Python AST taint analyzer.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native taint analyzer parses Python AST nodes only; lacks Semgrep's polyglot support for JS, Go, Java, PHP, and Ruby.

### 28. Cancellation Protocol
- Immediate process tree termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Process termination cleans up all temporary memory descriptors.

### 30. Parser Specification
- Parses JSON `results[]`, maps rule IDs to canonical check catalog, extracts line numbers, code snippets, and constructs `Finding` models.

### 31. Finding Normalization
- SQL Injection -> `SAST-INJ-001` (CWE-89)
- Command Injection -> `SAST-CMD-001` (CWE-78)
- Insecure Deserialization -> `SAST-CODE-001` (CWE-502)
- Weak Cryptography -> `SAST-CRYP-001` (CWE-327)

### 32. Severity Mapping
- `ERROR` -> `Severity.HIGH` (7.5) / `Severity.CRITICAL` (9.0) based on check ID
- `WARNING` -> `Severity.MEDIUM` (5.3)
- `INFO` -> `Severity.LOW` (3.1)

### 33. Taxonomy Mapping
- `CWE-89`, `CWE-78`, `CWE-79`, `CWE-502`, `CWE-327`, `OWASP A03:2021`, `NIST SI-10, SC-13`.

### 34. Evidence Mapping & Cryptographic Hashing
- File path, start line, end line, code snippet, rule description, evidence hash.

### 35. Secret Handling & Masking
- Masks any hardcoded secrets captured in code snippets.

### 36. Correlation Strategy
- Correlates with DAST findings on identical routes/parameters (SAST+DAST verification).

### 37. Validation Role
- `PRIMARY` source code security authority.

### 38. Reproducibility Record
- Records Semgrep version, ruleset version, scanned file count, and JSON output hash.

### 39. Update & Upgrade Policy
- Managed pip package updates.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestSemgrepAdapter` passing.
- **Capability Taxonomy:**
  - Polyglot AST Matching: `SUPPORTED`
  - Cross-File Deep Taint: `DEFERRED` (Requires Semgrep Pro engine)
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/semgrep_adapter.py`).

---

## TOOL 10: Bandit

### 1. Identity
- **Tool ID:** `TOOL-BANDIT`
- **Display Name:** Bandit
- **Upstream Project:** PyCQA (https://github.com/PyCQA/bandit)
- **Security Domain:** Python Source Code SAST
- **CyberAssess Role:** `SPECIALIZED`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/bandit_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Deep AST-based vulnerability analysis specifically engineered for Python source code.
- **What It Detects:** Insecure `subprocess` with `shell=True`, hardcoded passwords, `pickle` deserialization, weak MD5/SHA1 hashing, `assert` usage in production code, SQL string formatting.
- **What It Does NOT Detect:** Non-Python codebases, dynamic web vulnerabilities.
- **Why Present:** Authoritative Python-native security linter with high precision and low false positives for Python applications.

### 3. Role
- **Classification:** `SPECIALIZED` Python SAST engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `CODE_ANALYSIS`. Reads Python source code without execution.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`, `QUICK`.

### 6. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Bandit `1.7.8` (Exact PyPI Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "1.7.8"`.
- **Version Detection:** `bandit --version` -> Regex `([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `PACKAGE_MANAGER_MODE` (Installed via `pip_installer.py`).

### 9. Supply-Chain Integrity & Provenance
- PyPI package verification in `requirements.txt`.

### 10. Required Permissions & Privileges
- Read-only access to Python source files in authorized workspace.

### 11. Credential Requirements & Injection Method
- `NOT APPLICABLE`

### 12. Workspace Requirements & Confinement
- Server-derived authorized workspace jail.

### 13. Network Requirements & Destination Binding Mechanism
- 100% offline static analysis.

### 14. Safety Policy & Bounded Probing
- Read-only AST parsing; no code execution.

### 15. Rate Limit vs Timing Profile
- `NOT APPLICABLE`

### 16. Concurrency Policy
- Single subprocess instance.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 256 MB. Max stdout: 10 MB.

### 19. Invocation Contract
```text
Executable: <resolved_python_path> -m bandit
Command Line: bandit -r <authorized_workspace_path> -f json
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `-r <path>`, `-f json`, `-ll` (confidence filter), `-q`.

### 21. Forbidden Arguments
- Non-json output formats in automated sweeps.

### 22. Input Schema
- Validated filesystem path containing Python files.

### 23. Output Format
- Bandit JSON report.

### 24. Output Schema & Error Handling
- **Valid Schema:** `results[].test_id`, `results[].filename`, `results[].line_number`, `results[].issue_severity`, `results[].issue_confidence`, `results[].code`.
- **Malformed JSON:** Emits `PARSER_ERROR` and falls back to native AST visitor.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (No issues), `1` (Issues found), `Non-zero` (Parse error).
- **CyberAssess Normalized Execution States:**
  - Exit `0` -> `COMPLETED_NO_FINDINGS`
  - Exit `1` -> `COMPLETED_WITH_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native Python AST visitor.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native Python AST visitor.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native AST visitor covers basic `eval` and `subprocess` checks; lacks Bandit's extensive 70+ Python security rule catalog.

### 28. Cancellation Protocol
- Immediate process tree termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Descriptors closed on exit.

### 30. Parser Specification
- Parses JSON `results[]`, maps Bandit test IDs (`B101` through `B703`) to canonical check catalog.

### 31. Finding Normalization
- `B602`/`B603` (Subprocess shell=True) -> `SAST-CMD-001` (CWE-78)
- `B301`/`B403` (Pickle deserialization) -> `SAST-CODE-001` (CWE-502)
- `B303` (MD5/SHA1 usage) -> `SAST-CRYP-001` (CWE-327)
- `B105`/`B106` (Hardcoded password) -> `SAST-SEC-001` (CWE-798)

### 32. Severity Mapping
- `HIGH` -> `Severity.HIGH` (7.5) / `Severity.CRITICAL` (9.0)
- `MEDIUM` -> `Severity.MEDIUM` (5.3)
- `LOW` -> `Severity.LOW` (3.1)

### 33. Taxonomy Mapping
- `CWE-78`, `CWE-502`, `CWE-327`, `CWE-798`, `OWASP A03:2021`, `NIST SI-10, SC-13`.

### 34. Evidence Mapping & Cryptographic Hashing
- File path, line number, offending code snippet, Bandit test ID, evidence hash.

### 35. Secret Handling & Masking
- Masks hardcoded credentials in `results[].code`.

### 36. Correlation Strategy
- Clustered with Semgrep findings on identical Python files and lines.

### 37. Validation Role
- `SPECIALIZED` Python AST validation.

### 38. Reproducibility Record
- Records Bandit version, test ID list, and scanned file count.

### 39. Update & Upgrade Policy
- Pip package lockfile management.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestBanditAdapter` passing.
- **Capability Taxonomy:**
  - Python AST Security Linting: `SUPPORTED`
  - Cross-File Taint Tracking: `NOT_SUPPORTED`
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/bandit_adapter.py`).

---

## TOOL 11: Gitleaks

### 1. Identity
- **Tool ID:** `TOOL-GITLEAKS`
- **Display Name:** Gitleaks
- **Upstream Project:** Gitleaks (https://github.com/gitleaks/gitleaks)
- **Security Domain:** Secret Scanning & Git History
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/gitleaks_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Fast, regex and entropy-based detection of committed secrets, API keys, private tokens, and passwords in Git commit history and filesystems.
- **What It Detects:** AWS access keys, Stripe secret keys, OpenAI tokens, GitHub personal access tokens, private SSH keys, database connection strings.
- **What It Does NOT Detect:** Code logic vulnerabilities, network misconfigurations.
- **Why Present:** Industry standard for deep Git history audit and pre-commit secret detection.

### 3. Role
- **Classification:** `PRIMARY` secret scanning engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `CODE_ANALYSIS` & `CREDENTIAL_AWARE`. Reads files and Git history for exposed secrets.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`, `QUICK`.

### 6. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Gitleaks `v8.18.2` (Exact GitHub Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "gitleaks v8.18.2"`.
- **Version Detection:** `gitleaks version` -> Regex `v?([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `DIRECT_ARTIFACT_MODE` (Standalone GitHub release binary downloaded via `github_release_installer.py`).

### 9. Supply-Chain Integrity & Provenance
- `windows_amd64`: `22ffef9b8d28131378393c0bc506c4293f773b06ee258be0a597793d54839cf9`
- `linux_amd64`: `ea7b003a2efcaea7f311c19b02a9eb733b8a1c9ef007c6f0c6c06a350a4980a0`

### 10. Required Permissions & Privileges
- Read-only access to authorized workspace repository directory.

### 11. Credential Requirements & Injection Method
- `NOT APPLICABLE`

### 12. Workspace Requirements & Confinement
- Server-derived authorized workspace jail.

### 13. Network Requirements & Destination Binding Mechanism
- 100% offline local scanning.

### 14. Safety Policy & Bounded Probing
- Read-only Git history inspection; no file modifications.

### 15. Rate Limit vs Timing Profile
- `NOT APPLICABLE`

### 16. Concurrency Policy
- Single subprocess instance per scan job.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 512 MB. Max stdout: 10 MB.

### 19. Invocation Contract
```text
Executable: <resolved_gitleaks_path>
Command Line: gitleaks detect --source <authorized_workspace_path> --report-format json --report-path <temp_report_path> --no-banner
Stdout: Diagnostic logs
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `detect`, `--source <path>`, `--report-format json`, `--report-path <path>`, `--no-banner`, `--redact`.

### 21. Forbidden Arguments
- Uncontrolled external config fetches.

### 22. Input Schema
- Validated repository directory path.

### 23. Output Format
- JSON report file.

### 24. Output Schema & Error Handling
- **Valid Schema:** `RuleID`, `Description`, `Secret`, `File`, `StartLine`, `Commit`, `Author`.
- **Missing Author:** Defaults to `"unknown"`.
- **Malformed JSON:** Emits `PARSER_ERROR` and falls back to native secret scanner.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (No secrets found), `1` (Secrets detected), `Non-zero` (Repository error).
- **CyberAssess Normalized Execution States:**
  - Exit `0` -> `COMPLETED_NO_FINDINGS`
  - Exit `1` -> `COMPLETED_WITH_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native secret scanner.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native Shannon entropy & regex secret scanner.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native scanner detects high-entropy strings and common API keys in current files, but does not traverse deep Git commit history.

### 28. Cancellation Protocol
- Immediate process tree termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Temporary report file deleted immediately after parsing.

### 30. Parser Specification
- Reads temporary JSON report, extracts findings, applies mandatory multi-stage secret masking (`mask_secret()`), and generates `Finding` models.

### 31. Finding Normalization
- Hardcoded Secret -> Check ID `SAST-SEC-001`, Severity `CRITICAL`, CVSS 9.8, CWE-798.

### 32. Severity Mapping
- High-Entropy API Key / Private Key -> `Severity.CRITICAL` (9.8)
- Generic Credential -> `Severity.HIGH` (7.5)

### 33. Taxonomy Mapping
- `CWE-798`, `OWASP A07:2021`, `ASVS 5.0 v5.0.0-V3.6.1`, `NIST IA-2, SC-28`.

### 34. Evidence Mapping & Cryptographic Hashing
- File path, start line, commit hash, author email, masked secret snippet, SHA-256 evidence hash.

### 35. Secret Handling & Masking
- **Mandatory Masking:** Retains first 6 and last 4 characters; masks middle with `******` (e.g., `AKIAIOSFODNN******ABCD`). Unmasked raw secrets are NEVER persisted to database or logs.

### 36. Correlation Strategy
- Correlates with TruffleHog live validation and native secret scanner.

### 37. Validation Role
- `PRIMARY` static secret discovery authority.

### 38. Reproducibility Record
- Records Gitleaks version, scanned commit count, and masked finding hashes.

### 39. Update & Upgrade Policy
- Pinned manifest checksum updates.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestGitleaksAdapter` passing.
- **Capability Taxonomy:**
  - Filesystem Secret Detection: `SUPPORTED`
  - Git Commit History Traversal: `SUPPORTED`
  - Secret Live Verification: `NOT_SUPPORTED` (Delegated to TruffleHog)
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/gitleaks_adapter.py`).

---

## TOOL 12: TruffleHog

### 1. Identity
- **Tool ID:** `TOOL-TRUFFLEHOG`
- **Display Name:** TruffleHog
- **Upstream Project:** Truffle Security (https://github.com/trufflesecurity/trufflehog)
- **Security Domain:** Secret Scanning & Live Verification
- **CyberAssess Role:** `VALIDATION`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/trufflehog_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Detects secrets with detector-specific live verification (e.g. verifying if an AWS key or GitHub token is currently active and authenticated).
- **What It Detects:** Valid live AWS credentials, GitHub tokens, Slack webhooks, database credentials.
- **What It Does NOT Detect:** Code logic bugs, network vulnerabilities.
- **Why Present:** Eliminates false positives by validating whether exposed secrets are active and exploitable in the wild.

### 3. Role
- **Classification:** `VALIDATION` engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `CREDENTIAL_AWARE` & `ACTIVE_READ_ONLY`. Initiates read-only authentication probes to cloud providers.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`.

### 6. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` TruffleHog `v3.63.0` (Exact Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "trufflehog v3.63.0"`.
- **Version Detection:** `trufflehog --version` -> Regex `v?([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `DIRECT_ARTIFACT_MODE` (Standalone binary downloaded via `github_release_installer.py`).

### 9. Supply-Chain Integrity & Provenance
- Verified in `PINNED_TOOL_MANIFEST`.

### 10. Required Permissions & Privileges
- Read-only access to authorized workspace repository directory.

### 11. Credential Requirements & Injection Method
- `NOT APPLICABLE`

### 12. Workspace Requirements & Confinement
- Server-derived authorized workspace jail.

### 13. Network Requirements & Destination Binding Mechanism
- Outbound HTTPS access only if live secret verification is explicitly enabled in tenant policy.

### 14. Safety Policy & Bounded Probing
- Read-only live verification queries; non-destructive auth checks only.

### 15. Rate Limit vs Timing Profile
- Bounded to upstream provider limits.

### 16. Concurrency Policy
- Single subprocess instance.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 512 MB. Max stdout: 10 MB.

### 19. Invocation Contract
```text
Executable: <resolved_trufflehog_path>
Command Line: trufflehog filesystem <authorized_workspace_path> --json --no-update
Stdout: Captures JSON stream
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `filesystem <path>`, `--json`, `--no-update`, `--only-verified`.

### 21. Forbidden Arguments
- Unbounded network sweeps without tenant authorization.

### 22. Input Schema
- Validated workspace filesystem path.

### 23. Output Format
- JSON Lines stream.

### 24. Output Schema & Error Handling
- **Valid Schema:** `DetectorName`, `Verified`, `Raw`, `SourceMetadata.Data.Filesystem.file`, `SourceMetadata.Data.Filesystem.line`.
- **Malformed Lines:** Skipped safely.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (No secrets), `Non-zero` (Secrets found or execution error).
- **CyberAssess Normalized Execution States:**
  - Exit `0` -> `COMPLETED_NO_FINDINGS`
  - Findings parsed -> `COMPLETED_WITH_FINDINGS`
  - Unhandled error -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and relies on Gitleaks unverified findings.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native regex scanner & Gitleaks.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native scanner detects patterns but cannot verify if credentials are live and authenticated against external cloud APIs.

### 28. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Descriptors closed on exit.

### 30. Parser Specification
- Parses JSON Lines stream, verifies `Verified: true` status, masks secrets, and generates canonical findings.

### 31. Finding Normalization
- Verified Live Secret -> Check ID `SAST-SEC-001`, Severity `CRITICAL` (CVSS 10.0), CWE-798.

### 32. Severity Mapping
- Verified Live Key -> `Severity.CRITICAL` (10.0)
- Unverified Candidate -> `Severity.HIGH` (7.5)

### 33. Taxonomy Mapping
- `CWE-798`, `OWASP A07:2021`, `ASVS 5.0 v5.0.0-V3.6.1`, `NIST IA-2`.

### 34. Evidence Mapping & Cryptographic Hashing
- Detector name, verification state, file path, line number, masked key, SHA-256 evidence digest.

### 35. Secret Handling & Masking
- Strict multi-stage secret masking enforced before persistence.

### 36. Correlation Strategy
- Confirms and upgrades unverified `Gitleaks` findings to `VERIFIED` status.

### 37. Validation Role
- `VALIDATION` authority for credential exploitability.

### 38. Reproducibility Record
- Records detector name, verification status, and masked hash.

### 39. Update & Upgrade Policy
- Manifest checksum updates.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestTruffleHogAdapter` passing.
- **Capability Taxonomy:**
  - Filesystem Secret Detection: `SUPPORTED`
  - Live Secret Verification: `SUPPORTED`
  - S3 / Git Remote Crawling: `DEFERRED`
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/trufflehog_adapter.py`).

---

## TOOL 13: Retire.js

### 1. Identity
- **Tool ID:** `TOOL-RETIREJS`
- **Display Name:** Retire.js
- **Upstream Project:** Retire.js (https://github.com/RetireJS/retire.js)
- **Security Domain:** Client-Side JavaScript SCA
- **CyberAssess Role:** `SPECIALIZED`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/retirejs_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Scans JavaScript source files and node modules for known vulnerable frontend libraries (jQuery, Bootstrap, Angular, Lodash, React).
- **What It Detects:** Outdated client-side JS libraries with published CVEs and XSS vulnerabilities.
- **What It Does NOT Detect:** Backend server logic, infrastructure misconfigurations.
- **Why Present:** Specialized precision for client-side JavaScript supply chain vulnerabilities.

### 3. Role
- **Classification:** `SPECIALIZED` JavaScript SCA engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `SUPPLY_CHAIN` & `CODE_ANALYSIS`. Reads local JS files.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`, `DAST_ONLY`.

### 6. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Retire.js `4.4.3` (Exact Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "4.4.3"`.
- **Version Detection:** `retire --version` -> Regex `([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `PACKAGE_MANAGER_MODE` (Installed via npm / system installer).

### 9. Supply-Chain Integrity & Provenance
- Verified in `PINNED_TOOL_MANIFEST`.

### 10. Required Permissions & Privileges
- Read-only workspace access.

### 11. Credential Requirements & Injection Method
- `NOT APPLICABLE`

### 12. Workspace Requirements & Confinement
- Server-derived authorized workspace jail.

### 13. Network Requirements & Destination Binding Mechanism
- Offline scanning using bundled vulnerability database.

### 14. Safety Policy & Bounded Probing
- Read-only file inspection.

### 15. Rate Limit vs Timing Profile
- `NOT APPLICABLE`

### 16. Concurrency Policy
- Single subprocess instance.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 256 MB.

### 19. Invocation Contract
```text
Executable: <resolved_retire_path>
Command Line: retire --path <authorized_workspace_path> --outputformat json --nodownload
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `--path <path>`, `--outputformat json`, `--nodownload`.

### 21. Forbidden Arguments
- Execution of untrusted scripts.

### 22. Input Schema
- Validated workspace filesystem path.

### 23. Output Format
- JSON report structure.

### 24. Output Schema & Error Handling
- **Valid Schema:** `data[].file`, `data[].results[].component`, `data[].results[].version`, `data[].results[].vulnerabilities[]`.
- **Malformed JSON:** Emits `PARSER_ERROR` and falls back to native SCA.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (No issues), `1` / `13` (Issues found), `Non-zero` (Parse error).
- **CyberAssess Normalized Execution States:**
  - Exit `0` -> `COMPLETED_NO_FINDINGS`
  - Findings parsed -> `COMPLETED_WITH_FINDINGS`
  - Fatal error -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native dependency auditor.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native dependency auditor.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native auditor checks `package.json` lockfiles; cannot fingerprint raw unversioned vendor JS files embedded in HTML/JS assets.

### 28. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Descriptors closed on exit.

### 30. Parser Specification
- Parses JSON `data[]`, extracts library names, versions, CVE IDs, and generates `Finding` models.

### 31. Finding Normalization
- Vulnerable Client JS Library -> Check ID `SAST-DEP-001`, Severity `HIGH`/`MEDIUM`, CWE-1395.

### 32. Severity Mapping
- `critical`/`high` -> `Severity.HIGH` (7.5)
- `medium` -> `Severity.MEDIUM` (5.3)
- `low` -> `Severity.LOW` (3.1)

### 33. Taxonomy Mapping
- `CWE-1395`, `OWASP A06:2021`, `NIST SA-12, SI-2`.

### 34. Evidence Mapping & Cryptographic Hashing
- File path, library component, installed version, CVE identifier, evidence hash.

### 35. Secret Handling & Masking
- `NOT APPLICABLE`

### 36. Correlation Strategy
- Clustered with Trivy and Grype frontend dependency findings.

### 37. Validation Role
- `SPECIALIZED` frontend JS SCA authority.

### 38. Reproducibility Record
- Records Retire.js version, component list, and CVE matches.

### 39. Update & Upgrade Policy
- Pinned installer management.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestRetireJSAdapter` passing.
- **Capability Taxonomy:**
  - JavaScript File Scanning: `SUPPORTED`
  - Node Modules Scanning: `SUPPORTED`
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/retirejs_adapter.py`).

---

## TOOL 14: Trivy

### 1. Identity
- **Tool ID:** `TOOL-TRIVY`
- **Display Name:** Trivy
- **Upstream Project:** Aqua Security (https://github.com/aquasecurity/trivy)
- **Security Domain:** Container, Filesystem & Dependency SCA
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/trivy_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Comprehensive scanner for container images, filesystems, Git repositories, and lockfiles for known package CVEs, OS package vulnerabilities, and misconfigurations.
- **What It Detects:** Published CVEs across pip, npm, yarn, go.mod, maven, rubygems, cargo, composer, Docker images, and Linux OS packages (Alpine, Debian, Ubuntu, RHEL).
- **What It Does NOT Detect:** Dynamic web injection attacks, network port posture.
- **Why Present:** Industry standard multi-domain SCA and container vulnerability scanner.

### 3. Role
- **Classification:** `PRIMARY` SCA and container security engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `SUPPLY_CHAIN` & `CODE_ANALYSIS`. Reads lockfiles, manifests, and container layers.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`, `INFRA_CONTAINER`, `QUICK`.

### 6. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`, `DOCKERFILE`, `CONTAINER_IMAGE`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Trivy `v0.50.0` (Exact GitHub Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "0.50.0"`.
- **Version Detection:** `trivy --version` -> Regex `Version:\s*([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `DIRECT_ARTIFACT_MODE` (Standalone GitHub release binary downloaded via `github_release_installer.py`).

### 9. Supply-Chain Integrity & Provenance
- `windows_amd64`: `7ef999da89cc79aa9369d714cb9fdf3c32ef093a1f8d48e35a111a43a059f3d9`
- `linux_amd64`: `1ff1e6d2bc1050a4da61706f30a91176b6ef0aa0fefca23a63ec592ff3320f69`

### 10. Required Permissions & Privileges
- Read-only workspace access (or local Docker daemon access for image scanning).

### 11. Credential Requirements & Injection Method
- `NOT APPLICABLE` for filesystem scans; optional registry credentials for private image pulls.

### 12. Workspace Requirements & Confinement
- Server-derived authorized workspace jail.

### 13. Network Requirements & Destination Binding Mechanism
- Offline mode supported (`--offline-scan`) using pre-downloaded vulnerability DB.

### 14. Safety Policy & Bounded Probing
- Read-only static inspection; no container execution.

### 15. Rate Limit vs Timing Profile
- `NOT APPLICABLE`

### 16. Concurrency Policy
- Multi-core CPU parallel analysis.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 1024 MB. Max stdout: 10 MB.

### 19. Invocation Contract
```text
Executable: <resolved_trivy_path>
Command Line: trivy fs --format json --offline-scan <authorized_workspace_path>
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `fs`, `image`, `--format json`, `--offline-scan`, `--severity <severities>`, `--scanners vuln,misconfig`, `<path>`.

### 21. Forbidden Arguments
- In-place remediation flags, raw binary downloads during scan.

### 22. Input Schema
- Validated workspace filesystem path or image name.

### 23. Output Format
- Standard Trivy JSON schema.

### 24. Output Schema & Error Handling
- **Valid Schema:** `Results[].Target`, `Results[].Vulnerabilities[].VulnerabilityID`, `Results[].Vulnerabilities[].PkgName`, `Results[].Vulnerabilities[].InstalledVersion`, `Results[].Vulnerabilities[].FixedVersion`, `Results[].Vulnerabilities[].Severity`, `Results[].Vulnerabilities[].PrimaryURL`.
- **Malformed JSON:** Emits `PARSER_ERROR` and falls back to native lockfile auditor.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (Success), `Non-zero` (Database unreadable or target missing).
- **CyberAssess Normalized Execution States:**
  - Exit `0` with vulnerabilities found -> `COMPLETED_WITH_FINDINGS`
  - Exit `0` with no vulnerabilities -> `COMPLETED_NO_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native lockfile auditor.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native lockfile dependency auditor.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native auditor parses Python and Node lockfiles against a local cache; lacks Trivy's comprehensive multi-ecosystem vulnerability database and OS package scanning.

### 28. Cancellation Protocol
- Immediate process tree termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Descriptors closed on exit.

### 30. Parser Specification
- Parses JSON `Results[].Vulnerabilities[]`, extracts package details, maps CVEs and fix versions to `Finding` models.

### 31. Finding Normalization
- Third-Party Vulnerable Dependency -> Check ID `SAST-DEP-001`, Severity from Trivy, CWE-1395.

### 32. Severity Mapping
- `CRITICAL` -> `Severity.CRITICAL` (9.8)
- `HIGH` -> `Severity.HIGH` (7.5)
- `MEDIUM` -> `Severity.MEDIUM` (5.3)
- `LOW` -> `Severity.LOW` (3.1)

### 33. Taxonomy Mapping
- `CWE-1395`, `OWASP A06:2021`, `NIST SA-12, SI-2`.

### 34. Evidence Mapping & Cryptographic Hashing
- Package name, installed version, fixed version, CVE ID, advisory URL, evidence hash.

### 35. Secret Handling & Masking
- `NOT APPLICABLE`

### 36. Correlation Strategy
- Clustered with Syft, Grype, and OSV-Scanner findings using `(package_name, version, cve_id)` key.

### 37. Validation Role
- `PRIMARY` SCA and container vulnerability authority.

### 38. Reproducibility Record
- Records Trivy version, DB version, scanned manifest count, and JSON hash.

### 39. Update & Upgrade Policy
- Manifest digest updates.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestTrivyAdapter` passing.
- **Capability Taxonomy:**
  - Filesystem Lockfile SCA: `SUPPORTED`
  - Container Image Vulnerability: `SUPPORTED`
  - Kubernetes Live Cluster Scan: `DEFERRED`
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/trivy_adapter.py`).

---

## TOOL 15: Grype

### 1. Identity
- **Tool ID:** `TOOL-GRYPE`
- **Display Name:** Grype
- **Upstream Project:** Anchore (https://github.com/anchore/grype)
- **Security Domain:** SBOM & Container Vulnerability Scanning
- **CyberAssess Role:** `VALIDATION`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/grype_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Fast dependency vulnerability matcher that ingests SBOMs (CycloneDX / SPDX) and container images, matching against Anchore's multi-source vulnerability database.
- **What It Detects:** Known CVEs, GHSA advisories, fix versions across package ecosystems and container images.
- **What It Does NOT Detect:** Static code flaws, live web vulnerabilities.
- **Why Present:** High-speed validation engine that consumes Syft-generated SBOMs to cross-verify Trivy findings.

### 3. Role
- **Classification:** `VALIDATION` engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `SUPPLY_CHAIN`. Analyzes SBOMs and container packages.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`, `INFRA_CONTAINER`.

### 6. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`, `CONTAINER_IMAGE`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Grype `v0.74.0` (Exact GitHub Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "0.74.0"`.
- **Version Detection:** `grype version` -> Regex `version:\s*([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `DIRECT_ARTIFACT_MODE` (Standalone GitHub release binary downloaded via `github_release_installer.py`).

### 9. Supply-Chain Integrity & Provenance
- `windows_amd64`: `82ff190a6e60b135bb0a3952ba5c3d4f1ea38ba662884a20b666a0eb0bb9b7c8`
- `linux_amd64`: `e30e6912a52efc188fa63e52701a2eb3a8a9bc6838a53e680a653bb26d9c9b58`

### 10. Required Permissions & Privileges
- Read-only workspace access.

### 11. Credential Requirements & Injection Method
- `NOT APPLICABLE`

### 12. Workspace Requirements & Confinement
- Server-derived authorized workspace jail.

### 13. Network Requirements & Destination Binding Mechanism
- Offline mode supported.

### 14. Safety Policy & Bounded Probing
- Read-only SBOM and file inspection.

### 15. Rate Limit vs Timing Profile
- `NOT APPLICABLE`

### 16. Concurrency Policy
- Single subprocess instance.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 512 MB.

### 19. Invocation Contract
```text
Executable: <resolved_grype_path>
Command Line: grype dir:<authorized_workspace_path> -o json
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `dir:<path>`, `sbom:<sbom_file>`, `image:<image>`, `-o json`, `--only-fixed`.

### 21. Forbidden Arguments
- External database auto-updates during scan.

### 22. Input Schema
- Validated workspace filesystem path or SBOM file path.

### 23. Output Format
- Standard Grype JSON schema.

### 24. Output Schema & Error Handling
- **Valid Schema:** `matches[].vulnerability.id`, `matches[].vulnerability.severity`, `matches[].artifact.name`, `matches[].artifact.version`, `matches[].vulnerability.fix.versions[]`.
- **Malformed JSON:** Emits `PARSER_ERROR` and falls back to native SCA.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (Success), `Non-zero` (Parse error or invalid SBOM input).
- **CyberAssess Normalized Execution States:**
  - Exit `0` with vulnerability matches -> `COMPLETED_WITH_FINDINGS`
  - Exit `0` with clean SBOM -> `COMPLETED_NO_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and relies on Trivy and native SCA.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native dependency auditor.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native auditor lacks Anchore's proprietary vulnerability matching algorithms and vulnerability database.

### 28. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Descriptors closed on exit.

### 30. Parser Specification
- Parses JSON `matches[]`, maps CVEs and fix versions to `Finding` models.

### 31. Finding Normalization
- Third-Party Vulnerable Dependency -> Check ID `SAST-DEP-001`, Severity from Grype, CWE-1395.

### 32. Severity Mapping
- `Critical` -> `Severity.CRITICAL` (9.8)
- `High` -> `Severity.HIGH` (7.5)
- `Medium` -> `Severity.MEDIUM` (5.3)
- `Low` -> `Severity.LOW` (3.1)

### 33. Taxonomy Mapping
- `CWE-1395`, `OWASP A06:2021`, `NIST SA-12`.

### 34. Evidence Mapping & Cryptographic Hashing
- Package name, version, fix versions, CVE ID, evidence hash.

### 35. Secret Handling & Masking
- `NOT APPLICABLE`

### 36. Correlation Strategy
- Cross-validates and confirms Trivy SCA findings.

### 37. Validation Role
- `VALIDATION` authority for dependency CVEs.

### 38. Reproducibility Record
- Records Grype version, DB version, and match count.

### 39. Update & Upgrade Policy
- Manifest digest updates.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestGrypeAdapter` passing.
- **Capability Taxonomy:**
  - SBOM Vulnerability Matching: `SUPPORTED`
  - Container Image Vulnerability: `SUPPORTED`
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/grype_adapter.py`).

---

## TOOL 16: Syft

### 1. Identity
- **Tool ID:** `TOOL-SYFT`
- **Display Name:** Syft
- **Upstream Project:** Anchore (https://github.com/anchore/syft)
- **Security Domain:** Software Bill of Materials (SBOM)
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/syft_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Generates authoritative, standard-compliant Software Bill of Materials (SBOM) documents in CycloneDX and SPDX formats from filesystems and container images.
- **What It Detects:** Complete dependency inventory, packages, licenses, component hashes, transitive dependencies.
- **What It Does NOT Detect:** Direct security vulnerabilities (used upstream of scanners).
- **Why Present:** Industry standard engine for Executive Order 14028 / SLSA compliant SBOM generation.

### 3. Role
- **Classification:** `PRIMARY` SBOM generation engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `SUPPLY_CHAIN`. Inspects packages and creates SBOMs.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`, `INFRA_CONTAINER`.

### 6. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`, `CONTAINER_IMAGE`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Syft `v1.0.1` (Exact GitHub Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "1.0.1"`.
- **Version Detection:** `syft version` -> Regex `version:\s*([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `DIRECT_ARTIFACT_MODE` (Standalone GitHub release binary downloaded via `github_release_installer.py`).

### 9. Supply-Chain Integrity & Provenance
- `windows_amd64`: `426be0eb2a297e6be9ea83664746f34586db30188aa1d3824ee18c15668db8c0`
- `linux_amd64`: `99ea78ab499c75fe95fa72ce66d3cfcbb86baebfca1a24dcaee263d91cf9679f`

### 10. Required Permissions & Privileges
- Read-only workspace access.

### 11. Credential Requirements & Injection Method
- `NOT APPLICABLE`

### 12. Workspace Requirements & Confinement
- Server-derived authorized workspace jail.

### 13. Network Requirements & Destination Binding Mechanism
- 100% offline SBOM generation.

### 14. Safety Policy & Bounded Probing
- Read-only package cataloging.

### 15. Rate Limit vs Timing Profile
- `NOT APPLICABLE`

### 16. Concurrency Policy
- Single subprocess instance.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 512 MB.

### 19. Invocation Contract
```text
Executable: <resolved_syft_path>
Command Line: syft dir:<authorized_workspace_path> -o cyclonedx-json=<temp_output_file>
Stdout: Diagnostic logs
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `dir:<path>`, `image:<image>`, `-o cyclonedx-json=<file>`, `-o spdx-json=<file>`.

### 21. Forbidden Arguments
- Uncontrolled external uploads.

### 22. Input Schema
- Validated workspace filesystem path.

### 23. Output Format
- Standard CycloneDX 1.5 JSON or SPDX 2.3 JSON.

### 24. Output Schema & Error Handling
- **Valid Schema:** `bomFormat: "CycloneDX"`, `specVersion: "1.5"`, `components[]`.
- **Malformed Output:** Emits `PARSER_ERROR` and falls back to native CycloneDX exporter.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (Success), `Non-zero` (Cataloging error).
- **CyberAssess Normalized Execution States:**
  - Exit `0` -> `COMPLETED_NO_FINDINGS` (Artifact generated)
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native CycloneDX exporter.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native Python CycloneDX exporter.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native exporter catalogs top-level lockfile entries; lacks Syft's deep binary scanning and license extraction.

### 28. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Temporary SBOM export files deleted after archiving.

### 30. Parser Specification
- Parses CycloneDX JSON, validates component records, and attaches SBOM artifact to scan session.

### 31. Finding Normalization
- `NOT APPLICABLE` (Generates asset inventory/SBOM artifact rather than direct vulnerability findings).

### 32. Severity Mapping
- `Severity.INFO` (0.0 CVSS).

### 33. Taxonomy Mapping
- `NIST SP 800-53`: `CM-8, SA-12`.

### 34. Evidence Mapping & Cryptographic Hashing
- Complete serialized CycloneDX SBOM JSON string and SHA-256 evidence digest.

### 35. Secret Handling & Masking
- Sanitizes file paths in component metadata.

### 36. Correlation Strategy
- Feeds SBOM components directly into Grype for secondary vulnerability matching.

### 37. Validation Role
- `PRIMARY` software inventory authority.

### 38. Reproducibility Record
- Records Syft version, component count, and SBOM SHA-256 digest.

### 39. Update & Upgrade Policy
- Manifest digest updates.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestSyftAdapter` passing.
- **Capability Taxonomy:**
  - CycloneDX 1.5 JSON Generation: `SUPPORTED`
  - SPDX 2.3 JSON Generation: `SUPPORTED`
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/syft_adapter.py`).

---

## TOOL 17: OSV-Scanner

### 1. Identity
- **Tool ID:** `TOOL-OSV-SCANNER`
- **Display Name:** OSV-Scanner
- **Upstream Project:** Google (https://github.com/google/osv-scanner)
- **Security Domain:** Open Source Vulnerability Database SCA
- **CyberAssess Role:** `SPECIALIZED`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/osv_scanner_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Direct query interface into Google's authoritative Open Source Vulnerabilities (OSV) distributed database across npm, PyPI, Go, Maven, Rust, Packagist, and Debian.
- **What It Detects:** Published CVEs and GHSA advisories with precise commit-level vulnerability ranges.
- **What It Does NOT Detect:** Static code flaws, web DAST issues.
- **Why Present:** High-precision vulnerability intelligence backed directly by Google's OSV schema.

### 3. Role
- **Classification:** `SPECIALIZED` OSV intelligence engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `SUPPLY_CHAIN`. Queries Google OSV database.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`.

### 6. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` OSV-Scanner `v1.7.0` (Exact GitHub Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "v1.7.0"`.
- **Version Detection:** `osv-scanner --version` -> Regex `v?([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `DIRECT_ARTIFACT_MODE` (Standalone GitHub release binary downloaded via `github_release_installer.py`).

### 9. Supply-Chain Integrity & Provenance
- `windows_amd64`: `9812e987c1cb50faeeeb14c330f878f0d8a7c2b6ca8858e999905f15d9715bf8`
- `linux_amd64`: `a3b836ec3b2a8d381048b6c59b66f272a0ba0508ffb6a7a7262078696ec09138`

### 10. Required Permissions & Privileges
- Read-only workspace access.

### 11. Credential Requirements & Injection Method
- `NOT APPLICABLE`

### 12. Workspace Requirements & Confinement
- Server-derived authorized workspace jail.

### 13. Network Requirements & Destination Binding Mechanism
- Outbound HTTPS access to `api.osv.dev` (or local offline lockfile matching).

### 14. Safety Policy & Bounded Probing
- Read-only package metadata inspection.

### 15. Rate Limit vs Timing Profile
- Bounded to OSV API limits.

### 16. Concurrency Policy
- Single subprocess instance.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 512 MB.

### 19. Invocation Contract
```text
Executable: <resolved_osv_scanner_path>
Command Line: osv-scanner --json -r <authorized_workspace_path>
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `--json`, `-r <path>`, `--lockfile=<file>`, `--config=<file>`.

### 21. Forbidden Arguments
- Auto-remediation flags altering source lockfiles.

### 22. Input Schema
- Validated workspace filesystem path.

### 23. Output Format
- Standard OSV JSON schema.

### 24. Output Schema & Error Handling
- **Valid Schema:** `results[].packages[].package.name`, `results[].packages[].package.version`, `results[].packages[].vulnerabilities[].id`.
- **Malformed JSON:** Emits `PARSER_ERROR` and falls back to native SCA.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (No vulnerabilities), `1` (Vulnerabilities found), `Non-zero` (Parse failure).
- **CyberAssess Normalized Execution States:**
  - Exit `0` -> `COMPLETED_NO_FINDINGS`
  - Exit `1` -> `COMPLETED_WITH_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native dependency auditor.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native dependency auditor.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native auditor checks basic CVE listings; lacks Google OSV's precise commit-level hash matching.

### 28. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Descriptors closed on exit.

### 30. Parser Specification
- Parses JSON `results[]`, maps OSV/GHSA/CVE IDs to canonical `Finding` models.

### 31. Finding Normalization
- Third-Party Dependency Vulnerability -> Check ID `SAST-DEP-001`, Severity from OSV, CWE-1395.

### 32. Severity Mapping
- `CRITICAL` -> `Severity.CRITICAL` (9.8)
- `HIGH` -> `Severity.HIGH` (7.5)
- `MODERATE` / `MEDIUM` -> `Severity.MEDIUM` (5.3)
- `LOW` -> `Severity.LOW` (3.1)

### 33. Taxonomy Mapping
- `CWE-1395`, `OWASP A06:2021`, `NIST SA-12`.

### 34. Evidence Mapping & Cryptographic Hashing
- Package name, version, OSV ID, advisory summary, evidence hash.

### 35. Secret Handling & Masking
- `NOT APPLICABLE`

### 36. Correlation Strategy
- Clustered with Trivy and Grype findings.

### 37. Validation Role
- `SPECIALIZED` Google OSV intelligence authority.

### 38. Reproducibility Record
- Records OSV-Scanner version, scanned lockfiles, and match count.

### 39. Update & Upgrade Policy
- Manifest digest updates.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestOSVScannerAdapter` passing.
- **Capability Taxonomy:**
  - Lockfile OSV Intelligence: `SUPPORTED`
  - Git Commit Hash Vulnerability Matching: `SUPPORTED`
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/osv_scanner_adapter.py`).

---

## TOOL 18: Checkov

### 1. Identity
- **Tool ID:** `TOOL-CHECKOV`
- **Display Name:** Checkov
- **Upstream Project:** Bridgecrew / Prisma Cloud (https://github.com/bridgecrewio/checkov)
- **Security Domain:** Infrastructure-as-Code (IaC) & Cloud Posture
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/checkov_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Static code analysis for Infrastructure-as-Code (IaC) files covering Terraform, CloudFormation, Kubernetes YAML, Dockerfiles, ARM templates, and Serverless frameworks.
- **What It Detects:** Publicly exposed S3 buckets, unrestricted security groups (`0.0.0.0/0`), missing encryption at rest, root container processes, privileged Kubernetes pods, missing TLS policies.
- **What It Does NOT Detect:** Dynamic web injection bugs, live network services.
- **Why Present:** Authoritative multi-framework IaC security linter and CIS benchmark compliance engine.

### 3. Role
- **Classification:** `PRIMARY` IaC security analysis engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `CODE_ANALYSIS`. Reads IaC source manifests.

### 5. Supported CyberAssess Profiles
- `FULL_STACK`, `INFRA_ONLY`, `SAST_ONLY`, `INFRA_CONTAINER`.

### 6. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`, `IAC_MANIFEST`, `DOCKERFILE`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Checkov `3.2.0` (Exact PyPI Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "3.2.0"`.
- **Version Detection:** `checkov --version` -> Regex `([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `PACKAGE_MANAGER_MODE` (Installed via `pip_installer.py` in isolated venv).

### 9. Supply-Chain Integrity & Provenance
- PyPI package verification in `requirements.txt` with PEP 740 attestations.

### 10. Required Permissions & Privileges
- Read-only workspace access to IaC manifests.

### 11. Credential Requirements & Injection Method
- `NOT APPLICABLE` for static IaC file analysis.

### 12. Workspace Requirements & Confinement
- Server-derived authorized workspace jail.

### 13. Network Requirements & Destination Binding Mechanism
- 100% offline static inspection.

### 14. Safety Policy & Bounded Probing
- Read-only file inspection; zero resource provisioning.

### 15. Rate Limit vs Timing Profile
- `NOT APPLICABLE`

### 16. Concurrency Policy
- Multi-core CPU parallel parsing.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 1024 MB. Max stdout: 10 MB.

### 19. Invocation Contract
```text
Executable: <resolved_python_path> -m checkov
Command Line: checkov -d <authorized_workspace_path> -o json --quiet --compact
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `-d <dir>`, `-f <file>`, `-o json`, `--quiet`, `--compact`, `--framework <frameworks>`.

### 21. Forbidden Arguments
- External Bridgecrew cloud sync flags (`--bc-api-key`), telemetry uploads.

### 22. Input Schema
- Validated workspace filesystem path.

### 23. Output Format
- Checkov JSON report.

### 24. Output Schema & Error Handling
- **Valid Schema:** `results.failed_checks[].check_id`, `results.failed_checks[].check_name`, `results.failed_checks[].file_path`, `results.failed_checks[].file_line_range`, `results.failed_checks[].guideline`.
- **Malformed JSON:** Emits `PARSER_ERROR` and falls back to native IaC linters.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (All policies passed), `1` (Failed policies detected), `Non-zero` (Parse error).
- **CyberAssess Normalized Execution States:**
  - Exit `0` -> `COMPLETED_NO_FINDINGS`
  - Exit `1` -> `COMPLETED_WITH_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native IaC engine.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native Dockerfile, Kubernetes, and Terraform AST linters.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native linters cover root Docker containers and public S3 buckets; lack Checkov's 1,000+ multi-cloud CIS benchmark policy packs.

### 28. Cancellation Protocol
- Immediate process tree termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Descriptors closed on exit.

### 30. Parser Specification
- Parses JSON `failed_checks[]`, maps Checkov check IDs (e.g. `CKV_AWS_20`, `CKV_DOCKER_1`) to canonical `Finding` models.

### 31. Finding Normalization
- Public S3 Bucket -> `IAC-TF-001` (CWE-732), Severity `HIGH`, CVSS 7.5
- Unrestricted Ingress (0.0.0.0/0) -> `IAC-TF-002` (CWE-284), Severity `HIGH`, CVSS 7.5
- Container Root User -> `IAC-DOCKER-001` (CWE-250), Severity `HIGH`, CVSS 7.5
- Privileged K8s Pod -> `IAC-K8S-001` (CWE-732), Severity `CRITICAL`, CVSS 9.0

### 32. Severity Mapping
- Checkov `FAILED` checks mapped to `Severity.HIGH` or `Severity.CRITICAL` based on resource criticality.

### 33. Taxonomy Mapping
- `CWE-732`, `CWE-284`, `CWE-250`, `OWASP A05:2021`, `NIST SP 800-53: AC-3, AC-6, CM-7`.

### 34. Evidence Mapping & Cryptographic Hashing
- File path, line range, failed policy name, guideline URL, code snippet, evidence hash.

### 35. Secret Handling & Masking
- Masks any hardcoded variables in IaC snippets.

### 36. Correlation Strategy
- Correlates with Dockle and native IaC engine findings.

### 37. Validation Role
- `PRIMARY` Infrastructure-as-Code security authority.

### 38. Reproducibility Record
- Records Checkov version, scanned framework list, and failed policy count.

### 39. Update & Upgrade Policy
- Pip package lockfile management.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestCheckovAdapter` passing.
- **Capability Taxonomy:**
  - Terraform / CloudFormation AST: `SUPPORTED`
  - Kubernetes / Dockerfile Linter: `SUPPORTED`
  - Framework Plan Analysis: `DEFERRED`
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/checkov_adapter.py`).

---

## TOOL 19: Prowler

### 1. Identity
- **Tool ID:** `TOOL-PROWLER`
- **Display Name:** Prowler
- **Upstream Project:** Prowler (https://github.com/prowler-cloud/prowler)
- **Security Domain:** Multi-Cloud Posture & CIS Benchmarks
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/prowler_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Multi-cloud security posture assessment (CSPM) across AWS, Azure, GCP, and Kubernetes for CIS Benchmarks, GDPR, HIPAA, and ISO 27001 compliance.
- **What It Detects:** Unencrypted cloud databases, missing MFA on root accounts, overly permissive IAM roles, public storage buckets, unlogged API gateways.
- **What It Does NOT Detect:** Static source code vulnerabilities, dynamic web injections.
- **Why Present:** Industry standard multi-cloud CIS benchmark compliance and audit engine.

### 3. Role
- **Classification:** `PRIMARY` cloud security posture engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `CREDENTIAL_AWARE` & `ACTIVE_READ_ONLY`. Reads cloud configurations using read-only IAM credentials.

### 5. Supported CyberAssess Profiles
- `INFRA_ONLY`, `FULL_STACK`.

### 6. Supported Target Types
- `CLOUD_ACCOUNT`, `KUBERNETES_CLUSTER`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Prowler `4.1.0` (Exact PyPI Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "4.1.0"`.
- **Version Detection:** `prowler -v` -> Regex `([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `PACKAGE_MANAGER_MODE` (Installed via `pip_installer.py`).

### 9. Supply-Chain Integrity & Provenance
- PyPI package verification in `requirements.txt`.

### 10. Required Permissions & Privileges
- Read-only cloud audit credentials (`SecurityAudit` or `ViewOnlyAccess` IAM policies).

### 11. Credential Requirements & Injection Method
- Ephemeral cloud audit tokens injected via environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`).

### 12. Workspace Requirements & Confinement
- `NOT APPLICABLE`

### 13. Network Requirements & Destination Binding Mechanism
- Outbound HTTPS access to cloud provider management APIs (AWS, Azure, GCP).

### 14. Safety Policy & Bounded Probing
- Read-only API queries strictly enforced; zero state-changing or resource modifying calls.

### 15. Rate Limit vs Timing Profile
- Bounded to cloud provider API rate limits.

### 16. Concurrency Policy
- Single subprocess instance.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 120.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 1024 MB. Max stdout: 10 MB.

### 19. Invocation Contract
```text
Executable: <resolved_python_path> -m prowler
Command Line: prowler aws -M json-asff --output-filename <temp_output_path> --quiet
Stdout: Diagnostic logs
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `aws`, `azure`, `gcp`, `kubernetes`, `-M json-asff`, `--output-filename <path>`, `--quiet`, `--services <services>`, `--compliance <compliance>`.

### 21. Forbidden Arguments
- Any destructive or mutating flags.

### 22. Input Schema
- Validated cloud account target with scoped read-only credentials.

### 23. Output Format
- AWS Security Finding Format (ASFF) JSON report.

### 24. Output Schema & Error Handling
- **Valid Schema:** `Findings[].Title`, `Findings[].Severity.Label`, `Findings[].Compliance.Status`, `Findings[].Remediation.Recommendation.Text`.
- **Malformed JSON:** Emits `PARSER_ERROR` and falls back to native posture checks.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (Success), `Non-zero` (Auth error or API failure).
- **CyberAssess Normalized Execution States:**
  - Exit `0` with compliance findings -> `COMPLETED_WITH_FINDINGS`
  - Exit `0` with 100% compliance -> `COMPLETED_NO_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native posture checks.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native Terraform and Cloud posture checks.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native engine audits static manifests; lacks live multi-cloud API queries across live AWS/Azure accounts.

### 28. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Injected temporary credentials wiped from process memory; report files deleted.

### 30. Parser Specification
- Parses ASFF JSON, extracts failed compliance controls, maps to `Finding` models.

### 31. Finding Normalization
- Cloud Posture Failure -> Check ID `IAC-CLOUD-001`, Severity from ASFF, CWE-284.

### 32. Severity Mapping
- `CRITICAL` -> `Severity.CRITICAL` (9.8)
- `HIGH` -> `Severity.HIGH` (7.5)
- `MEDIUM` -> `Severity.MEDIUM` (5.3)
- `LOW` -> `Severity.LOW` (3.1)

### 33. Taxonomy Mapping
- `CWE-284`, `CWE-732`, `OWASP A05:2021`, `NIST SP 800-53: AC-3, AC-6, IA-2`.

### 34. Evidence Mapping & Cryptographic Hashing
- Cloud resource ARN, region, failed check ID, remediation text, evidence hash.

### 35. Secret Handling & Masking
- Sanitizes cloud account IDs and access keys in stored evidence.

### 36. Correlation Strategy
- Grouped by cloud resource identifier across scan sessions.

### 37. Validation Role
- `PRIMARY` cloud posture compliance authority.

### 38. Reproducibility Record
- Records Prowler version, cloud account ID, benchmark version, and finding count.

### 39. Update & Upgrade Policy
- Pip package lockfile management.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestProwlerAdapter` passing.
- **Capability Taxonomy:**
  - AWS CIS Benchmarks: `SUPPORTED`
  - Azure / GCP CIS Benchmarks: `LIMITED`
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/prowler_adapter.py`).

---

## TOOL 20: Kube-Bench

### 1. Identity
- **Tool ID:** `TOOL-KUBE-BENCH`
- **Display Name:** Kube-Bench
- **Upstream Project:** Aqua Security (https://github.com/aquasecurity/kube-bench)
- **Security Domain:** Kubernetes CIS Benchmark Auditing
- **CyberAssess Role:** `SPECIALIZED`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/kubebench_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Verifies whether a Kubernetes cluster is configured securely according to the CIS Kubernetes Benchmark standards.
- **What It Detects:** Insecure kubelet parameters, unencrypted etcd communication, anonymous authentication enabled on API server, missing RBAC policies.
- **What It Does NOT Detect:** Web application bugs, source code vulnerabilities.
- **Why Present:** Authoritative CIS Kubernetes benchmark compliance checker.

### 3. Role
- **Classification:** `SPECIALIZED` Kubernetes compliance engine.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `PRIVILEGED` & `CODE_ANALYSIS`. Requires read access to `/etc/kubernetes/` configuration files in cluster mode.

### 5. Supported CyberAssess Profiles
- `INFRA_ONLY`, `FULL_STACK`.

### 6. Supported Target Types
- `KUBERNETES_CLUSTER`, `LOCAL_PATH` (Manifest mode).

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Kube-Bench `v0.7.0` (Exact GitHub Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "v0.7.0"`.
- **Version Detection:** `kube-bench version` -> Regex `v?([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `DIRECT_ARTIFACT_MODE` (Standalone GitHub release binary downloaded via `github_release_installer.py`).

### 9. Supply-Chain Integrity & Provenance
- Verified in `PINNED_TOOL_MANIFEST`.

### 10. Required Permissions & Privileges
- Read-only access to Kubernetes cluster configuration files (`/etc/kubernetes/`) or manifest directory.

### 11. Credential Requirements & Injection Method
- `NOT APPLICABLE` in manifest mode; standard read-only kubeconfig in cluster mode.

### 12. Workspace Requirements & Confinement
- Server-derived authorized workspace jail.

### 13. Network Requirements & Destination Binding Mechanism
- Offline in manifest mode; local cluster API access in in-cluster mode.

### 14. Safety Policy & Bounded Probing
- Read-only configuration auditing; zero pod execution.

### 15. Rate Limit vs Timing Profile
- `NOT APPLICABLE`

### 16. Concurrency Policy
- Single subprocess instance.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 256 MB.

### 19. Invocation Contract
```text
Executable: <resolved_kube_bench_path>
Command Line: kube-bench --json
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `--json`, `--config-dir=<path>`, `--benchmark=<version>`, `--targets=master,node,etcd`.

### 21. Forbidden Arguments
- Root execution wrappers outside container sandbox.

### 22. Input Schema
- Validated Kubernetes manifest path or cluster context.

### 23. Output Format
- Kube-bench JSON schema.

### 24. Output Schema & Error Handling
- **Valid Schema:** `Controls[].tests[].results[].test_number`, `test_desc`, `status`, `remediation`.
- **Malformed JSON:** Emits `PARSER_ERROR` and falls back to native manifest auditor.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (Success), `Non-zero` (Error).
- **CyberAssess Normalized Execution States:**
  - Exit `0` with CIS failures -> `COMPLETED_WITH_FINDINGS`
  - Exit `0` with 100% pass -> `COMPLETED_NO_FINDINGS`
  - Exit non-zero -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native K8s manifest auditor.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native Kubernetes YAML manifest auditor.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native auditor analyzes static Pod/Deployment manifests; lacks CIS benchmark checks for master node services (apiserver, etcd, kubelet).

### 28. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Descriptors closed on exit.

### 30. Parser Specification
- Parses JSON `Controls[].tests[].results[]`, filters `status: "FAIL"`, maps to `Finding` models.

### 31. Finding Normalization
- Kubernetes CIS Benchmark Failure -> Check ID `IAC-K8S-002`, Severity `HIGH`/`MEDIUM`, CWE-284.

### 32. Severity Mapping
- `FAIL` on Master/API Server -> `Severity.HIGH` (7.5)
- `FAIL` on Node/Kubelet -> `Severity.MEDIUM` (5.3)
- `WARN` -> `Severity.LOW` (3.1)

### 33. Taxonomy Mapping
- `CWE-284`, `OWASP A05:2021`, `NIST SP 800-53: AC-3, CM-7`.

### 34. Evidence Mapping & Cryptographic Hashing
- Test number, test description, remediation string, evidence hash.

### 35. Secret Handling & Masking
- Masks any cert paths or tokens in test descriptions.

### 36. Correlation Strategy
- Clustered with Checkov K8s findings.

### 37. Validation Role
- `SPECIALIZED` Kubernetes CIS benchmark authority.

### 38. Reproducibility Record
- Records Kube-bench version, CIS benchmark version, and failed test count.

### 39. Update & Upgrade Policy
- Manifest digest updates.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestKubeBenchAdapter` passing.
- **Capability Taxonomy:**
  - Manifest Mode CIS Audit: `SUPPORTED`
  - In-Cluster Master/Node Audit: `LIMITED` (Requires node filesystem access)
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/kubebench_adapter.py`).

---

## TOOL 21: Dockle

### 1. Identity
- **Tool ID:** `TOOL-DOCKLE`
- **Display Name:** Dockle
- **Upstream Project:** GoodWithTech (https://github.com/goodwithtech/dockle)
- **Security Domain:** Container Image Hardening & CIS Docker
- **CyberAssess Role:** `SPECIALIZED`
- **Evidence Basis:** `[REPOSITORY_VERIFIED]` (`backend/app/adapters/dockle_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Container image linter verifying compliance with CIS Docker Benchmarks, best practices, and security hardening rules.
- **What It Detects:** Container processes running as root (`CIS-DI-0001`), hardcoded secrets/passwords in image layers (`CIS-DI-0005`), unneeded setuid/setgid permissions, missing Content Trust.
- **What It Does NOT Detect:** Dynamic web injection bugs, network port exposure.
- **Why Present:** High-precision container image hardening auditor for DevSecOps build pipelines.

### 3. Role
- **Classification:** `SPECIALIZED` container image hardening linter.

### 4. Security Classification
- `[UPSTREAM_VERIFIED]` `SUPPLY_CHAIN` & `CODE_ANALYSIS`. Inspects container image layers.

### 5. Supported CyberAssess Profiles
- `INFRA_CONTAINER`, `INFRA_ONLY`, `FULL_STACK`.

### 6. Supported Target Types
- `CONTAINER_IMAGE`, `DOCKERFILE`.

### 7. Upstream Version Policy
- **Exact Pinned Version:** `[CYBERASSESS_REQUIRED]` Dockle `v0.4.14` (Exact GitHub Release).
- **Version Enforcement:** Runtime probe checks `actual_version == "0.4.14"`.
- **Version Detection:** `dockle -v` -> Regex `version:\s*([0-9\.]+)`

### 8. Artifact / Installation Method & Supply-Chain Trust Mode
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `DIRECT_ARTIFACT_MODE` (Standalone GitHub release binary downloaded via `github_release_installer.py`).

### 9. Supply-Chain Integrity & Provenance
- `windows_amd64`: `fca8987ec89da3b764b8bb26c3674681467ea309db8935c1ba9c0a373b9e4a8b`
- `linux_amd64`: `64d0a3ec74f63cbb2f97f740a6b98686fba7fa01f5c6adbc81c81ef4554b5ec9`

### 10. Required Permissions & Privileges
- Read-only access to local Docker daemon or image tarball.

### 11. Credential Requirements & Injection Method
- `NOT APPLICABLE` for local images.

### 12. Workspace Requirements & Confinement
- Server-derived authorized workspace jail.

### 13. Network Requirements & Destination Binding Mechanism
- 100% offline local image inspection.

### 14. Safety Policy & Bounded Probing
- Static image layer inspection; zero container execution.

### 15. Rate Limit vs Timing Profile
- `NOT APPLICABLE`

### 16. Concurrency Policy
- Single subprocess instance.

### 17. Timeout Policy
- `[DESIGN_DECISION]` Startup: 5.0s. Execution: 60.0s.

### 18. Resource Limits
- `[DESIGN_DECISION]` Max memory: 512 MB.

### 19. Invocation Contract
```text
Executable: <resolved_dockle_path>
Command Line: dockle -f json <image_name>
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 20. Allowed Arguments
- `-f json`, `--exit-code 0`, `--ignore <codes>`, `<image_name>`.

### 21. Forbidden Arguments
- Uncontrolled remote socket execution.

### 22. Input Schema
- Validated container image name or archive path.

### 23. Output Format
- Dockle JSON report.

### 24. Output Schema & Error Handling
- **Valid Schema:** `details[].code`, `details[].title`, `details[].level`, `details[].alerts[]`.
- **Malformed JSON:** Emits `PARSER_ERROR` and falls back to native Dockerfile linter.

### 25. Exit Code Semantics
- **Upstream Exit Codes:** `0` (No fatal issues), `1` (Issues found), `Non-zero` (Daemon/image error).
- **CyberAssess Normalized Execution States:**
  - Exit `0` -> `COMPLETED_NO_FINDINGS`
  - Findings parsed -> `COMPLETED_WITH_FINDINGS`
  - Fatal error -> `TOOL_EXECUTION_FAILED`

### 26. Failure Semantics & Coverage Impact
- Failure sets `COVERAGE_DEGRADED` and activates native Dockerfile linter.

### 27. Fallback Coverage Level & Coverage Loss
- **Fallback Engine:** Native Dockerfile security linter.
- **Coverage Level:** `LIMITED` (Partial Baseline Coverage).
- **Coverage Loss:** Native linter inspects `Dockerfile` syntax; cannot inspect compiled multi-layer binary image tarballs.

### 28. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 29. Cleanup Policy
- Descriptors closed on exit.

### 30. Parser Specification
- Parses JSON `details[]`, extracts CIS Docker codes (`CIS-DI-0001` through `CIS-DI-0010`), maps to `Finding` models.

### 31. Finding Normalization
- `CIS-DI-0001` (Root User) -> `IAC-DOCKER-001` (CWE-250), Severity `HIGH`, CVSS 7.5
- `CIS-DI-0005` (Secret in Image) -> `IAC-DOCKER-002` (CWE-522), Severity `CRITICAL`, CVSS 9.0

### 32. Severity Mapping
- `FATAL` -> `Severity.CRITICAL` (9.0)
- `WARN` -> `Severity.HIGH` (7.5)
- `INFO` -> `Severity.LOW` (3.1)

### 33. Taxonomy Mapping
- `CWE-250`, `CWE-522`, `OWASP A05:2021`, `NIST SP 800-53: AC-6, IA-2`.

### 34. Evidence Mapping & Cryptographic Hashing
- CIS code, alert description, image layer hash, evidence hash.

### 35. Secret Handling & Masking
- Masks any secret tokens detected in image layer history.

### 36. Correlation Strategy
- Clustered with Trivy and Checkov Dockerfile findings.

### 37. Validation Role
- `SPECIALIZED` container image hardening authority.

### 38. Reproducibility Record
- Records Dockle version, image digest, and alert count.

### 39. Update & Upgrade Policy
- Manifest digest updates.

### 40. Deprecation Policy
- Active core tool.

### 41. Required Tests & Verification Status
- `[REPOSITORY_VERIFIED]` `tests/test_adapters.py::TestDockleAdapter` passing.
- **Capability Taxonomy:**
  - CIS Docker Image Hardening: `SUPPORTED`
  - Dockerfile Static Linting: `SUPPORTED`
- **Verification Status:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/dockle_adapter.py`).

---

# Part III: Verification, Test Traceability & Assurance Matrix

## 1. Tool-to-Contract Traceability Matrix

| Tool ID | Display Name | Security Class | Trust Mode | Role | Primary Check IDs | Test Suite Reference | Upstream Project |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `TOOL-NMAP` | Nmap | `ACTIVE_INTRUSIVE` | `PACKAGE_MANAGER_MODE` | `PRIMARY` | `NET-PORT-001/2`, `NET-SVC-001` | `tests/test_adapters.py::TestNmapAdapter` | Insecure.Org |
| `TOOL-SSLYZE` | SSLyze | `ACTIVE_READ_ONLY` | `PACKAGE_MANAGER_MODE` | `PRIMARY` | `NET-TLS-001/2/3` | `tests/test_adapters.py::TestSslyzeAdapter` | Nabla C0d3 |
| `TOOL-SUBFINDER` | Subfinder | `PASSIVE` | `DIRECT_ARTIFACT_MODE` | `PRIMARY` | `NET-OSINT-001` | `tests/test_adapters.py::TestSubfinderAdapter` | ProjectDiscovery |
| `TOOL-HTTPX` | httpx | `ACTIVE_READ_ONLY` | `DIRECT_ARTIFACT_MODE` | `VALIDATION` | `NET-HTTP-001` | `tests/test_adapters.py::TestHttpxAdapter` | ProjectDiscovery |
| `TOOL-NUCLEI` | Nuclei | `ACTIVE_INTRUSIVE` | `DIRECT_ARTIFACT_MODE` | `PRIMARY` | `DAST-INJ-001`, `DAST-EXP-001` | `tests/test_adapters.py::TestNucleiAdapter` | ProjectDiscovery |
| `TOOL-FFUF` | FFuF | `ACTIVE_INTRUSIVE` | `DIRECT_ARTIFACT_MODE` | `SPECIALIZED` | `DAST-EXP-001`, `DAST-PARAM-001` | `tests/test_adapters.py::TestFfufAdapter` | FFuF |
| `TOOL-KATANA` | Katana | `ACTIVE_READ_ONLY` | `DIRECT_ARTIFACT_MODE` | `PRIMARY` | `DAST-CRAWL-001` | `tests/test_adapters.py::TestKatanaAdapter` | ProjectDiscovery |
| `TOOL-SCHEMATHESIS` | Schemathesis | `STATE_CHANGING` | `PACKAGE_MANAGER_MODE` | `SPECIALIZED` | `DAST-API-003` | `tests/test_adapters.py::TestSchemathesisAdapter` | Schemathesis |
| `TOOL-SEMGREP` | Semgrep | `CODE_ANALYSIS` | `PACKAGE_MANAGER_MODE` | `PRIMARY` | `SAST-INJ-001`, `SAST-CMD-001` | `tests/test_adapters.py::TestSemgrepAdapter` | Semgrep Inc. |
| `TOOL-BANDIT` | Bandit | `CODE_ANALYSIS` | `PACKAGE_MANAGER_MODE` | `SPECIALIZED` | `SAST-CMD-001`, `SAST-CRYP-001` | `tests/test_adapters.py::TestBanditAdapter` | PyCQA |
| `TOOL-GITLEAKS` | Gitleaks | `CREDENTIAL_AWARE` | `DIRECT_ARTIFACT_MODE` | `PRIMARY` | `SAST-SEC-001` | `tests/test_adapters.py::TestGitleaksAdapter` | Gitleaks |
| `TOOL-TRUFFLEHOG` | TruffleHog | `CREDENTIAL_AWARE` | `DIRECT_ARTIFACT_MODE` | `VALIDATION` | `SAST-SEC-001` | `tests/test_adapters.py::TestTruffleHogAdapter` | Truffle Security |
| `TOOL-RETIREJS` | Retire.js | `SUPPLY_CHAIN` | `PACKAGE_MANAGER_MODE` | `SPECIALIZED` | `SAST-DEP-001` | `tests/test_adapters.py::TestRetireJSAdapter` | Retire.js |
| `TOOL-TRIVY` | Trivy | `SUPPLY_CHAIN` | `DIRECT_ARTIFACT_MODE` | `PRIMARY` | `SAST-DEP-001`, `IAC-DOCKER-001` | `tests/test_adapters.py::TestTrivyAdapter` | Aqua Security |
| `TOOL-GRYPE` | Grype | `SUPPLY_CHAIN` | `DIRECT_ARTIFACT_MODE` | `VALIDATION` | `SAST-DEP-001` | `tests/test_adapters.py::TestGrypeAdapter` | Anchore |
| `TOOL-SYFT` | Syft | `SUPPLY_CHAIN` | `DIRECT_ARTIFACT_MODE` | `PRIMARY` | `SAST-SBOM-001` | `tests/test_adapters.py::TestSyftAdapter` | Anchore |
| `TOOL-OSV-SCANNER` | OSV-Scanner | `SUPPLY_CHAIN` | `DIRECT_ARTIFACT_MODE` | `SPECIALIZED` | `SAST-DEP-001` | `tests/test_adapters.py::TestOSVScannerAdapter` | Google |
| `TOOL-CHECKOV` | Checkov | `CODE_ANALYSIS` | `PACKAGE_MANAGER_MODE` | `PRIMARY` | `IAC-TF-001/2`, `IAC-DOCKER-001` | `tests/test_adapters.py::TestCheckovAdapter` | Prisma Cloud |
| `TOOL-PROWLER` | Prowler | `CREDENTIAL_AWARE` | `PACKAGE_MANAGER_MODE` | `PRIMARY` | `IAC-CLOUD-001` | `tests/test_adapters.py::TestProwlerAdapter` | Prowler |
| `TOOL-KUBE-BENCH` | Kube-Bench | `PRIVILEGED` | `DIRECT_ARTIFACT_MODE` | `SPECIALIZED` | `IAC-K8S-002` | `tests/test_adapters.py::TestKubeBenchAdapter` | Aqua Security |
| `TOOL-DOCKLE` | Dockle | `SUPPLY_CHAIN` | `DIRECT_ARTIFACT_MODE` | `SPECIALIZED` | `IAC-DOCKER-001/2` | `tests/test_adapters.py::TestDockleAdapter` | GoodWithTech |

---

## 2. Mandatory Test Coverage Invariant

Every tool adapter MUST have unit and integration test coverage in `tests/test_adapters.py` proving:
1. Deterministic version extraction matching exact approved version string.
2. Standard output parsing (JSON / XML / Line Stream).
3. Finding normalization to canonical check IDs, CWE, and NIST controls.
4. Mandatory multi-stage secret masking.
5. Explicit `COVERAGE_DEGRADED` telemetry emission and permanent failure event recording.
6. Execution of native fallback engines with partial baseline coverage guarantees.
