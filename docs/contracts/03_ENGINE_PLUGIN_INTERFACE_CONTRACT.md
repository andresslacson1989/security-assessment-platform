# Contract 03: Engine Plugin Interface, Execution Governance & Tool Supply Chain Contract

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 14.3.0 (Execution Plane Governance, 26-Tool Fleet Adapter Specifications, ProcessSupervisor Tree Termination & Sandbox Isolation)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Engine Interfaces, Tool Adapters, Binary Supply Chain Verification, Quarantine Lifecycle & Worker Sandbox Controls  

---

## 1. Engine & Tool Adapter Abstraction Architecture

All scanning engines implement the `BaseEngine` interface, while external security tools subclass `BaseToolAdapter`:

```python
class BaseEngine(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_progress: Callable[[int, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
        **kwargs: Any,
    ) -> List[Finding]: ...

class BaseToolAdapter(ABC):
    @property
    @abstractmethod
    def tool_name(self) -> str: ...

    def resolve_binary_path(self, custom_path: Optional[str] = None) -> Optional[str]:
        """Resolves binary from custom path, backend/bin/ directory, or system PATH."""
        ...

    @abstractmethod
    async def is_available(self, custom_path: Optional[str] = None) -> bool: ...

    @abstractmethod
    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]: ...

    @abstractmethod
    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
        **kwargs: Any,
    ) -> List[Finding]: ...
```

---

## 2. Tool Supply Chain Security & Verification Pipeline

All external tools downloaded by the platform MUST follow an unyielding cryptographic verification pipeline. Unpinned or unverifiable tools are strictly prohibited in production.

### 2.1 Manifest Requirements & Registry Parity
Every tool manifest entry MUST define:
- `tool_name`: Canonical identifier (e.g., `nuclei`, `trivy`, `semgrep`, `metasploit`, `sqlmap`, `amass`, `hydra`).
- `version`: Exact pinned semver release (e.g., `v3.2.0`).
- `release_tag`: Exact immutable GitHub release tag (`/releases/tags/{version}`).
- `platform`: `windows`, `linux`, `darwin`.
- `architecture`: `amd64`, `arm64`.
- `asset_name`: Exact archive filename.
- `sha256`: Authentic 64-character lowercase hexadecimal cryptographic SHA-256 checksum.
- `source_build`: For an explicitly approved `SOURCE_BUILD_MODE` exception, the immutable source archive,
  compiler/toolchain archive, build inputs, and resulting executable MUST each be pinned and verified before
  promotion. This mode MUST NOT replace an available direct release artifact.

**Registry Parity Invariant:**
$$\text{Tool Registry} \equiv \text{Installer Registry} \equiv \text{Integrity Manifest} \equiv \text{Supported 26 Tools}$$
Any disparity in supported tool registries fails CI and startup integrity gates.

### 2.2 Quarantine & Atomic Promotion Lifecycle
Binary installation must follow this strict 8-step lifecycle:
```text
1. DOWNLOAD: Download archive from immutable release URL to a temporary quarantine directory.
2. HASH CHECK: Compute SHA-256 hash of downloaded bytes and compare against manifest. Mismatch aborts immediately.
3. ARCHIVE AUDIT: Inspect archive contents for directory traversal (ZipSlip / TarSlip). Reject malicious paths.
4. EXTRACTION: Extract executable into isolated quarantine sandbox.
5. VALIDATION: Execute binary `--version` check in a sandbox to ensure binary integrity and functionality.
6. ATOMIC PROMOTION: Atomically move verified executable to production `backend/bin/` destination.
7. AUDIT LOGGING: Emit privileged `TOOL_INSTALL_COMPLETED` audit event.
8. REGISTRATION: Register active tool status with the platform adapter registry. Capability registration and backend-owned toolbox/system capability snapshots are observational only; cached status MUST NOT replace live pre-launch executable integrity and exact-version verification.
```

### 1.1 Full-Capability Automation and Authorization Boundary

Automation MUST orchestrate the upstream tool; it MUST NOT silently replace, cripple, or permanently remove upstream capabilities. The complete supported command, module, protocol, and option surface remains available to an authorized execution policy. Safety is enforced at the CyberAssess control plane and process-launch boundary through authorization, target binding, resource governance, and auditability—not by misrepresenting a reduced tool as the full tool.

Each automated request MUST be represented as a typed, server-validated execution request containing the tenant, project, asset, immutable `ValidatedTarget`, tool identity, exact requested operation, policy version, authorization decision, and resource budget. The adapter MUST construct the final argument vector without shell interpolation. Client input MUST NOT directly provide an executable path, shell string, output path, credential location, or unvalidated destination.

The platform MUST distinguish `CAPABILITY_AVAILABLE`, `EXECUTION_AUTHORIZED`, `AUTHORIZATION_REQUIRED`, `EXECUTION_BLOCKED`, and `NATIVE_ENGINE_READY`. A default assessment profile MAY select conservative operations, but that default MUST NOT be represented as a permanent capability restriction. Higher-impact operations require an explicit policy decision, appropriate tenant authorization, isolated worker permissions, bounded resources, and an auditable decision record. Installation or capability detection alone MUST never authorize execution.

### 1.1.1 Normative state crosswalk and operation policy

The canonical state domains are: capability (`AVAILABLE`, `LIMITED`, `DEFERRED`,
`HOST_UNAVAILABLE`, `NOT_SUPPORTED`), assurance (`VERIFIED`, `UNVERIFIED`,
`FAILED`, `EXPIRED`), authorization (`PENDING`, `APPROVED`, `REVOKED`,
`EXPIRED`, `DENIED`), execution (`REQUESTED`, `STARTING`, `RUNNING`,
`SUCCEEDED`, `PARTIAL_RESULTS_WITH_WARNING`, `FAILED`, `TIMED_OUT`,
`CANCELLED`, `EXECUTION_BLOCKED`), and coverage (`COMPLETE`, `PARTIAL`,
`UNAVAILABLE`). `NATIVE_ENGINE_READY` is a capability/engine readiness value;
`CAPABILITY_AVAILABLE` and `EXECUTION_AUTHORIZED` are compatibility aliases
that MUST map to `AVAILABLE` and `APPROVED` respectively. `NOT_SUPPORTED`
means permanently unsupported by the platform only; it MUST NOT mean unapproved,
uninstalled, deferred, unverified, or unavailable on the current host.

The authoritative operation matrix is versioned with the policy. Metasploit
module/payload/session/persistence/post-exploitation operations, sqlmap
extraction/takeover/file/OS-shell options, and Hydra protocol/dictionary and
credential-resilience operations are `ELEVATED_APPROVAL_REQUIRED` and may run
after one authenticated administrator confirms the explicit warning that the
target is owned or authorized. The session-bound approval remains valid only
while that administrator session is authenticated and not idle-expired, and is
revoked by logout, session expiry, reauthentication failure, explicit revoke,
target-seal change, operation change, or budget exhaustion. The worker must be
isolated, cancellable, auditable, and bound to the approved tenant/project/
asset. No upstream feature is removed; the policy controls authority to invoke.

Operations that bypass target/tenant authorization, execute a tampered binary,
escape the approved destination, evade isolation or budgets, expose credentials,
suppress audit, or continue after revocation are `PERMANENTLY_BLOCKED`.

The machine-readable operation-policy artifact is
`backend/app/core/tool_operation_policy.py`. It is versioned independently from
the contract as `policy_revision` and each row contains `tool_id`,
`operation_family`, `option_or_module_class`, `capability_state`,
`default_profile_behavior`, `approval_level`, `worker_class`, `target_rules`,
`credential_requirements`, `resource_budget`, `account_impact_budget`,
`stop_conditions`, `evidence_requirements`, and `audit_requirements`. A policy
revision change invalidates prior approvals. No adapter may define a private
operation policy.

### 1.1.2 Canonical state crosswalk

`CAPABILITY_AVAILABLE` maps to capability `AVAILABLE`; `NATIVE_ENGINE_READY`
maps to capability `AVAILABLE` plus assurance `VERIFIED`; `SUPPORTED` is a
legacy capability alias for `AVAILABLE`; `LIMITED`, `DEFERRED`,
`HOST_UNAVAILABLE`, and `UNVERIFIED` retain their capability or assurance
domain. `ELEVATED_APPROVAL_REQUIRED` is an operation-policy classification,
not an execution state. `PERMANENTLY_BLOCKED` is a policy rejection reason and
maps to authorization `DENIED` plus execution `EXECUTION_BLOCKED`.

Contract 09 outcomes map as follows: `COMPLETED_WITH_FINDINGS` becomes
execution `SUCCEEDED` with coverage `COMPLETE`; `COMPLETED_NO_FINDINGS` becomes
the same execution state with zero findings; `TOOL_EXECUTION_FAILED` maps to
`FAILED`; `EXECUTION_TIMED_OUT` maps to `TIMED_OUT`; `EXECUTION_CANCELLED`
maps to `CANCELLED`; and any valid output with incomplete coverage maps to
`PARTIAL_RESULTS_WITH_WARNING` plus coverage `PARTIAL`. `UNVERIFIED` is never
an execution result; it is assurance state and blocks assured launch.

Authorization `APPROVED` maps to execution `AUTHORIZED`; `DENIED`,
`REVOKED`, `EXPIRED`, and `PERMANENTLY_BLOCKED` map to execution
`EXECUTION_BLOCKED`. Assurance `UNVERIFIED`, `FAILED`, and `EXPIRED` deny
launch and produce the corresponding blocked reason. A successful execution
with partial coverage MUST be serialized as `PARTIAL_RESULTS_WITH_WARNING`.
`ELEVATED_APPROVAL_REQUIRED` is only an operation-policy classification, and
`PERMANENTLY_BLOCKED` is only a rejection reason, not an additional state
domain.

### 1.2 Cross-Cutting Execution Boundary Controls

Every external process launch, including direct callers of `ProcessSupervisor`, MUST pass through one deny-by-default environment builder. Ambient environment merging is prohibited. Each operation declares an explicit environment allowlist; secret-like variables, loader variables (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`), interpreter injection variables (`PYTHONPATH`, `PYTHONHOME`, `NODE_OPTIONS`), arbitrary API/auth tokens, and ambient proxy variables are excluded unless a separately authorized, tool-specific policy injects an exact value. `SCANNER_EGRESS_PROXY` may be translated only by the egress policy and must never inherit arbitrary proxy settings.

All output boundaries MUST use one mandatory sanitizer before persistence, logging, API response, SSE publication, historical replay, export, or exception rendering. The sanitizer must recursively process strings, mappings, sequences, Pydantic models, exception text, finding evidence, comments, and telemetry. It must mask API keys, JWTs, bearer tokens, passwords, connection strings, and private-key material while preserving a deterministic evidence digest of the sanitized representation. No adapter, orchestrator, API route, or exporter may bypass this boundary.

Target binding MUST preserve the complete canonical IP value, including IPv6, without colon-based string splitting. Bracketed IPv6 URL syntax, selected destinations, Host/SNI values, target identity, integrity seals, native HTTP transports, and CLI adapters must all derive from the same validated target decision. Internal targets require a persisted, narrowly scoped authorization decision bound to tenant, actor, asset, target seal, allowed destination, purpose, and expiry; downstream engines must revalidate that decision and may not infer it from a boolean request flag.

`ValidatedTarget` operational immutability includes nested addresses, scope, authorization context, and any mutable metadata. Nested structures MUST be immutable or defensively copied and mutation attempts MUST fail or be detected before execution. Database relationships for tenant-owned findings, occurrences, scans, and assets MUST enforce referential and tenant integrity transactionally, subject to an explicitly governed retention/purge policy.

### 2.2.1 Managed Package-Adapter Resolution
For every adapter backed by `PACKAGE_MANAGER_MODE`, the shared adapter resolver MUST search the installer-owned per-tool virtual environment before the active application environment, system `PATH`, or platform auto-discovery paths. Capability discovery and runtime execution MUST resolve the same canonical managed executable path. An explicit custom path may be used for diagnostics, but it MUST remain subject to the managed trust gate and MUST NOT be treated as enterprise-assured merely because it reports the approved version. A missing, inaccessible, or unverified managed environment MUST remain fail-closed and MUST expose the native fallback/degraded state.

Version probes that require a tool configuration file MUST use a server-selected, non-writing configuration path and MUST NOT depend on permissions or files in the service working directory.

### 2.2.2 Automated Installation Job Contract

Tool installation is a backend job, never a frontend side effect. It MUST require authenticated administrative authorization, a unique idempotency key, a per-tool installation lock, a bounded job deadline, and a durable audit trail. Login, page refresh, capability observation, scan creation, and anonymous requests MUST NOT start installation.

The installer MUST select an acquisition strategy from the approved manifest: verified direct artifact, approved verified source build, verified package-manager installation, or verified isolated language-package environment. The manifest MUST identify the exact tool, version, platform, architecture, acquisition URL or repository identity, archive/executable digests, signature or provenance evidence where available, build inputs, toolchain identity, installer version, and policy approval. Missing, conflicting, unverified, or platform-incompatible metadata MUST fail closed; no digest, URL, version, or provenance claim may be invented at implementation time.

The job lifecycle is: `REQUESTED` → `AUTHORIZED` → `ACQUIRING` → `QUARANTINED` → `ARCHIVE_VERIFIED` → `EXTRACTED` → `EXECUTABLE_VERIFIED` → `PROMOTED` → `REGISTERED`, with terminal states `FAILED`, `CANCELLED`, or `ROLLED_BACK`. Quarantine extraction MUST reject absolute paths, traversal, symlinks, hardlinks, duplicate entries, unexpected files, and architecture mismatches. Promotion MUST be atomic into the installer-owned managed path. Partial or failed jobs MUST leave no executable that can satisfy assured resolution.

After promotion, the installer MUST verify the exact executable path, executable SHA-256, version, supporting resource tree, and installation-record binding. The record MUST separately state `ARCHIVE_INTEGRITY_VERIFIED`, `EXECUTABLE_INTEGRITY_VERIFIED`, and `UPSTREAM_PROVENANCE_VERIFIED`; one claim MUST NOT be substituted for another. A successful installation invalidates observational caches and triggers one post-install live capability refresh, but does not authorize a scan or high-impact operation.

Metasploit and sqlmap MUST install their complete upstream distributions. Hydra MUST install its complete upstream protocol/module capability. GTFOBins/LOLBAS MUST use the reviewed, pinned native catalog and does not require a binary installer. Full capability is preserved; execution policy, target authorization, credentials, resource budgets, and process supervision govern use after installation.

### 2.2.3 Machine-readable supply-chain evidence

Each managed installation MUST produce a machine-readable evidence record before
promotion. Required fields are `verifier`, `verified_at`, `commit_or_image_digest`,
`tool_id`, `tool_version`, `platform`, `architecture`, `source_url_or_repository`,
`archive_sha256`, `executable_sha256`, `resource_tree_sha256`, `version_output`,
`signature_result`, `provenance_result`, `evidence_location`, and
`reverification_expires_at`. Source builds additionally record immutable source
identity, build inputs, toolchain identity, and reproducibility result.

Each field has an explicit state: `VERIFIED`, `UNVERIFIED`, `NOT_APPLICABLE`, or
`FAILED`. `UNVERIFIED` is not equivalent to success and cannot satisfy assured
execution where the field is required. Prose, a version string, or a mutable
sidecar alone is not supply-chain evidence. Records are tenant-independent
installation evidence, immutable after promotion, auditable, and reverified at
the declared expiry and at every assured process launch.

### 2.3 Strict Verification Invariants
- **No Silent Bypass:** If `expected_sha256` is missing or invalid, installation MUST FAIL CLOSED.
- **Approved source-build exceptions:** Trivy `v0.50.0` and Nmap `7.95` may use `SOURCE_BUILD_MODE` because
  their approved upstream source distributions are available while suitable direct release assets are not.
  Each build MUST use the immutable source identity, pinned build toolchain identity, verified build inputs,
  reproducible build controls, and a generated executable trust record declared in Contract 09. Exact runtime
  version and pre-launch integrity verification remain mandatory.
- **Dual-Mode and Direct Artifact Support:** In addition to the container `SOURCE_BUILD_MODE` exception, Nmap `7.95`
  supports portable `DIRECT_ARTIFACT_MODE` dynamic installation for supported Linux x86-64 host environments using the
  official Insecure.Org release package (`nmap-7.95-1.x86_64.rpm`). The installer strictly enforces SHA-256 archive
  verification, CPIO extraction boundary hardening (rejecting traversal sequences, absolute paths, symlinks, hardlinks,
  and duplicate entries), and deterministic cryptographic hash-binding of the runtime resource directory tree
  (`resources/nmap` containing NSE scripts and signatures) under the `RESOURCE_TREE_INTEGRITY_VERIFIED` claim.
- **Atomic Replacement:** Production executables are never overwritten in-place during download; promotion occurs only after 100% verification passes.

---

## 3. Worker Execution Sandboxing & Central Process Supervisor

External tool subprocesses must be executed and governed exclusively through the central `ProcessSupervisor`:

1. **`ProcessSupervisor` Responsibilities:**
   - Spawns child processes in isolated process groups (`creationflags=CREATE_NEW_PROCESS_GROUP` on Windows, `start_new_session=True` on POSIX).
   - Tracks active process trees (parent, children, grandchildren).
   - Enforces execution timeouts (`60.0s` default per tool, configurable up to `120.0s` for deep EASM).
   - Enforces maximum output buffers (10 MB) to prevent buffer exhaustion attacks.
   - On cancellation or timeout: recursively terminates the entire process tree without leaving orphaned zombie processes.
2. **Process Tree Cancellation Protocol:**
   - On Windows: `taskkill /F /T /PID <pid>` or Win32 Job Object tree termination.
   - On POSIX: Process group termination (`os.killpg(os.getpgid(proc.pid), signal.SIGKILL)`).
3. **Workspace Confinement:** All tool file operations must execute strictly within the server-derived workspace directory.

---

## 4. Comprehensive 26-Tool Fleet Execution & Parsing Specifications

### 4.1 Metasploit Framework (`MetasploitAdapter`)
- **Tool Binary:** `msfconsole`
- **Domain:** Exploit Verification & Auxiliary Assessment
- **Version Probing:** `msfconsole -v` -> Regex `Framework Version:\s*([0-9\.]+)`
- **Execution Command:**
  ```bash
  msfconsole -q -x "use auxiliary/scanner/ssl/openssl_heartbleed; set RHOSTS <target_host>; set RPORT <port>; run; exit"
  ```
- **Strict Non-Destructive Invariant:**
  - The complete upstream module and payload surface remains available through typed policy-gated requests.
  - The default unattended profile is limited to non-destructive auxiliary verification. Exploit modules, payload delivery, sessions, shells, persistence, and post-exploitation require explicit elevated authorization and an isolated execution context; they are not silently removed from the installed tool.
- **Output Parsing:** Regex capture on `[+]`, `[*]`, and `[-]` standard Metasploit logger tokens; extracts vulnerability confirmation and maps to `NET-TLS-001`, `NET-PORT-001`, or specific CVEs with `source_tool="metasploit"`.
- **Native Fallback:** Native Python TLS auditor, SSL socket probing, and HTTP header verification.

### 4.2 sqlmap (`SqlmapAdapter`)
- **Tool Binary:** `sqlmap` / `python sqlmap.py`
- **Domain:** Automated Web DAST SQL Injection Verification
- **Version Probing:** `sqlmap --version` -> Regex `sqlmap/([0-9\.]+)`
- **Execution Command:**
  ```bash
  sqlmap -u "<target_url>" --batch --banner --level=1 --risk=1 --timeout=15 --retries=1 --threads=2 --output-dir="<sandbox_tmp>"
  ```
- **Safety Invariant:**
  - The complete upstream sqlmap option surface remains available through typed policy-gated requests.
  - The default unattended profile uses `--batch`, `--risk=1`, `--level=1`, bounded timeout/retries/threads, and a server-derived output directory.
  - Data extraction, file read/write, OS shell, takeover, and equivalent high-impact options require explicit elevated authorization, a separately recorded policy decision, and a resource/target budget; they are not deleted from the tool installation.
- **Output Parsing:** Inspects `<sandbox_tmp>/log` and console stdout for identified DBMS technologies, backend web servers, parameter injection points, and confirms `DAST-INJ-001` with CVSS 9.8 and `source_tool="sqlmap"`.
- **Native Fallback:** Native AST/differential parameter fuzzer (`fuzz_sqli` boolean and time-based canaries).

### 4.3 OWASP Amass (`AmassAdapter`)
- **Tool Binary:** `amass`
- **Domain:** External Attack Surface Management & Subdomain Enumeration
- **Trust Mode:** `[CYBERASSESS_REQUIRED]` `DIRECT_ARTIFACT_MODE` using the pinned official v5.1.1 platform release archive; host/PATH installations remain diagnostic-only.
- **Version Verification:** `amass -version` MUST report exact version `5.1.1` before execution.
- **Version Probing:** `amass -version` -> Regex `v?([0-9\.]+)`
- **Execution Command:**
  ```bash
  amass enum -passive -d <target_domain> -json <output_file> -timeout 30
  ```
- **Output Parsing:** Streaming line-delimited JSON parsing of `<output_file>`:
  - Extracts the reported `name` (FQDN), `domain`, and `sources` fields.
  - Enriches untrusted `DiscoveredSubdomain` observations with `dns_status="UNRESOLVED"`; reported address data is not promoted to resolved or authorized target state.
- **Native Fallback:** Independent passive CT enrichment. Any later DNS resolution is a separate authorized stage and is not represented as Amass execution or fallback coverage.

### 4.4 THC-Hydra (`HydraAdapter`)
- **Tool Binary:** `hydra`
- **Domain:** Authentication Resilience & Password Policy Auditing
- **Version Probing:** `hydra -h` -> Regex `Hydra v([0-9\.]+)`
- **Execution Command:**
  ```bash
  hydra -L <top10_users_file> -P <top10_pass_file> <protocol>://<target_host>:<port> -t 2 -W 1 -f -b json -o <output_file>
  ```
- **Rate-Limiting & Safety Invariant:**
  - The complete upstream protocol, module, and dictionary capability remains available through explicitly authorized policy-gated requests.
  - The default unattended profile uses bounded concurrency and inter-request delays to reduce lockout and denial-of-service risk. Broader credential audits require explicit credential-audit authorization, tenant-scoped secret handoff, target-owner approval, and an auditable account-impact budget.
- **Output Parsing:** Parses JSON output records for successful credential pairs; emits `AUTH-STUFF-001` or `NET-PORT-001` with `source_tool="hydra"`.
- **Native Fallback:** Native Python HTTP/Auth form session validator and brute-force rate-limit header checker.

### 4.5 GTFOBins & LOLBAS Rule Engine (`GTFOBinsEngine`)
- **Domain:** Host & Container Privilege Escalation Auditing
- **Execution Mode:** Native Python Static & Host Rule Evaluator
- **Evaluation Mechanism:**
  - Evaluates discovered SUID/SGID binaries, `sudo -l` permissions, and container process configurations against the canonical GTFOBins executable catalog (`find`, `vim`, `nmap`, `awk`, `bash`, `more`, `less`, `python`, `perl`, `ruby`, `env`, `tar`, `zip`).
  - Matches binary functions: `sudo`, `suid`, `capabilities`, `file-read`, `file-write`, `reverse-shell`.
  - Emits `HOST-PRIV-001` (Dangerous SUID binary) or `HOST-SUDO-001` (Insecure NOPASSWD sudo rule) with `source_tool="gtfobins"`.

### 4.6 Nmap (`NmapAdapter`)
- **Tool Binary:** `nmap`
- **Domain:** Network Port Scanning & Service Fingerprinting
- **Trust Architecture:** Dual installation modes supported:
  - `SOURCE_BUILD_MODE` for the hardened Linux production image (compiled from pinned source archive `nmap-7.95.tar.bz2` with GCC toolchain).
  - `DIRECT_ARTIFACT_MODE` for standalone dynamic installation on supported Linux x86-64 environments (extracted from official `nmap-7.95-1.x86_64.rpm` with resource manifest hash-locking).
- **Resource Tree Integrity:** If the managed installation includes a supporting resource directory (`resources/nmap`), the adapter automatically passes `NMAPDIR` pointing to the verified directory tree, and pre-launch verification ensures all NSE scripts, signatures, and data files match their cryptographic SHA-256 hash manifest (`RESOURCE_TREE_INTEGRITY_VERIFIED`). Any modification, deletion, or injection of unexpected files causes pre-launch execution to fail closed.
- **Version Probing:** `nmap --version` -> Regex `Nmap version ([0-9\.]+)`
- **Execution Command:** `nmap -sV -sC --version-light -T4 -oX - <target_host>`
- **Output Parsing:** XML ElementTree parser extracting `<port>`, `<service>`, script results (`ssl-cert`, `http-title`), mapping to `NET-PORT-001`, `NET-PORT-002`, `NET-TLS-001` with `source_tool="nmap"`.
- **Native Fallback:** Native async socket port checker, banner grabber, and TLS auditor.

### 4.7 SSLyze (`SSLyzeAdapter`)
- **Tool Binary:** `sslyze`
- **Domain:** Deep TLS/SSL Protocol & Cipher Configuration
- **Execution Command:** `sslyze --json_out=- <target_host>:<port>`
- **Output Parsing:** JSON parsing of TLS 1.0/1.1 enablement, weak ciphers (RC4, 3DES, EXPORT), certificate expiration, mapping to `NET-TLS-001` and `NET-TLS-002`.
- **Native Fallback:** Native Python `ssl.SSLContext` protocol sweep.

### 4.8 Subfinder (`SubfinderAdapter`)
- **Tool Binary:** `subfinder`
- **Domain:** Passive Multi-Source Subdomain Enumeration
- **Execution Command:** `subfinder -d <authorized_root> -s crtsh -silent -json -timeout 10 -max-time 1`
- **Provider Boundary:** The governed baseline forces the public `crtsh` provider, excludes provider credentials and client-supplied provider selections, and does not claim all process egress is restricted to that provider without a separate egress control.
- **Output Parsing:** Line-delimited JSON extracting normalized subdomain observations and source attribution. No active A/AAAA/CNAME DNS resolution is performed by Subfinder; every discovery remains `UNRESOLVED` until a separate authorized stage.
- **Authorization Boundary:** A discovery is an untrusted candidate observation and does not create an inventory asset, `ValidatedTarget`, or active assessment authorization.
- **Native Fallback:** Native Certificate Transparency log auditor.

### 4.9 Httpx (`HttpxAdapter`)
- **Tool Binary:** `httpx`
- **Domain:** Fast HTTP Probing & Technology Detection
- **Execution Command:** `httpx -u <target_url> -silent -json -title -tech-detect -status-code`
- **Output Parsing:** JSON output parser mapping HTTP status, headers, and technologies.
- **Native Fallback:** Native `httpx` async client.

### 4.10 Nuclei (`NucleiAdapter`)
- **Tool Binary:** `nuclei`
- **Domain:** Automated Vulnerability & CVE Template Scanning
- **Execution Command:** `nuclei -u <target_url> -j -silent -tags cve,misconfig -severity low,medium,high,critical`
- **Output Parsing:** JSON line parser mapping `template-id`, `severity`, `cwe-id`, `reproduction_curl`.
- **Native Fallback:** Native DAST security check ruleset.

### 4.11 FFuF (`FFuFAdapter`)
- **Tool Binary:** `ffuf`
- **Domain:** Web Content, Directory & Parameter Fuzzing
- **Execution Command:** `ffuf -u <target_url>/FUZZ -w <wordlist> -mc 200,204,301,302,307,401,403 -o - -of json -t 5 -rate 10 -s`
- **Output Parsing:** JSON output parser identifying hidden routes and parameters.
- **Native Fallback:** Native BFS crawler with sitemap/robots parsing.

### 4.12 Katana (`KatanaAdapter`)
- **Tool Binary:** `katana`
- **Domain:** Headless SPA & Dynamic JavaScript Crawling
- **Execution Command:** `katana -u <target_url> -silent -json -d 3 -jc`
- **Output Parsing:** JSON stream extracting dynamic endpoints, forms, and JavaScript routes.
- **Native Fallback:** Native HTML DOM parser crawler.

### 4.13 Schemathesis (`SchemathesisAdapter`)
- **Tool Binary:** `schemathesis`
- **Domain:** Property-Based REST API & OpenAPI Contract Fuzzing
- **Execution Command:** `schemathesis run <openapi_url> --format=json`
- **Output Parsing:** JSON test runner output mapping 500 errors and schema non-compliance.
- **Native Fallback:** Native API inspector.

### 4.14 Semgrep (`SemgrepAdapter`)
- **Tool Binary:** `semgrep`
- **Domain:** Multi-Language AST Static Code Analysis
- **Execution Command:** `semgrep scan --config auto --json <repo_path>`
- **Output Parsing:** JSON parsing of `results[]`, mapping AST taint paths, code snippets, and lines to `Finding` objects.
- **Native Fallback:** Native Python AST taint analyzer.

### 4.15 Bandit (`BanditAdapter`)
- **Tool Binary:** `bandit`
- **Domain:** Python AST Security Linter
- **Execution Command:** `bandit -r <repo_path> -f json`
- **Output Parsing:** JSON results parser mapping AST issues (`B101` through `B703`).
- **Native Fallback:** Native Python AST visitor.

### 4.16 Gitleaks (`GitleaksAdapter`)
- **Tool Binary:** `gitleaks`
- **Domain:** Git Commit History Secret Scanning
- **Execution Command:** `gitleaks detect --source <repo_path> --report-format json --report-path <tmp>`
- **Output Parsing:** JSON findings parser extracting commits, files, lines, and redacted secrets.
- **Native Fallback:** Native Shannon entropy secret scanner.

### 4.17 TruffleHog (`TruffleHogAdapter`)
- **Tool Binary:** `trufflehog`
- **Domain:** Verified Live Secret & API Key Detection
- **Execution Command:** `trufflehog filesystem <repo_path> --json`
- **Output Parsing:** JSON stream parser extracting verified live credentials.
- **Native Fallback:** Native regex & entropy secret analyzer.

### 4.18 RetireJS (`RetireJSAdapter`)
- **Tool Binary:** `retire`
- **Domain:** Client-Side JavaScript Library Vulnerabilities
- **Execution Command:** `retire --path <repo_path> --outputformat json`
- **Output Parsing:** JSON report parser mapping vulnerable JS libraries and CVEs.
- **Native Fallback:** Native regex dependency auditor.

### 4.19 Trivy (`TrivyAdapter`)
- **Tool Binary:** `trivy`
- **Domain:** Container Image, File System & OS Package Vulnerabilities
- **Execution Command:** `trivy fs --format json <repo_path>`
- **Output Parsing:** JSON parsing of `Results[].Vulnerabilities[]` mapping CVEs and fix versions.
- **Native Fallback:** Native lockfile dependency auditor.

### 4.20 Syft (`SyftAdapter`)
- **Tool Binary:** `syft`
- **Domain:** Software Bill of Materials (SBOM) Generation
- **Execution Command:** `syft <repo_path> -o cyclonedx-json=<output_file>`
- **Output Parsing:** Generates standardized CycloneDX 1.5 and SPDX 2.3 SBOM packages.
- **Native Fallback:** Native CycloneDX exporter.

### 4.21 Grype (`GrypeAdapter`)
- **Tool Binary:** `grype`
- **Domain:** SBOM & Vulnerability Scanner
- **Execution Command:** `grype sbom:<sbom_path> -o json`
- **Output Parsing:** JSON results parser mapping package vulnerabilities.
- **Native Fallback:** Native CVE database matcher.

### 4.22 OSV-Scanner (`OSVScannerAdapter`)
- **Tool Binary:** `osv-scanner`
- **Domain:** Google Open Source Vulnerability Database Scanner
- **Execution Command:** `osv-scanner --json -r <repo_path>`
- **Output Parsing:** JSON results parser mapping package CVEs and GHSA advisories.
- **Native Fallback:** Native lockfile auditor.

### 4.23 Checkov (`CheckovAdapter`)
- **Tool Binary:** `checkov`
- **Domain:** Infrastructure-as-Code (Terraform, CloudFormation, K8s, Dockerfile)
- **Execution Command:** `checkov -d <repo_path> -o json`
- **Output Parsing:** JSON results parser mapping failed policies to `IAC-*` checks.
- **Native Fallback:** Native Dockerfile, K8s, and Terraform AST linters.

### 4.24 Prowler (`ProwlerAdapter`)
- **Tool Binary:** `prowler`
- **Domain:** Multi-Cloud (AWS, Azure, GCP) CIS Benchmark Auditor
- **Execution Command:** `prowler <cloud_provider> -M json-asff`
- **Output Parsing:** JSON ASFF parser mapping CIS Benchmark non-compliance.
- **Native Fallback:** Native Terraform policy auditor.

### 4.25 Kube-bench (`KubeBenchAdapter`)
- **Tool Binary:** `kube-bench`
- **Domain:** CIS Kubernetes Benchmark Compliance Auditor
- **Execution Command:** `kube-bench --json`
- **Output Parsing:** JSON test output mapping master, node, and control plane posture.
- **Native Fallback:** Native Kubernetes YAML manifest security auditor.

### 4.26 Dockle (`DockleAdapter`)
- **Tool Binary:** `dockle`
- **Domain:** CIS Docker Container Image Hardening Linter
- **Execution Command:** `dockle -f json <image_name>`
- **Output Parsing:** JSON report parser mapping CIS Docker benchmarks (`CIS-DI-0001` through `CIS-DI-0010`).
- **Native Fallback:** Native Dockerfile linter.
