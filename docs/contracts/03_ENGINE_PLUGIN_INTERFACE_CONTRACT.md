# Contract 03: Engine Plugin Interface, Execution Governance & Tool Supply Chain Contract

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 14.0.0 (Execution Plane Governance, 26-Tool Fleet Adapter Specifications, ProcessSupervisor Tree Termination & Sandbox Isolation)  
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
8. REGISTRATION: Register active tool status with the platform adapter registry.
```

### 2.3 Strict Verification Invariants
- **No Silent Bypass:** If `expected_sha256` is missing or invalid, installation MUST FAIL CLOSED.
- **Approved source-build exceptions:** Trivy `v0.50.0` and Nmap `7.95` may use `SOURCE_BUILD_MODE` because
  their approved upstream source distributions are available while suitable direct release assets are not.
  Each build MUST use the immutable source identity, pinned build toolchain identity, verified build inputs,
  reproducible build controls, and a generated executable trust record declared in Contract 09. Exact runtime
  version and pre-launch integrity verification remain mandatory.
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
  - Automated scanning is STRICTLY restricted to modules matching `auxiliary/scanner/*` and `auxiliary/admin/*` banner/verification checks.
  - Weaponized payload delivery (`exploit/*` with meterpreter/shell payloads) is prohibited during automated pipeline scans.
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
  - Mandatory `--batch` (non-interactive mode).
  - Bounded `--risk=1 --level=1` during automated sweeps to eliminate data loss or server disruption.
  - Data dumping (`--dump`, `--dump-all`, `--os-shell`) is disabled in automated scans.
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
  - Thread concurrency is hard-capped at `-t 2` or `-t 4` with inter-request delays (`-W 1`) to prevent account lockout or denial of service.
  - Restricted to small, standard credential audit dictionaries (maximum 10 entries) to verify default credential hardening.
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
