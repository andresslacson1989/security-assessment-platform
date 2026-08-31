# Contract 09: Authoritative Enterprise Security Tool Implementation Contract & Execution Specifications

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 14.0.0 (Authoritative 21-Tool Fleet Implementation Specifications, Execution Governance & Parser Invariants)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Authority:** Platform Core Architecture, Tool Adapter Layer, Process Supervisor & Verification Pipeline  
**Scope:** Canonical implementation specifications, invocation boundaries, failure semantics, output schemas, and security controls for all 21 supported external security tools.  
**Dependencies:** Contract 01 (Scope & Safety), Contract 02 (Data Schemas), Contract 03 (Engine & Plugin Interface), Contract 04 (API & Streaming), Contract 05 (Deliverables & Acceptance), Contract 06 (Check Catalog & CWE Mapping), Contract 07 (Frontend UI/UX), Contract 08 (Technical Implementation & Test Vectors).

---

# Part I: Architecture, Invariants & Generic Tool Contract Model

## 1. Executive Purpose & Governance Invariants

This authoritative contract governs the integration, execution, sandboxing, parsing, and normalization of every external security tool in CyberAssess.

No security tool may execute within the CyberAssess ecosystem unless it strictly satisfies the 41-point specification defined in this contract.

### 1.1 The Seven Fundamental Tool Execution Invariants

1. **The Target Validation Invariant (Contract 01 §3, Contract 08 §2):**
   No tool adapter may ever receive raw, unvalidated user input strings. Network-capable tools receive ONLY a `ValidatedTarget` produced by the authoritative Target Security Gateway (`assert_safe_target()`), ensuring pre-resolved IP validation, loopback/private CIDR denylisting, and connection-level destination pinning.

2. **The Workspace Confinement Invariant (Contract 01 §3, Contract 08 §3):**
   Filesystem and source analysis tools must execute strictly within the server-derived authorized workspace root. Symlink traversal escapes, sensitive system directories (`/etc`, `/root`, `C:\Windows`, `.ssh`, `.aws`), and arbitrary host paths fail closed.

3. **The Cryptographic Supply Chain Invariant (Contract 03 §2, Contract 08 §4):**
   Every external binary must match the authoritative pinned release manifest and verify against an authentic SHA-256 digest through an 8-step quarantine-before-promotion pipeline. Unpinned, untrusted, or modified binaries are rejected immediately.

4. **The Process Supervision & Non-Destructive Invariant (Contract 03 §3, Contract 05 §2):**
   All subprocess executions are governed exclusively through `ProcessSupervisor` with isolated process groups, strict execution timeouts (default 60s), 10MB output buffers, and recursive process tree termination on cancellation or timeout. Destructive exploits and data dumps are prohibited in automated modes.

5. **The Deterministic Output & Parser Invariant (Contract 06 §1, Contract 06 §2):**
   Tool output is untrusted input. Every adapter must validate schema integrity and transform raw observations into canonical `Finding` objects mapped to explicit CWE, OWASP Top 10, ASVS 5.0, and NIST SP 800-53 controls with cryptographic SHA-256 evidence digests (`evidence_hash`).

6. **The Silent Failure Prohibition Invariant (Contract 05 §1):**
   A tool execution failure, timeout, or cancellation MUST NEVER be interpreted as "no vulnerabilities found." Failed tool executions record explicit coverage limitations (`COVERAGE_DEGRADED`) and alert the orchestrator.

7. **The Graceful Native Fallback Guarantee (Contract 03 §1, Contract 05 §2):**
   Every primary security domain must be backed by a native Python engine. If an external binary is missing, unsupported on the host platform, or fails execution, the platform falls back 100% seamlessly to native checks with zero cascade failures.

---

## 2. Generic Tool Contract Schema (41-Point Specification Model)

Every supported tool integration is defined across 41 standardized fields:

```text
ToolDefinition
  ├── 1. Identity
  ├── 2. Security Purpose
  ├── 3. Role (PRIMARY | VALIDATION | SPECIALIZED | FALLBACK)
  ├── 4. Supported CyberAssess Profiles
  ├── 5. Supported Target Types
  ├── 6. Upstream Version Policy
  ├── 7. Artifact / Installation Method
  ├── 8. Integrity / Provenance (SHA-256)
  ├── 9. Required Permissions
  ├── 10. Credential Requirements
  ├── 11. Workspace Requirements
  ├── 12. Network Requirements
  ├── 13. Safety Policy
  ├── 14. Rate Limit
  ├── 15. Concurrency
  ├── 16. Timeout
  ├── 17. Resource Limits
  ├── 18. Invocation Contract
  ├── 19. Allowed Arguments
  ├── 20. Forbidden Arguments
  ├── 21. Input Schema
  ├── 22. Output Format
  ├── 23. Output Schema
  ├── 24. Exit Codes
  ├── 25. Failure Semantics
  ├── 26. Cancellation Protocol
  ├── 27. Cleanup Policy
  ├── 28. Parser Specification
  ├── 29. Finding Normalization
  ├── 30. Severity Mapping
  ├── 31. Taxonomy Mapping (CWE / OWASP / ASVS / NIST)
  ├── 32. Evidence Mapping
  ├── 33. Secret Handling & Masking
  ├── 34. Correlation Strategy
  ├── 35. Validation Role
  ├── 36. Reproducibility Record
  ├── 37. Update Policy
  ├── 38. Deprecation Policy
  ├── 39. Required Tests
  ├── 40. Known Limitations
  └── 41. Verification Status
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
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/nmap_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Discovers open TCP/UDP network ports, fingerprints listening services and versions, detects legacy operating systems, and identifies exposed administrative/database services on perimeter assets.
- **What It Detects:** Open network ports, service banners, SSL/TLS certificates on non-standard ports, basic script indicators (`http-title`, `ssl-cert`).
- **What It Does NOT Detect:** Deep web application logic flaws, authenticated API vulnerabilities, source code secrets.
- **Why Present:** Industry standard for reliable, low-overhead port scanning and banner identification.

### 3. Role
- **Classification:** `PRIMARY` network port scanner.
- **Overlap Strategy:** Complemented by `sslyze` (for deep TLS ciphers) and `httpx` (for web service probing).

### 4. Supported CyberAssess Profiles
- `FULL_STACK`: ALLOWED (Full port sweep)
- `QUICK`: ALLOWED (Top 100 ports)
- `NETWORK_ONLY`: ALLOWED (Primary engine)
- `DAST_ONLY`: DENIED (Web application focus only)
- `SAST_ONLY`: DENIED (Filesystem code focus only)

### 5. Supported Target Types
- `IP`: Supported (IPv4, IPv6)
- `DOMAIN`: Supported (Resolved via Target Security Gateway)
- `URL`: Supported (Hostname extracted prior to invocation)
- `LOCAL_PATH`: PROHIBITED

### 6. Upstream Version Policy
- **Pinned Version:** Nmap 7.94+
- **Version Detection:** `nmap --version` -> Regex `Nmap version\s+([0-9\.]+[a-zA-Z0-9]*)`

### 7. Artifact / Installation Method
- **Method:** Preinstalled system binary or official platform installer (WinGet / apt / yum / brew).
- **Resolver Path:** Tier 1: `config.adapters.nmap_path`, Tier 2: `backend/bin/nmap.exe`, Tier 4: `shutil.which("nmap")`, Tier 5: Windows `C:\Program Files (x86)\Nmap\nmap.exe`.

### 8. Integrity / Provenance
- **Integrity Status:** System-level binary validation; verified via executable existence and `--version` execution probe.

### 9. Required Permissions
- Unprivileged TCP connect scanning (`-sT` or unprivileged `-sV`). Root/Administrator raw socket privileges (`-sS` SYN stealth) are NOT required for standard operation.

### 10. Credential Requirements
- `NOT APPLICABLE` (Unauthenticated network probing).

### 11. Workspace Requirements
- `NOT APPLICABLE` (Network operations only; no filesystem artifacts stored outside temporary stdout pipe).

### 12. Network Requirements
- Direct TCP/UDP egress to target host ports. Egress to private/loopback subnets is blocked unless explicit `scan:internal` scope is verified.

### 13. Safety Policy
- **Scan Timing:** Strict `-T4` timing capped to avoid network flooding.
- **Safe Scripts Only:** Only light, non-intrusive scripts (`--version-light`, `-sC`) are permitted. Intrusive exploit scripts (`--script exploit`, `--script dos`) are strictly PROHIBITED.

### 14. Rate Limit
- Standard rate limit: Default packet rate controlled by `-T4` timing template.

### 15. Concurrency
- Single subprocess instance per scan job; internal probe parallelism managed by Nmap engine.

### 16. Timeout
- Startup timeout: 5.0s.
- Execution timeout: 60.0s (or `min(60.0, config.timeout_seconds * 6)`).

### 17. Resource Limits
- Max stdout buffer: 10 MB.
- Max memory: 256 MB.

### 18. Invocation Contract
```text
Executable: <resolved_nmap_path>
Command Line: nmap -sV -sC --version-light -T4 -oX - [-p <port_list>] <validated_target_host>
Working Directory: Server-derived temporary execution directory
Stdin: Closed
Stdout: Captures XML output for stream parsing
Stderr: Captures runtime diagnostics and errors
```

### 19. Allowed Arguments
- `-sV`, `-sC`, `--version-light`, `-T4`, `-oX -`, `-p <port_list>`, `<validated_target_host>`.

### 20. Forbidden Arguments
- `--script exploit`, `--script dos`, `--interactive`, `--privileged`, `--system-commands`, `-oN <arbitrary_path>`, `-iL <arbitrary_file>`.

### 21. Input Schema
- Target hostname or IP string extracted and validated via `extract_host(target.value)`.

### 22. Output Format
- Standard Nmap XML (`-oX -`) emitted to stdout.

### 23. Output Schema
- Validated XML containing root `<nmaprun>` and child `<host><ports><port>` elements.

### 24. Exit Codes
- `0`: Successful scan execution.
- `Non-zero`: Tool execution failure or invalid arguments.

### 25. Failure Semantics
- Missing binary: Emits `LogLevel.WARNING`, transitions execution to native `port_checker` and `banner_grabber`.
- Timeout / Error: Logs warning, retains partial results if XML is parseable, otherwise invokes native fallback.

### 26. Cancellation Protocol
- Managed by `ProcessSupervisor`. Sends `SIGTERM` / `taskkill /F /T /PID <pid>` to kill the entire process tree.

### 27. Cleanup Policy
- No persistent output files written to disk (`-oX -` uses memory stream). Temporary process resources freed on termination.

### 28. Parser Specification
- **Engine:** Python `xml.etree.ElementTree`.
- **Extraction:** Iterates `.findall(".//ports/port")`, extracts `portid`, `protocol`, `state`, `service.name`, `service.product`, `service.version`, `script.output`.

### 29. Finding Normalization
- Exposed Database Port (3306, 5432, 27017, 6379): Check ID `NET-PORT-001`, Severity `HIGH`, CVSS 7.5, CWE-284.
- Exposed Admin Management Port (22, 3389, 23, 21): Check ID `NET-PORT-002`, Severity `MEDIUM`, CVSS 5.3, CWE-284.
- Discovered Active Service: Check ID `NET-SVC-001`, Severity `INFO`, CVSS 0.0, CWE-200.

### 30. Severity Mapping
- Database Exposure -> `Severity.HIGH` (7.5)
- Management Port Exposure -> `Severity.MEDIUM` (5.3)
- Generic Open Port -> `Severity.INFO` (0.0)

### 31. Taxonomy Mapping
- `CWE-284`: Improper Access Control
- `CWE-200`: Exposure of Sensitive Information
- `OWASP A05:2021`: Security Misconfiguration
- `NIST SP 800-53`: `AC-17` (Remote Access), `CM-7` (Least Functionality)

### 32. Evidence Mapping
- `observed_value`: Port number, protocol, service product, version string.
- `script_output`: Full formatted text of script responses (`ssl-cert`, `http-title`).
- `evidence_hash`: SHA-256 digest of port + service + version string.

### 33. Secret Handling & Masking
- Sanitizes banner strings for any embedded credentials or private tokens.

### 34. Correlation Strategy
- Correlates with native `port_checker` and `banner_grabber` using `(target_ip, port, protocol)` tuple.

### 35. Validation Role
- `PRIMARY` network discovery authority.

### 36. Reproducibility Record
- Records Nmap version, execution timestamp, port arguments, and XML evidence hash.

### 37. Update Policy
- Updated via host package manager or platform image rebuilding with regression validation in `tests/test_adapters.py`.

### 38. Deprecation Policy
- Core foundational tool; not scheduled for deprecation.

### 39. Required Tests
- `test_nmap_adapter_version_extraction`
- `test_nmap_adapter_xml_parsing_standard`
- `test_nmap_adapter_database_port_identification`
- `test_nmap_adapter_missing_binary_fallback`
- `test_nmap_adapter_timeout_handling`

### 40. Known Limitations
- Does not inspect application layer payloads beyond banner extraction; requires elevated privileges for OS TCP SYN fingerprinting.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/nmap_adapter.py`, `tests/test_adapters.py`).

---

## TOOL 02: SSLyze

### 1. Identity
- **Tool ID:** `TOOL-SSLYZE`
- **Display Name:** SSLyze
- **Upstream Project:** Nabla C0d3 (https://github.com/nabla-c0d3/sslyze)
- **Security Domain:** Network Perimeter & TLS
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/sslyze_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Fast and comprehensive TLS/SSL configuration analysis to identify broken protocols, deprecated ciphers, and certificate validation flaws.
- **What It Detects:** SSLv2, SSLv3, TLS 1.0, TLS 1.1 enablement, weak ciphers (RC4, 3DES, EXPORT, NULL, CBC mode vulnerabilities), expired/untrusted certificates, missing OCSP stapling.
- **What It Does NOT Detect:** Web application injection bugs, operating system vulnerabilities.
- **Why Present:** Authoritative engine for complete cryptographic protocol compliance (NIST SP 800-52r2 / ASVS 5.0 V9).

### 3. Role
- **Classification:** `PRIMARY` TLS security analysis engine.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`: ALLOWED
- `NETWORK_ONLY`: ALLOWED
- `DAST_ONLY`: ALLOWED
- `QUICK`: ALLOWED
- `SAST_ONLY`: DENIED

### 5. Supported Target Types
- `URL`: Supported (Hostname & port extracted)
- `DOMAIN`: Supported
- `IP`: Supported

### 6. Upstream Version Policy
- **Pinned Version:** SSLyze 5.2.0+ / Python library package.
- **Version Detection:** `sslyze --version` or Python package `importlib.metadata.version("sslyze")`.

### 7. Artifact / Installation Method
- **Method:** Pure Python wheel installed via pip (`pip_installer.py`) in isolated venv.

### 8. Integrity / Provenance
- Verified via PyPI hashes and pip lockfiles (`backend/requirements.txt`).

### 9. Required Permissions
- Unprivileged network socket access.

### 10. Credential Requirements
- `NOT APPLICABLE`

### 11. Workspace Requirements
- `NOT APPLICABLE`

### 12. Network Requirements
- Direct outbound TLS connection on target ports (443, 8443, custom TLS ports).

### 13. Safety Policy
- Safe, non-destructive TLS handshakes only.

### 14. Rate Limit
- Bounded to 5 concurrent handshake probes per host.

### 15. Concurrency
- Managed via internal thread pool; capped at 1 subprocess/thread per scan job.

### 16. Timeout
- Startup timeout: 5.0s. Execution timeout: 45.0s.

### 17. Resource Limits
- Max memory: 256 MB.

### 18. Invocation Contract
```text
Executable: <resolved_python_path> -m sslyze
Command Line: sslyze --json_out=- <target_host>:<target_port>
Stdout: Captures JSON results stream
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `--json_out=-`, `<target_host>:<target_port>`, `--certinfo`, `--sslv2`, `--sslv3`, `--tlsv1`, `--tlsv1_1`, `--tlsv1_2`, `--tlsv1_3`.

### 20. Forbidden Arguments
- Arbitrary file write flags (`--json_out=<arbitrary_path>`).

### 21. Input Schema
- `<target_host>:<target_port>` derived from validated target.

### 22. Output Format
- JSON structure parsed from stdout.

### 23. Output Schema
- Validated JSON containing `server_scan_results[].scan_result`.

### 24. Exit Codes
- `0`: Scan completed successfully.
- `Non-zero`: Connection error or unsupported target.

### 25. Failure Semantics
- Falls back seamlessly to native Python `ssl.SSLContext` protocol sweeper.

### 26. Cancellation Protocol
- Standard process group termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- In-memory stream processing; no disk artifacts retained.

### 28. Parser Specification
- Extracts `ssl_2_0_cipher_suites`, `ssl_3_0_cipher_suites`, `tls_1_0_cipher_suites`, `tls_1_1_cipher_suites`, `certificate_deployments`.

### 29. Finding Normalization
- Deprecated Protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1): Check ID `NET-TLS-001`, Severity `HIGH`, CVSS 7.5, CWE-326.
- Weak Ciphers (RC4, 3DES, NULL): Check ID `NET-TLS-002`, Severity `MEDIUM`, CVSS 5.9, CWE-327.
- Expired/Untrusted Certificate: Check ID `NET-TLS-003`, Severity `HIGH`, CVSS 7.5, CWE-295.

### 30. Severity Mapping
- Deprecated TLS 1.0/1.1 -> `Severity.HIGH`
- Weak Ciphers -> `Severity.MEDIUM`
- Certificate Expired -> `Severity.HIGH`

### 31. Taxonomy Mapping
- `CWE-326`: Inadequate Encryption Strength
- `CWE-327`: Use of a Broken or Risky Cryptographic Algorithm
- `CWE-295`: Improper Certificate Validation
- `ASVS 5.0`: `v5.0.0-V9.1.1`, `v5.0.0-V9.2.1`
- `NIST SP 800-53`: `SC-8`, `SC-13`

### 32. Evidence Mapping
- Observed cipher suite lists, protocol names, certificate expiry timestamps, and SHA-256 evidence hash.

### 33. Secret Handling & Masking
- Redacts private keys if accidentally returned in server certificate fields.

### 34. Correlation Strategy
- Correlates with native `tls_auditor` findings.

### 35. Validation Role
- `PRIMARY` TLS cryptographic authority.

### 36. Reproducibility Record
- Records SSLyze version, TLS endpoints scanned, and JSON result hash.

### 37. Update Policy
- Managed via `pip` package upgrades in locked environment.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_sslyze_adapter_json_parsing`
- `test_sslyze_adapter_deprecated_tls_detection`
- `test_sslyze_adapter_fallback`

### 40. Known Limitations
- Requires target to expose valid TLS port; does not test non-TLS plain HTTP.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/sslyze_adapter.py`).

---

## TOOL 03: Subfinder

### 1. Identity
- **Tool ID:** `TOOL-SUBFINDER`
- **Display Name:** Subfinder
- **Upstream Project:** ProjectDiscovery (https://github.com/projectdiscovery/subfinder)
- **Security Domain:** Perimeter / EASM
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/subfinder_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Fast passive subdomain enumeration using Certificate Transparency logs, search engines, and passive DNS datasets without sending traffic to the target.
- **What It Detects:** Valid organizational subdomains, forgotten staging environments, legacy domains.
- **What It Does NOT Detect:** Active service vulnerabilities, application logic bugs.
- **Why Present:** Essential reconnaissance engine for establishing total attack surface breadth.

### 3. Role
- **Classification:** `PRIMARY` passive reconnaissance tool.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`: ALLOWED
- `NETWORK_ONLY`: ALLOWED
- `PASSIVE_OSINT`: ALLOWED
- `DAST_ONLY`: ALLOWED (When `include_subdomains=True`)
- `SAST_ONLY`: DENIED

### 5. Supported Target Types
- `DOMAIN`: Supported
- `URL`: Supported (Apex domain extracted)
- `IP`: PROHIBITED (Domain reconnaissance only)

### 6. Upstream Version Policy
- **Pinned Version:** `v2.6.5`
- **Version Detection:** `subfinder -version` -> Regex `v?([0-9\.]+)`

### 7. Artifact / Installation Method
- **Method:** Official GitHub release standalone binary downloaded via `github_release_installer.py`.
- **Checksums:** Verified in `PINNED_TOOL_MANIFEST` (`windows_amd64`, `linux_amd64`).

### 8. Integrity / Provenance
- `windows_amd64`: `382a5c54ec5a7cfeb60ad4fae3c321fa4ba5b6028a05c6ea4d49a751682ea576`
- `linux_amd64`: `5ea58ceea06ea64e5aa06b12f68bc7aa3f63e6396da197825d19ec6ad06b2e3e`

### 9. Required Permissions
- Unprivileged network socket access.

### 10. Credential Requirements
- Supports optional passive provider API keys configured in tenant settings (e.g. VirusTotal, SecurityTrails, Chaos).

### 11. Workspace Requirements
- `NOT APPLICABLE`

### 12. Network Requirements
- Outbound HTTPS access to public passive API endpoints (e.g. crt.sh, hacker-target). Zero direct traffic sent to target domain.

### 13. Safety Policy
- 100% passive; zero active network interaction with target servers.

### 14. Rate Limit
- Bounded to upstream provider limits.

### 15. Concurrency
- Single process per scan job.

### 16. Timeout
- Startup timeout: 5.0s. Execution timeout: 60.0s.

### 17. Resource Limits
- Max memory: 256 MB. Max stdout: 10 MB.

### 18. Invocation Contract
```text
Executable: <resolved_subfinder_path>
Command Line: subfinder -d <target_domain> -silent -json
Stdout: Captures JSON Lines stream
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `-d <domain>`, `-silent`, `-json`, `-t <threads>`, `-timeout <seconds>`.

### 20. Forbidden Arguments
- Arbitrary file write (`-o <arbitrary_path>`), execution wrappers.

### 21. Input Schema
- Validated root domain string (`example.com`).

### 22. Output Format
- Line-delimited JSON (JSON Lines).

### 23. Output Schema
- Objects containing `{"host": "sub.example.com", "input": "example.com", "sources": [...]}`.

### 24. Exit Codes
- `0`: Successful enumeration.
- `Non-zero`: API error or network connectivity failure.

### 25. Failure Semantics
- Falls back seamlessly to native Certificate Transparency log queries (`crt.sh` / `certspotter`).

### 26. Cancellation Protocol
- Immediate process tree termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Process termination cleans up all temporary memory descriptors.

### 28. Parser Specification
- Parses JSON Lines stream, extracts `host`, resolves active DNS A/AAAA records asynchronously, and constructs `DiscoveredSubdomain` models.

### 29. Finding Normalization
- Populates `scan.discovered_subdomains` list and emits `NET-OSINT-001` informational findings.

### 30. Severity Mapping
- `Severity.INFO` (0.0 CVSS).

### 31. Taxonomy Mapping
- `CWE-200`: Information Exposure
- `OWASP A05:2021`: Security Misconfiguration
- `NIST SP 800-53`: `CM-8` (Information System Component Inventory)

### 32. Evidence Mapping
- FQDN, discovery source list, active resolved IP list, CNAME targets.

### 33. Secret Handling & Masking
- Redacts any API tokens passed to external providers in debug logs.

### 34. Correlation Strategy
- Merged into unified attack surface inventory with native CT findings.

### 35. Validation Role
- Feeds validated endpoints downstream to `httpx` and `katana`.

### 36. Reproducibility Record
- Records Subfinder version, query timestamp, domain seed, and discovered host count.

### 37. Update Policy
- Automated manifest bump with SHA-256 verification in `tool_manifest.py`.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_subfinder_adapter_json_lines_parsing`
- `test_subfinder_active_dns_resolution`
- `test_subfinder_fallback`

### 40. Known Limitations
- Passive discovery only; does not find unindexed internal subdomains without active brute-forcing.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/subfinder_adapter.py`).

---

## TOOL 04: httpx

### 1. Identity
- **Tool ID:** `TOOL-HTTPX`
- **Display Name:** httpx
- **Upstream Project:** ProjectDiscovery (https://github.com/projectdiscovery/httpx)
- **Security Domain:** HTTP Probing & Discovery
- **CyberAssess Role:** `VALIDATION`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/httpx_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Rapid multi-point HTTP service validation, technology stack identification, and status code verification across large lists of hosts.
- **What It Detects:** Live web servers, HTTP response status codes, page titles, web servers (Nginx, Apache, Cloudflare), web technologies, TLS SANs.
- **What It Does NOT Detect:** Deep DAST vulnerabilities (SQLi, XSS).
- **Why Present:** Bridges perimeter subdomain enumeration and active web crawling by validating live HTTP services at high speed.

### 3. Role
- **Classification:** `VALIDATION` engine.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`, `NETWORK_ONLY`, `DAST_ONLY`, `QUICK`.

### 5. Supported Target Types
- `URL`, `DOMAIN`, `IP`.

### 6. Upstream Version Policy
- **Pinned Version:** `v1.6.0`
- **Version Detection:** `httpx -version` -> Regex `v?([0-9\.]+)`

### 7. Artifact / Installation Method
- Standalone GitHub release binary (`github_release_installer.py`).

### 8. Integrity / Provenance
- `windows_amd64`: `4a129d20c57c44db8fca539e0839f8f2b3ec48ee5f8e65fa1a4e9b9809930f76`
- `linux_amd64`: `9fa0cb78fe664bd9f0cb18a4d79a29e4eb589a19c72e2cf5ec9aeebbb85da570`

### 9. Required Permissions
- Unprivileged HTTP/HTTPS network access.

### 10. Credential Requirements
- `NOT APPLICABLE`

### 11. Workspace Requirements
- `NOT APPLICABLE`

### 12. Network Requirements
- Direct outbound HTTP/HTTPS connections to target hosts.

### 13. Safety Policy
- Enforces SSRF target validation; denies private CIDR sweeps.

### 14. Rate Limit
- Bounded to 20 requests/sec.

### 15. Concurrency
- Capped at `-threads 10`.

### 16. Timeout
- Startup: 5.0s. Execution: 60.0s.

### 17. Resource Limits
- Max memory: 256 MB.

### 18. Invocation Contract
```text
Executable: <resolved_httpx_path>
Command Line: httpx -u <target_url> -silent -json -title -tech-detect -status-code
Stdout: Captures JSON Lines stream
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `-u <url>`, `-silent`, `-json`, `-title`, `-tech-detect`, `-status-code`, `-threads <int>`, `-timeout <int>`.

### 20. Forbidden Arguments
- Arbitrary file execution, raw unsanitized request files.

### 21. Input Schema
- Validated target URL or list of hostnames.

### 22. Output Format
- JSON Lines stream.

### 23. Output Schema
- Objects containing `url`, `status_code`, `title`, `technologies`, `webserver`, `host`, `port`.

### 24. Exit Codes
- `0`: Success. `Non-zero`: Network failure.

### 25. Failure Semantics
- Falls back to native Python `httpx` async library.

### 26. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Memory descriptors closed on exit.

### 28. Parser Specification
- Parses JSON Lines stream and enriches `DiscoveredEndpoint` models.

### 29. Finding Normalization
- Emits technology fingerprinting records and validates reachable HTTP endpoints.

### 30. Severity Mapping
- `Severity.INFO` (0.0 CVSS).

### 31. Taxonomy Mapping
- `CWE-200`, `OWASP A05:2021`, `NIST CM-8`.

### 32. Evidence Mapping
- Response headers, title, detected technologies, status code.

### 33. Secret Handling & Masking
- Sanitizes cookies and Authorization headers in output.

### 34. Correlation Strategy
- Enriches endpoint inventory before DAST crawl execution.

### 35. Validation Role
- Confirms live web service reachability.

### 36. Reproducibility Record
- Records httpx version, input URLs, and technology match list.

### 37. Update Policy
- Pinned manifest updates.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_httpx_adapter_json_parsing`
- `test_httpx_tech_detection`

### 40. Known Limitations
- Probes endpoints only; does not fuzz parameters.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/httpx_adapter.py`).

---

## TOOL 05: Nuclei

### 1. Identity
- **Tool ID:** `TOOL-NUCLEI`
- **Display Name:** Nuclei
- **Upstream Project:** ProjectDiscovery (https://github.com/projectdiscovery/nuclei)
- **Security Domain:** Web DAST & Vulnerability Assessment
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/nuclei_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Fast, deterministic template-driven vulnerability scanning for known CVEs, security misconfigurations, default credentials, and exposed sensitive panels.
- **What It Detects:** Known CVEs across web frameworks, unauthenticated admin portals, exposed `.env` files, git repositories, CORS misconfigurations, GraphQL introspection.
- **What It Does NOT Detect:** Complex business logic flaws requiring multi-step state machines.
- **Why Present:** Authoritative modern DAST scanner with community-driven, curated CVE templates.

### 3. Role
- **Classification:** `PRIMARY` DAST vulnerability scanner.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`, `DAST_ONLY`, `QUICK`, `API_FOCUSED`.

### 5. Supported Target Types
- `URL`, `DOMAIN`, `IP`.

### 6. Upstream Version Policy
- **Pinned Version:** `v3.2.0`
- **Version Detection:** `nuclei -version` -> Regex `v?([0-9\.]+)`

### 7. Artifact / Installation Method
- Standalone GitHub release binary (`github_release_installer.py`).

### 8. Integrity / Provenance
- `windows_amd64`: `64d0a3ec74f63cbb2f97f740a6b98686fba7fa01f5c6adbc81c81ef4554b5ec9`
- `linux_amd64`: `e2c39e248b613c0efcfd1d575c3db6fb8260b43521b44ec5fdfdfc845ad35e80`

### 9. Required Permissions
- Unprivileged HTTP/HTTPS network access.

### 10. Credential Requirements
- Supports custom auth headers (`-H "Authorization: Bearer <token>"`) injected by orchestrator.

### 11. Workspace Requirements
- `NOT APPLICABLE`

### 12. Network Requirements
- Direct outbound HTTP/HTTPS access to target URL.

### 13. Safety Policy
- Strict template classification: only non-destructive tags (`cve`, `misconfig`, `exposure`) are enabled. Destructive exploit or DoS templates are forbidden.

### 14. Rate Limit
- Bounded to 10 requests/sec (`-rate-limit 10`).

### 15. Concurrency
- Capped at `-c 5`.

### 16. Timeout
- Startup: 5.0s. Execution: 90.0s.

### 17. Resource Limits
- Max memory: 512 MB. Max stdout: 10 MB.

### 18. Invocation Contract
```text
Executable: <resolved_nuclei_path>
Command Line: nuclei -u <target_url> -j -silent -tags cve,misconfig -severity low,medium,high,critical
Stdout: Captures JSON Lines stream
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `-u <url>`, `-j`, `-silent`, `-tags <tags>`, `-severity <severities>`, `-H <header>`, `-timeout <sec>`, `-rate-limit <rps>`.

### 20. Forbidden Arguments
- `-update-templates` (uncontrolled network pull in production), `-t <untrusted_local_path>`.

### 21. Input Schema
- Normalized target URL string (`http://` or `https://`).

### 22. Output Format
- Line-delimited JSON stream.

### 23. Output Schema
- Objects containing `template-id`, `info.name`, `info.severity`, `info.classification.cwe-id`, `info.classification.cvss-score`, `matched-at`, `curl-command`.

### 24. Exit Codes
- `0`: Completed with or without findings. `Non-zero`: Network failure.

### 25. Failure Semantics
- Falls back seamlessly to native DAST rule engine (`headers_cookies`, `cors_analyzer`, `browser_posture`).

### 26. Cancellation Protocol
- Immediate process tree termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Process termination cleans up all memory streams.

### 28. Parser Specification
- Parses JSON Lines stream, maps `template-id` to canonical check catalog, extracts `reproduction_curl`, and generates `Finding` models.

### 29. Finding Normalization
- Maps Nuclei findings to canonical check IDs (`DAST-INJ-001`, `DAST-XSS-001`, `DAST-EXP-001`, `DAST-CORS-001`, etc.).

### 30. Severity Mapping
- `critical` -> `Severity.CRITICAL` (9.8)
- `high` -> `Severity.HIGH` (7.5)
- `medium` -> `Severity.MEDIUM` (5.3)
- `low` -> `Severity.LOW` (3.1)
- `info` -> `Severity.INFO` (0.0)

### 31. Taxonomy Mapping
- Populates exact CWE ID from `info.classification.cwe-id`, maps to OWASP Top 10 (2021) and NIST SP 800-53 controls (`AC-3`, `SI-10`, `SC-8`).

### 32. Evidence Mapping
- Matched URL, HTTP request/response snippets, reproduction curl command, and SHA-256 evidence digest.

### 33. Secret Handling & Masking
- Masks credentials in `reproduction_curl` and response bodies before persistence.

### 34. Correlation Strategy
- Clustered with native DAST findings on identical endpoints and check IDs.

### 35. Validation Role
- `PRIMARY` automated CVE discovery authority.

### 36. Reproducibility Record
- Records Nuclei version, template ID, matched URL, and evidence hash.

### 37. Update Policy
- Version and template manifest bumps with regression verification.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_nuclei_adapter_json_stream_parsing`
- `test_nuclei_adapter_severity_mapping`
- `test_nuclei_adapter_fallback`

### 40. Known Limitations
- Does not maintain authenticated state across complex multi-step workflows.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/nuclei_adapter.py`).

---

## TOOL 06: FFuF

### 1. Identity
- **Tool ID:** `TOOL-FFUF`
- **Display Name:** FFuF (Fuzz Faster U Fool)
- **Upstream Project:** FFuF (https://github.com/ffuf/ffuf)
- **Security Domain:** Web Fuzzing & Parameter Discovery
- **CyberAssess Role:** `SPECIALIZED`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/ffuf_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** High-speed fuzzing for hidden web routes, directories, URL query parameters, and HTTP headers.
- **What It Detects:** Unlinked administrative portals, hidden debug parameters, backup files (`.bak`, `.old`), unindexed API routes.
- **What It Does NOT Detect:** Static source code vulnerabilities, TLS cipher configuration.
- **Why Present:** High-performance Go fuzzer with advanced response filtering (size, words, lines).

### 3. Role
- **Classification:** `SPECIALIZED` parameter and directory discovery engine.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`, `DAST_ONLY`, `API_FOCUSED`.

### 5. Supported Target Types
- `URL`.

### 6. Upstream Version Policy
- **Pinned Version:** `v2.1.0`
- **Version Detection:** `ffuf -V` -> Regex `v?([0-9\.]+)`

### 7. Artifact / Installation Method
- Standalone GitHub release binary (`github_release_installer.py`).

### 8. Integrity / Provenance
- `windows_amd64`: `c62b66236b281bf77bb0b57e7eb3b7235a8bc33b28b58a1ee2e94625b597c5e2`
- `linux_amd64`: `426be0eb2a297e6be9ea83664746f34586db30188aa1d3824ee18c15668db8c0`

### 9. Required Permissions
- Unprivileged HTTP/HTTPS network access.

### 10. Credential Requirements
- Optional session cookies / auth headers passed via `-H`.

### 11. Workspace Requirements
- Temporary wordlist files created in sandboxed temp directory.

### 12. Network Requirements
- Outbound HTTP/HTTPS requests to target URL.

### 13. Safety Policy
- Restrictive wordlists; exclusion patterns for logout and destructive actions (`*logout*`, `*delete*`, `*purge*`).

### 14. Rate Limit
- Bounded to `-rate 10` requests/sec.

### 15. Concurrency
- Capped at `-t 5` threads.

### 16. Timeout
- Startup: 5.0s. Execution: 60.0s.

### 17. Resource Limits
- Max memory: 256 MB. Max stdout: 10 MB.

### 18. Invocation Contract
```text
Executable: <resolved_ffuf_path>
Command Line: ffuf -u <target_url>/FUZZ -w <wordlist_path> -mc 200,204,301,302,307,401,403 -o - -of json -t 5 -rate 10 -s
Stdout: Captures JSON output
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `-u <url>`, `-w <path>`, `-mc <codes>`, `-ms <size>`, `-fs <size>`, `-o -`, `-of json`, `-t <threads>`, `-rate <rps>`, `-s`.

### 20. Forbidden Arguments
- Non-standard HTTP methods (`-X DELETE`), arbitrary file writes.

### 21. Input Schema
- Validated target URL with `FUZZ` placeholder.

### 22. Output Format
- JSON output emitted to stdout.

### 23. Output Schema
- Validated JSON containing `results[].url`, `results[].status`, `results[].length`, `results[].words`, `results[].input.FUZZ`.

### 24. Exit Codes
- `0`: Success. `Non-zero`: Error.

### 25. Failure Semantics
- Falls back to native Python BFS crawler and parameter fuzzer.

### 26. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Temporary wordlist files deleted immediately upon execution completion.

### 28. Parser Specification
- Parses JSON results, extracts discovered paths/parameters, and constructs `DiscoveredEndpoint` models.

### 29. Finding Normalization
- Emits `DAST-EXP-001` (Exposed Administrative Endpoint) or `DAST-PARAM-001` (Hidden Parameter).

### 30. Severity Mapping
- Exposed Admin Route -> `Severity.MEDIUM` (5.3)
- Information Disclosure -> `Severity.LOW` (3.1)

### 31. Taxonomy Mapping
- `CWE-200`, `CWE-284`, `OWASP A01:2021`, `NIST AC-3`.

### 32. Evidence Mapping
- Discovered URL, status code, response length, fuzz word.

### 33. Secret Handling & Masking
- Sanitizes request headers in stored evidence.

### 34. Correlation Strategy
- Feeds newly discovered endpoints into the live assessment dossier.

### 35. Validation Role
- `SPECIALIZED` fuzzing authority.

### 36. Reproducibility Record
- Records wordlist hash, target URL, and FFuF version.

### 37. Update Policy
- Manifest digest verification.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_ffuf_adapter_json_parsing`
- `test_ffuf_wordlist_execution`

### 40. Known Limitations
- Fuzzing volume depends on wordlist size; requires calibrated response filtering.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/ffuf_adapter.py`).

---

## TOOL 07: Katana

### 1. Identity
- **Tool ID:** `TOOL-KATANA`
- **Display Name:** Katana
- **Upstream Project:** ProjectDiscovery (https://github.com/projectdiscovery/katana)
- **Security Domain:** Web Crawling & Attack Surface Discovery
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/katana_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Next-generation web crawler supporting both standard HTTP DOM parsing and headless Chromium crawling for Single Page Applications (SPAs).
- **What It Detects:** Hyperlinks, API routes in JavaScript bundles, HTML forms, input parameters, endpoint trees.
- **What It Does NOT Detect:** Static source code vulnerabilities, network port status.
- **Why Present:** Deep crawling capabilities for modern JavaScript-heavy frontend applications.

### 3. Role
- **Classification:** `PRIMARY` web crawler.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`, `DAST_ONLY`, `QUICK`.

### 5. Supported Target Types
- `URL`.

### 6. Upstream Version Policy
- **Pinned Version:** `v1.0.5`
- **Version Detection:** `katana -version` -> Regex `v?([0-9\.]+)`

### 7. Artifact / Installation Method
- Standalone GitHub release binary (`github_release_installer.py`).

### 8. Integrity / Provenance
- `windows_amd64`: `806a6b574a44b94f1c713beeafe9be2bb53a5c6ca8858e999905f15d9715bf85`
- `linux_amd64`: `00f07bf266ce2da4a6c4c95f19069d5fb3fbffac4fe6d24f0cba160b73df7816`

### 9. Required Permissions
- Unprivileged HTTP/HTTPS network access.

### 10. Credential Requirements
- Optional cookie header passed via `-H`.

### 11. Workspace Requirements
- `NOT APPLICABLE`

### 12. Network Requirements
- Outbound HTTP/HTTPS access strictly scoped to target domain.

### 13. Safety Policy
- Depth capped at `-d 3`, maximum crawl limit enforced, out-of-scope domain traversal blocked.

### 14. Rate Limit
- Bounded to 10 requests/sec.

### 15. Concurrency
- Capped at `-c 5`.

### 16. Timeout
- Startup: 5.0s. Execution: 90.0s.

### 17. Resource Limits
- Max memory: 512 MB.

### 18. Invocation Contract
```text
Executable: <resolved_katana_path>
Command Line: katana -u <target_url> -silent -json -d 3 -jc
Stdout: Captures JSON Lines stream
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `-u <url>`, `-silent`, `-json`, `-d <depth>`, `-jc`, `-c <concurrency>`, `-ct <timeout>`.

### 20. Forbidden Arguments
- Unrestricted crawling without depth caps.

### 21. Input Schema
- Validated target URL string.

### 22. Output Format
- JSON Lines stream.

### 23. Output Schema
- Objects containing `request.endpoint`, `request.method`, `request.tag`, `response.status_code`.

### 24. Exit Codes
- `0`: Success. `Non-zero`: Failure.

### 25. Failure Semantics
- Falls back to native Python BFS HTML crawler.

### 26. Cancellation Protocol
- Process tree termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Memory descriptors closed on exit.

### 28. Parser Specification
- Parses JSON Lines stream, normalizes endpoints, and populates `DiscoveredEndpoint` models.

### 29. Finding Normalization
- Enriches endpoint inventory and records discovered forms and parameters.

### 30. Severity Mapping
- `Severity.INFO` (0.0 CVSS).

### 31. Taxonomy Mapping
- `CWE-200`, `OWASP A05:2021`, `NIST CM-8`.

### 32. Evidence Mapping
- Endpoint URL, HTTP method, discovery tag, parent page URL.

### 33. Secret Handling & Masking
- Sanitizes request headers in stored records.

### 34. Correlation Strategy
- Feeds crawled endpoints directly into the assessment dossier.

### 35. Validation Role
- `PRIMARY` web endpoint discovery engine.

### 36. Reproducibility Record
- Records Katana version, crawl depth, and discovered endpoint count.

### 37. Update Policy
- Manifest digest updates.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_katana_adapter_json_parsing`
- `test_katana_depth_limit`

### 40. Known Limitations
- Headless mode requires system Chromium/Chrome binary.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/katana_adapter.py`).

---

## TOOL 08: Schemathesis

### 1. Identity
- **Tool ID:** `TOOL-SCHEMATHESIS`
- **Display Name:** Schemathesis
- **Upstream Project:** Schemathesis (https://github.com/schemathesis/schemathesis)
- **Security Domain:** API Contract Security & Fuzzing
- **CyberAssess Role:** `SPECIALIZED`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/schemathesis_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Property-based testing for OpenAPI, Swagger, and GraphQL APIs to detect server crashes (HTTP 500), schema violations, and input validation failures.
- **What It Detects:** Server-side unhandled exceptions (HTTP 500), missing input validation, boundary violations, status code mismatches.
- **What It Does NOT Detect:** Static source code vulnerabilities, network port exposure.
- **Why Present:** Enterprise API contract security and robust automated boundary fuzzing.

### 3. Role
- **Classification:** `SPECIALIZED` API testing engine.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`, `API_FOCUSED`, `DAST_ONLY`.

### 5. Supported Target Types
- `URL` (OpenAPI schema URL or base API URL).

### 6. Upstream Version Policy
- **Pinned Version:** Schemathesis 3.20.0+ (pip package).
- **Version Detection:** `schemathesis --version` -> Regex `([0-9\.]+)`

### 7. Artifact / Installation Method
- Installed via pip (`pip_installer.py`).

### 8. Integrity / Provenance
- PyPI package hashes in `requirements.txt`.

### 9. Required Permissions
- Unprivileged HTTP/HTTPS network access.

### 10. Credential Requirements
- Supports API bearer tokens or custom headers passed via `--header`.

### 11. Workspace Requirements
- `NOT APPLICABLE`

### 12. Network Requirements
- Direct outbound HTTP/HTTPS connections to API endpoints.

### 13. Safety Policy
- Read-only operations prioritized; state-changing endpoints (POST/PUT/DELETE) strictly bounded.

### 14. Rate Limit
- Bounded to 10 requests/sec.

### 15. Concurrency
- Single subprocess instance.

### 16. Timeout
- Startup: 5.0s. Execution: 60.0s.

### 17. Resource Limits
- Max memory: 512 MB.

### 18. Invocation Contract
```text
Executable: <resolved_python_path> -m schemathesis
Command Line: schemathesis run <openapi_url> --format=json --workers=1 --hypothesis-max-examples=10
Stdout: Captures JSON test runner report
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `run <schema_url>`, `--format=json`, `--workers=1`, `--hypothesis-max-examples=<int>`, `--header=<header>`.

### 20. Forbidden Arguments
- Unbounded example generation (`--hypothesis-max-examples=10000`).

### 21. Input Schema
- Validated OpenAPI / Swagger URL.

### 22. Output Format
- JSON report structure.

### 23. Output Schema
- Validated JSON containing `errors`, `checks`, `interactions`.

### 24. Exit Codes
- `0`: All tests passed. `1`: Schema violations/server errors found. `Non-zero`: Fatal error.

### 25. Failure Semantics
- Falls back to native Python API Inspector.

### 26. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- In-memory processing; descriptors closed.

### 28. Parser Specification
- Parses JSON report, extracts HTTP 500 errors and schema failures, maps to `DAST-API-003`.

### 29. Finding Normalization
- Unhandled 500 Server Error: Check ID `DAST-API-003`, Severity `MEDIUM`, CVSS 5.3, CWE-754.

### 30. Severity Mapping
- Server 500 Crash -> `Severity.MEDIUM` (5.3)
- Schema Mismatch -> `Severity.LOW` (3.1)

### 31. Taxonomy Mapping
- `CWE-754`: Improper Check for Unusual or Exceptional Conditions
- `OWASP A05:2021`: Security Misconfiguration
- `NIST SP 800-53`: `SI-11` (Error Handling)

### 32. Evidence Mapping
- Failing HTTP request body, response status, schema error message, evidence hash.

### 33. Secret Handling & Masking
- Masks auth tokens in request/response dumps.

### 34. Correlation Strategy
- Grouped with API Inspector endpoint findings.

### 35. Validation Role
- `SPECIALIZED` API robustness authority.

### 36. Reproducibility Record
- Records Schemathesis version, schema URL, seed, and failed test cases.

### 37. Update Policy
- Pip package lockfile management.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_schemathesis_adapter_json_parsing`
- `test_schemathesis_500_error_detection`

### 40. Known Limitations
- Requires accessible OpenAPI/Swagger specification endpoint.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/schemathesis_adapter.py`).

---

## TOOL 09: Semgrep

### 1. Identity
- **Tool ID:** `TOOL-SEMGREP`
- **Display Name:** Semgrep
- **Upstream Project:** Semgrep Inc. (https://github.com/semgrep/semgrep)
- **Security Domain:** Source Code SAST
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/semgrep_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Fast, polyglot static analysis and AST pattern matching across Python, JavaScript, TypeScript, Go, Java, C#, PHP, and Ruby.
- **What It Detects:** SQL injection, command injection, XSS, insecure deserialization, cryptographic failures, broken authentication, hardcoded secrets.
- **What It Does NOT Detect:** Dynamic runtime configurations, network port states.
- **Why Present:** Premier multi-language AST static analysis engine for modern application codebases.

### 3. Role
- **Classification:** `PRIMARY` SAST engine.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`, `QUICK`.

### 5. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`.

### 6. Upstream Version Policy
- **Pinned Version:** Semgrep 1.65.0+ (pip package or standalone CLI).
- **Version Detection:** `semgrep --version` -> Regex `([0-9\.]+)`

### 7. Artifact / Installation Method
- Installed via pip (`pip_installer.py`) in virtual environment.

### 8. Integrity / Provenance
- PyPI package verification in `requirements.txt`.

### 9. Required Permissions
- Read-only access to authorized workspace repository directory.

### 10. Credential Requirements
- `NOT APPLICABLE`

### 11. Workspace Requirements
- Server-derived authorized workspace jail (`Path.resolve().startswith(workspace_root)`).

### 12. Network Requirements
- Offline execution (uses local ruleset or cached rules).

### 13. Safety Policy
- Read-only static analysis; no code execution or file modifications.

### 14. Rate Limit
- `NOT APPLICABLE` (Local computation).

### 15. Concurrency
- Multi-core CPU parallel analysis managed by Semgrep engine.

### 16. Timeout
- Startup: 5.0s. Execution: 60.0s (or `config.timeout_seconds * 6`).

### 17. Resource Limits
- Max memory: 1024 MB. Max stdout: 10 MB.

### 18. Invocation Contract
```text
Executable: <resolved_semgrep_path>
Command Line: semgrep scan --config auto --json <authorized_workspace_path>
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `scan`, `--config auto`, `--config <local_rules_path>`, `--json`, `<authorized_workspace_path>`.

### 20. Forbidden Arguments
- External telemetry uploads (`--send-metrics`), code modification flags.

### 21. Input Schema
- Validated absolute filesystem path within authorized workspace.

### 22. Output Format
- Standard Semgrep JSON report.

### 23. Output Schema
- Validated JSON containing `results[].check_id`, `results[].path`, `results[].start.line`, `results[].extra.message`, `results[].extra.severity`, `results[].extra.lines`.

### 24. Exit Codes
- `0`: Scan completed successfully. `Non-zero`: Error.

### 25. Failure Semantics
- Falls back seamlessly to native Python AST taint analyzer.

### 26. Cancellation Protocol
- Immediate process tree termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Process termination cleans up all temporary memory descriptors.

### 28. Parser Specification
- Parses JSON `results[]`, maps rule IDs to canonical check catalog, extracts line numbers, code snippets, and constructs `Finding` models.

### 29. Finding Normalization
- SQL Injection -> `SAST-INJ-001` (CWE-89)
- Command Injection -> `SAST-CMD-001` (CWE-78)
- Insecure Deserialization -> `SAST-CODE-001` (CWE-502)
- Weak Cryptography -> `SAST-CRYP-001` (CWE-327)

### 30. Severity Mapping
- `ERROR` -> `Severity.HIGH` (7.5) / `Severity.CRITICAL` (9.0) based on check ID
- `WARNING` -> `Severity.MEDIUM` (5.3)
- `INFO` -> `Severity.LOW` (3.1)

### 31. Taxonomy Mapping
- `CWE-89`, `CWE-78`, `CWE-79`, `CWE-502`, `CWE-327`, `OWASP A03:2021`, `NIST SI-10`, `SC-13`.

### 32. Evidence Mapping
- File path, start line, end line, code snippet, rule description, evidence hash.

### 33. Secret Handling & Masking
- Masks any hardcoded secrets captured in code snippets.

### 34. Correlation Strategy
- Correlates with DAST findings on identical routes/parameters (SAST+DAST verification).

### 35. Validation Role
- `PRIMARY` source code security authority.

### 36. Reproducibility Record
- Records Semgrep version, ruleset version, scanned file count, and JSON output hash.

### 37. Update Policy
- Managed pip package updates.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_semgrep_adapter_json_parsing`
- `test_semgrep_injection_mapping`
- `test_semgrep_fallback`

### 40. Known Limitations
- Dynamic runtime language features (e.g. `eval` with external strings) require taint engine modeling.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/semgrep_adapter.py`).

---

## TOOL 10: Bandit

### 1. Identity
- **Tool ID:** `TOOL-BANDIT`
- **Display Name:** Bandit
- **Upstream Project:** PyCQA (https://github.com/PyCQA/bandit)
- **Security Domain:** Python Source Code SAST
- **CyberAssess Role:** `SPECIALIZED`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/bandit_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Deep AST-based vulnerability analysis specifically engineered for Python source code.
- **What It Detects:** Insecure `subprocess` with `shell=True`, hardcoded passwords, `pickle` deserialization, weak MD5/SHA1 hashing, `assert` usage in production code, SQL string formatting.
- **What It Does NOT Detect:** Non-Python codebases, dynamic web vulnerabilities.
- **Why Present:** Authoritative Python-native security linter with high precision and low false positives for Python applications.

### 3. Role
- **Classification:** `SPECIALIZED` Python SAST engine.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`, `QUICK`.

### 5. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`.

### 6. Upstream Version Policy
- **Pinned Version:** Bandit 1.7.8+ (pip package).
- **Version Detection:** `bandit --version` -> Regex `([0-9\.]+)`

### 7. Artifact / Installation Method
- Installed via pip (`pip_installer.py`).

### 8. Integrity / Provenance
- PyPI package verification in `requirements.txt`.

### 9. Required Permissions
- Read-only access to Python source files in authorized workspace.

### 10. Credential Requirements
- `NOT APPLICABLE`

### 11. Workspace Requirements
- Server-derived authorized workspace jail.

### 12. Network Requirements
- 100% offline static analysis.

### 13. Safety Policy
- Read-only AST parsing; no code execution.

### 14. Rate Limit
- `NOT APPLICABLE`

### 15. Concurrency
- Single subprocess instance.

### 16. Timeout
- Startup: 5.0s. Execution: 60.0s.

### 17. Resource Limits
- Max memory: 256 MB. Max stdout: 10 MB.

### 18. Invocation Contract
```text
Executable: <resolved_python_path> -m bandit
Command Line: bandit -r <authorized_workspace_path> -f json
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `-r <path>`, `-f json`, `-ll` (confidence filter), `-q`.

### 20. Forbidden Arguments
- Non-json output formats in automated sweeps.

### 21. Input Schema
- Validated filesystem path containing Python files.

### 22. Output Format
- Bandit JSON report.

### 23. Output Schema
- Validated JSON containing `results[].test_id`, `results[].filename`, `results[].line_number`, `results[].issue_severity`, `results[].issue_confidence`, `results[].code`.

### 24. Exit Codes
- `0`: No issues found. `1`: Issues found. `Non-zero`: Error.

### 25. Failure Semantics
- Falls back to native Python AST visitor.

### 26. Cancellation Protocol
- Immediate process tree termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Descriptors closed on exit.

### 28. Parser Specification
- Parses JSON `results[]`, maps Bandit test IDs (`B101` through `B703`) to canonical check catalog.

### 29. Finding Normalization
- `B602`/`B603` (Subprocess shell=True) -> `SAST-CMD-001` (CWE-78)
- `B301`/`B403` (Pickle deserialization) -> `SAST-CODE-001` (CWE-502)
- `B303` (MD5/SHA1 usage) -> `SAST-CRYP-001` (CWE-327)
- `B105`/`B106` (Hardcoded password) -> `SAST-SEC-001` (CWE-798)

### 30. Severity Mapping
- `HIGH` -> `Severity.HIGH` (7.5) / `Severity.CRITICAL` (9.0)
- `MEDIUM` -> `Severity.MEDIUM` (5.3)
- `LOW` -> `Severity.LOW` (3.1)

### 31. Taxonomy Mapping
- `CWE-78`, `CWE-502`, `CWE-327`, `CWE-798`, `OWASP A03:2021`, `NIST SI-10`, `SC-13`.

### 32. Evidence Mapping
- File path, line number, offending code snippet, Bandit test ID, evidence hash.

### 33. Secret Handling & Masking
- Masks hardcoded credentials in `results[].code`.

### 34. Correlation Strategy
- Clustered with Semgrep findings on identical Python files and lines.

### 35. Validation Role
- `SPECIALIZED` Python AST validation.

### 36. Reproducibility Record
- Records Bandit version, test ID list, and scanned file count.

### 37. Update Policy
- Pip package lockfile management.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_bandit_adapter_json_parsing`
- `test_bandit_subprocess_detection`
- `test_bandit_fallback`

### 40. Known Limitations
- Python source files only; ignores other languages.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/bandit_adapter.py`).

---

## TOOL 11: Gitleaks

### 1. Identity
- **Tool ID:** `TOOL-GITLEAKS`
- **Display Name:** Gitleaks
- **Upstream Project:** Gitleaks (https://github.com/gitleaks/gitleaks)
- **Security Domain:** Secret Scanning & Git History
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/gitleaks_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Fast, regex and entropy-based detection of committed secrets, API keys, private tokens, and passwords in Git commit history and filesystems.
- **What It Detects:** AWS access keys, Stripe secret keys, OpenAI tokens, GitHub personal access tokens, private SSH keys, database connection strings.
- **What It Does NOT Detect:** Code logic vulnerabilities, network misconfigurations.
- **Why Present:** Industry standard for deep Git history audit and pre-commit secret detection.

### 3. Role
- **Classification:** `PRIMARY` secret scanning engine.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`, `QUICK`.

### 5. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`.

### 6. Upstream Version Policy
- **Pinned Version:** `v8.18.2`
- **Version Detection:** `gitleaks version` -> Regex `v?([0-9\.]+)`

### 7. Artifact / Installation Method
- Standalone GitHub release binary (`github_release_installer.py`).

### 8. Integrity / Provenance
- `windows_amd64`: `22ffef9b8d28131378393c0bc506c4293f773b06ee258be0a597793d54839cf9`
- `linux_amd64`: `ea7b003a2efcaea7f311c19b02a9eb733b8a1c9ef007c6f0c6c06a350a4980a0`

### 9. Required Permissions
- Read-only access to authorized workspace repository directory.

### 10. Credential Requirements
- `NOT APPLICABLE`

### 11. Workspace Requirements
- Server-derived authorized workspace jail.

### 12. Network Requirements
- 100% offline local scanning.

### 13. Safety Policy
- Read-only Git history inspection; no file modifications.

### 14. Rate Limit
- `NOT APPLICABLE`

### 15. Concurrency
- Single subprocess instance per scan job.

### 16. Timeout
- Startup: 5.0s. Execution: 60.0s.

### 17. Resource Limits
- Max memory: 512 MB. Max stdout: 10 MB.

### 18. Invocation Contract
```text
Executable: <resolved_gitleaks_path>
Command Line: gitleaks detect --source <authorized_workspace_path> --report-format json --report-path <temp_report_path> --no-banner
Stdout: Diagnostic logs
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `detect`, `--source <path>`, `--report-format json`, `--report-path <path>`, `--no-banner`, `--redact`.

### 20. Forbidden Arguments
- Uncontrolled external config fetches.

### 21. Input Schema
- Validated repository directory path.

### 22. Output Format
- JSON report file.

### 23. Output Schema
- Validated JSON array containing `RuleID`, `Description`, `Secret`, `File`, `StartLine`, `Commit`, `Author`.

### 24. Exit Codes
- `0`: No secrets found. `1`: Secrets detected. `Non-zero`: Error.

### 25. Failure Semantics
- Falls back seamlessly to native Shannon entropy & regex secret scanner.

### 26. Cancellation Protocol
- Immediate process tree termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Temporary report file deleted immediately after parsing.

### 28. Parser Specification
- Reads temporary JSON report, extracts findings, applies mandatory multi-stage secret masking (`mask_secret()`), and generates `Finding` models.

### 29. Finding Normalization
- Hardcoded Secret -> Check ID `SAST-SEC-001`, Severity `CRITICAL`, CVSS 9.8, CWE-798.

### 30. Severity Mapping
- High-Entropy API Key / Private Key -> `Severity.CRITICAL` (9.8)
- Generic Credential -> `Severity.HIGH` (7.5)

### 31. Taxonomy Mapping
- `CWE-798`: Use of Hard-coded Credentials
- `OWASP A07:2021`: Identification and Authentication Failures
- `ASVS 5.0`: `v5.0.0-V3.6.1`
- `NIST SP 800-53`: `IA-2`, `SC-28`

### 32. Evidence Mapping
- File path, start line, commit hash, author email, masked secret snippet, SHA-256 evidence hash.

### 33. Secret Handling & Masking
- **Mandatory Masking:** Retains first 6 and last 4 characters; masks middle with `******` (e.g., `AKIAIOSFODNN******ABCD`). Unmasked raw secrets are NEVER persisted to database or logs.

### 34. Correlation Strategy
- Correlates with TruffleHog live validation and native secret scanner.

### 35. Validation Role
- `PRIMARY` static secret discovery authority.

### 36. Reproducibility Record
- Records Gitleaks version, scanned commit count, and masked finding hashes.

### 37. Update Policy
- Pinned manifest checksum updates.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_gitleaks_adapter_json_parsing`
- `test_gitleaks_secret_masking_invariant`
- `test_gitleaks_fallback`

### 40. Known Limitations
- High-entropy test fixtures or mock strings may produce false positives without verification.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/gitleaks_adapter.py`).

---

## TOOL 12: TruffleHog

### 1. Identity
- **Tool ID:** `TOOL-TRUFFLEHOG`
- **Display Name:** TruffleHog
- **Upstream Project:** Truffle Security (https://github.com/trufflesecurity/trufflehog)
- **Security Domain:** Secret Scanning & Live Verification
- **CyberAssess Role:** `VALIDATION`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/trufflehog_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Detects secrets with detector-specific live verification (e.g. verifying if an AWS key or GitHub token is currently active and authenticated).
- **What It Detects:** Valid live AWS credentials, GitHub tokens, Slack webhooks, database credentials.
- **What It Does NOT Detect:** Code logic bugs, network vulnerabilities.
- **Why Present:** Eliminates false positives by validating whether exposed secrets are active and exploitable in the wild.

### 3. Role
- **Classification:** `VALIDATION` engine.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`.

### 5. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`.

### 6. Upstream Version Policy
- **Pinned Version:** TruffleHog 3.63.0+
- **Version Detection:** `trufflehog --version` -> Regex `v?([0-9\.]+)`

### 7. Artifact / Installation Method
- Standalone binary (`github_release_installer.py`).

### 8. Integrity / Provenance
- Verified in `PINNED_TOOL_MANIFEST`.

### 9. Required Permissions
- Read-only access to authorized workspace repository directory.

### 10. Credential Requirements
- `NOT APPLICABLE`

### 11. Workspace Requirements
- Server-derived authorized workspace jail.

### 12. Network Requirements
- Outbound HTTPS access only if live secret verification is explicitly enabled in tenant policy.

### 13. Safety Policy
- Read-only live verification queries; non-destructive auth checks only.

### 14. Rate Limit
- Bounded to upstream provider limits.

### 15. Concurrency
- Single subprocess instance.

### 16. Timeout
- Startup: 5.0s. Execution: 60.0s.

### 17. Resource Limits
- Max memory: 512 MB. Max stdout: 10 MB.

### 18. Invocation Contract
```text
Executable: <resolved_trufflehog_path>
Command Line: trufflehog filesystem <authorized_workspace_path> --json --no-update
Stdout: Captures JSON stream
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `filesystem <path>`, `--json`, `--no-update`, `--only-verified`.

### 20. Forbidden Arguments
- Unbounded network sweeps without tenant authorization.

### 21. Input Schema
- Validated workspace filesystem path.

### 22. Output Format
- JSON Lines stream.

### 23. Output Schema
- Objects containing `DetectorName`, `Verified`, `Raw`, `SourceMetadata.Data.Filesystem.file`, `SourceMetadata.Data.Filesystem.line`.

### 24. Exit Codes
- `0`: No secrets. `Non-zero`: Secrets found or error.

### 25. Failure Semantics
- Falls back to Gitleaks and native secret scanner.

### 26. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Descriptors closed on exit.

### 28. Parser Specification
- Parses JSON Lines stream, verifies `Verified: true` status, masks secrets, and generates canonical findings.

### 29. Finding Normalization
- Verified Live Secret -> Check ID `SAST-SEC-001`, Severity `CRITICAL` (CVSS 10.0), CWE-798.

### 30. Severity Mapping
- Verified Live Key -> `Severity.CRITICAL` (10.0)
- Unverified Candidate -> `Severity.HIGH` (7.5)

### 31. Taxonomy Mapping
- `CWE-798`, `OWASP A07:2021`, `ASVS 5.0 v5.0.0-V3.6.1`, `NIST IA-2`.

### 32. Evidence Mapping
- Detector name, verification state, file path, line number, masked key, SHA-256 evidence digest.

### 33. Secret Handling & Masking
- Strict multi-stage secret masking enforced before persistence.

### 34. Correlation Strategy
- Confirms and upgrades unverified `Gitleaks` findings to `VERIFIED` status.

### 35. Validation Role
- `VALIDATION` authority for credential exploitability.

### 36. Reproducibility Record
- Records detector name, verification status, and masked hash.

### 37. Update Policy
- Manifest checksum updates.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_trufflehog_adapter_json_parsing`
- `test_trufflehog_verification_upgrade`

### 40. Known Limitations
- Live verification requires outbound network access to cloud provider APIs.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/trufflehog_adapter.py`).

---

## TOOL 13: Retire.js

### 1. Identity
- **Tool ID:** `TOOL-RETIREJS`
- **Display Name:** Retire.js
- **Upstream Project:** Retire.js (https://github.com/RetireJS/retire.js)
- **Security Domain:** Client-Side JavaScript SCA
- **CyberAssess Role:** `SPECIALIZED`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/retirejs_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Scans JavaScript source files and node modules for known vulnerable frontend libraries (jQuery, Bootstrap, Angular, Lodash, React).
- **What It Detects:** Outdated client-side JS libraries with published CVEs and XSS vulnerabilities.
- **What It Does NOT Detect:** Backend server logic, infrastructure misconfigurations.
- **Why Present:** Specialized precision for client-side JavaScript supply chain vulnerabilities.

### 3. Role
- **Classification:** `SPECIALIZED` JavaScript SCA engine.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`, `DAST_ONLY`.

### 5. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`.

### 6. Upstream Version Policy
- **Pinned Version:** Retire.js 4.4.0+
- **Version Detection:** `retire --version` -> Regex `([0-9\.]+)`

### 7. Artifact / Installation Method
- Standalone CLI / npm package (`system_installer.py`).

### 8. Integrity / Provenance
- Verified in `PINNED_TOOL_MANIFEST`.

### 9. Required Permissions
- Read-only workspace access.

### 10. Credential Requirements
- `NOT APPLICABLE`

### 11. Workspace Requirements
- Server-derived authorized workspace jail.

### 12. Network Requirements
- Offline scanning using bundled vulnerability database.

### 13. Safety Policy
- Read-only file inspection.

### 14. Rate Limit
- `NOT APPLICABLE`

### 15. Concurrency
- Single subprocess instance.

### 16. Timeout
- Startup: 5.0s. Execution: 60.0s.

### 17. Resource Limits
- Max memory: 256 MB.

### 18. Invocation Contract
```text
Executable: <resolved_retire_path>
Command Line: retire --path <authorized_workspace_path> --outputformat json --nodownload
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `--path <path>`, `--outputformat json`, `--nodownload`.

### 20. Forbidden Arguments
- Execution of untrusted scripts.

### 21. Input Schema
- Validated workspace filesystem path.

### 22. Output Format
- JSON report structure.

### 23. Output Schema
- Validated JSON array containing `data[].file`, `data[].results[].component`, `data[].results[].version`, `data[].results[].vulnerabilities[]`.

### 24. Exit Codes
- `0`: No issues. `Non-zero`: Vulnerabilities found or error.

### 25. Failure Semantics
- Falls back to native dependency auditor.

### 26. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Descriptors closed on exit.

### 28. Parser Specification
- Parses JSON `data[]`, extracts library names, versions, CVE IDs, and generates `Finding` models.

### 29. Finding Normalization
- Vulnerable Client JS Library -> Check ID `SAST-DEP-001`, Severity `HIGH`/`MEDIUM`, CWE-1395.

### 30. Severity Mapping
- `critical`/`high` -> `Severity.HIGH` (7.5)
- `medium` -> `Severity.MEDIUM` (5.3)
- `low` -> `Severity.LOW` (3.1)

### 31. Taxonomy Mapping
- `CWE-1395`: Dependency on Vulnerable Third-Party Component
- `OWASP A06:2021`: Vulnerable and Outdated Components
- `NIST SP 800-53`: `SA-12`, `SI-2`

### 32. Evidence Mapping
- File path, library component, installed version, CVE identifier, evidence hash.

### 33. Secret Handling & Masking
- `NOT APPLICABLE`

### 34. Correlation Strategy
- Clustered with Trivy and Grype frontend dependency findings.

### 35. Validation Role
- `SPECIALIZED` frontend JS SCA authority.

### 36. Reproducibility Record
- Records Retire.js version, component list, and CVE matches.

### 37. Update Policy
- Pinned installer management.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_retirejs_adapter_json_parsing`
- `test_retirejs_cve_mapping`

### 40. Known Limitations
- Scans JS/CSS files only; does not analyze backend language dependencies.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/retirejs_adapter.py`).

---

## TOOL 14: Trivy

### 1. Identity
- **Tool ID:** `TOOL-TRIVY`
- **Display Name:** Trivy
- **Upstream Project:** Aqua Security (https://github.com/aquasecurity/trivy)
- **Security Domain:** Container, Filesystem & Dependency SCA
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/trivy_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Comprehensive scanner for container images, filesystems, Git repositories, and lockfiles for known package CVEs, OS package vulnerabilities, and misconfigurations.
- **What It Detects:** Published CVEs across pip, npm, yarn, go.mod, maven, rubygems, cargo, composer, Docker images, and Linux OS packages (Alpine, Debian, Ubuntu, RHEL).
- **What It Does NOT Detect:** Dynamic web injection attacks, network port posture.
- **Why Present:** Industry standard multi-domain SCA and container vulnerability scanner.

### 3. Role
- **Classification:** `PRIMARY` SCA and container security engine.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`, `INFRA_CONTAINER`, `QUICK`.

### 5. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`, `DOCKERFILE`, `CONTAINER_IMAGE`.

### 6. Upstream Version Policy
- **Pinned Version:** `v0.50.0`
- **Version Detection:** `trivy --version` -> Regex `Version:\s*([0-9\.]+)`

### 7. Artifact / Installation Method
- Standalone GitHub release binary (`github_release_installer.py`).

### 8. Integrity / Provenance
- `windows_amd64`: `7ef999da89cc79aa9369d714cb9fdf3c32ef093a1f8d48e35a111a43a059f3d9`
- `linux_amd64`: `1ff1e6d2bc1050a4da61706f30a91176b6ef0aa0fefca23a63ec592ff3320f69`

### 9. Required Permissions
- Read-only workspace access (or local Docker daemon access for image scanning).

### 10. Credential Requirements
- `NOT APPLICABLE` for filesystem scans; optional registry credentials for private image pulls.

### 11. Workspace Requirements
- Server-derived authorized workspace jail.

### 12. Network Requirements
- Offline mode supported (`--offline-scan`) using pre-downloaded vulnerability DB.

### 13. Safety Policy
- Read-only static inspection; no container execution.

### 14. Rate Limit
- `NOT APPLICABLE`

### 15. Concurrency
- Multi-core CPU parallel analysis.

### 16. Timeout
- Startup: 5.0s. Execution: 60.0s.

### 17. Resource Limits
- Max memory: 1024 MB. Max stdout: 10 MB.

### 18. Invocation Contract
```text
Executable: <resolved_trivy_path>
Command Line: trivy fs --format json --offline-scan <authorized_workspace_path>
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `fs`, `image`, `--format json`, `--offline-scan`, `--severity <severities>`, `--scanners vuln,misconfig`, `<path>`.

### 20. Forbidden Arguments
- In-place remediation flags, raw binary downloads during scan.

### 21. Input Schema
- Validated workspace filesystem path or image name.

### 22. Output Format
- Standard Trivy JSON schema.

### 23. Output Schema
- Validated JSON containing `Results[].Target`, `Results[].Vulnerabilities[].VulnerabilityID`, `Results[].Vulnerabilities[].PkgName`, `Results[].Vulnerabilities[].InstalledVersion`, `Results[].Vulnerabilities[].FixedVersion`, `Results[].Vulnerabilities[].Severity`, `Results[].Vulnerabilities[].PrimaryURL`.

### 24. Exit Codes
- `0`: Scan completed. `Non-zero`: Fatal error.

### 25. Failure Semantics
- Falls back seamlessly to native lockfile dependency auditor.

### 26. Cancellation Protocol
- Immediate process tree termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Descriptors closed on exit.

### 28. Parser Specification
- Parses JSON `Results[].Vulnerabilities[]`, extracts package details, maps CVEs and fix versions to `Finding` models.

### 29. Finding Normalization
- Third-Party Vulnerable Dependency -> Check ID `SAST-DEP-001`, Severity from Trivy, CWE-1395.

### 30. Severity Mapping
- `CRITICAL` -> `Severity.CRITICAL` (9.8)
- `HIGH` -> `Severity.HIGH` (7.5)
- `MEDIUM` -> `Severity.MEDIUM` (5.3)
- `LOW` -> `Severity.LOW` (3.1)

### 31. Taxonomy Mapping
- `CWE-1395`: Dependency on Vulnerable Third-Party Component
- `OWASP A06:2021`: Vulnerable and Outdated Components
- `NIST SP 800-53`: `SA-12` (Supply Chain Protection), `SI-2` (Flaw Remediation)

### 32. Evidence Mapping
- Package name, installed version, fixed version, CVE ID, advisory URL, evidence hash.

### 33. Secret Handling & Masking
- `NOT APPLICABLE`

### 34. Correlation Strategy
- Clustered with Syft, Grype, and OSV-Scanner findings using `(package_name, version, cve_id)` key.

### 35. Validation Role
- `PRIMARY` SCA and container vulnerability authority.

### 36. Reproducibility Record
- Records Trivy version, DB version, scanned manifest count, and JSON hash.

### 37. Update Policy
- Manifest digest updates.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_trivy_adapter_json_parsing`
- `test_trivy_cve_extraction`
- `test_trivy_fallback`

### 40. Known Limitations
- Vulnerability database must be kept current for latest zero-day CVE detection.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/trivy_adapter.py`).

---

## TOOL 15: Grype

### 1. Identity
- **Tool ID:** `TOOL-GRYPE`
- **Display Name:** Grype
- **Upstream Project:** Anchore (https://github.com/anchore/grype)
- **Security Domain:** SBOM & Container Vulnerability Scanning
- **CyberAssess Role:** `VALIDATION`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/grype_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Fast dependency vulnerability matcher that ingests SBOMs (CycloneDX / SPDX) and container images, matching against Anchore's multi-source vulnerability database.
- **What It Detects:** Known CVEs, GHSA advisories, fix versions across package ecosystems and container images.
- **What It Does NOT Detect:** Static code flaws, live web vulnerabilities.
- **Why Present:** High-speed validation engine that consumes Syft-generated SBOMs to cross-verify Trivy findings.

### 3. Role
- **Classification:** `VALIDATION` engine.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`, `INFRA_CONTAINER`.

### 5. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`, `CONTAINER_IMAGE`.

### 6. Upstream Version Policy
- **Pinned Version:** `v0.74.0`
- **Version Detection:** `grype version` -> Regex `version:\s*([0-9\.]+)`

### 7. Artifact / Installation Method
- Standalone GitHub release binary (`github_release_installer.py`).

### 8. Integrity / Provenance
- `windows_amd64`: `82ff190a6e60b135bb0a3952ba5c3d4f1ea38ba662884a20b666a0eb0bb9b7c8`
- `linux_amd64`: `e30e6912a52efc188fa63e52701a2eb3a8a9bc6838a53e680a653bb26d9c9b58`

### 9. Required Permissions
- Read-only workspace access.

### 10. Credential Requirements
- `NOT APPLICABLE`

### 11. Workspace Requirements
- Server-derived authorized workspace jail.

### 12. Network Requirements
- Offline mode supported.

### 13. Safety Policy
- Read-only SBOM and file inspection.

### 14. Rate Limit
- `NOT APPLICABLE`

### 15. Concurrency
- Single subprocess instance.

### 16. Timeout
- Startup: 5.0s. Execution: 60.0s.

### 17. Resource Limits
- Max memory: 512 MB.

### 18. Invocation Contract
```text
Executable: <resolved_grype_path>
Command Line: grype dir:<authorized_workspace_path> -o json
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `dir:<path>`, `sbom:<sbom_file>`, `image:<image>`, `-o json`, `--only-fixed`.

### 20. Forbidden Arguments
- External database auto-updates during scan.

### 21. Input Schema
- Validated workspace filesystem path or SBOM file path.

### 22. Output Format
- Standard Grype JSON schema.

### 23. Output Schema
- Validated JSON containing `matches[].vulnerability.id`, `matches[].vulnerability.severity`, `matches[].artifact.name`, `matches[].artifact.version`, `matches[].vulnerability.fix.versions[]`.

### 24. Exit Codes
- `0`: Success. `Non-zero`: Error.

### 25. Failure Semantics
- Falls back to native dependency auditor.

### 26. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Descriptors closed on exit.

### 28. Parser Specification
- Parses JSON `matches[]`, maps CVEs and fix versions to `Finding` models.

### 29. Finding Normalization
- Third-Party Vulnerable Dependency -> Check ID `SAST-DEP-001`, Severity from Grype, CWE-1395.

### 30. Severity Mapping
- `Critical` -> `Severity.CRITICAL` (9.8)
- `High` -> `Severity.HIGH` (7.5)
- `Medium` -> `Severity.MEDIUM` (5.3)
- `Low` -> `Severity.LOW` (3.1)

### 31. Taxonomy Mapping
- `CWE-1395`, `OWASP A06:2021`, `NIST SA-12`.

### 32. Evidence Mapping
- Package name, version, fix versions, CVE ID, evidence hash.

### 33. Secret Handling & Masking
- `NOT APPLICABLE`

### 34. Correlation Strategy
- Cross-validates and confirms Trivy SCA findings.

### 35. Validation Role
- `VALIDATION` authority for dependency CVEs.

### 36. Reproducibility Record
- Records Grype version, DB version, and match count.

### 37. Update Policy
- Manifest digest updates.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_grype_adapter_json_parsing`
- `test_grype_cve_matching`

### 40. Known Limitations
- Relies on accurate package detection in target manifests.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/grype_adapter.py`).

---

## TOOL 16: Syft

### 1. Identity
- **Tool ID:** `TOOL-SYFT`
- **Display Name:** Syft
- **Upstream Project:** Anchore (https://github.com/anchore/syft)
- **Security Domain:** Software Bill of Materials (SBOM)
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/syft_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Generates authoritative, standard-compliant Software Bill of Materials (SBOM) documents in CycloneDX and SPDX formats from filesystems and container images.
- **What It Detects:** Complete dependency inventory, packages, licenses, component hashes, transitive dependencies.
- **What It Does NOT Detect:** Direct security vulnerabilities (used upstream of scanners).
- **Why Present:** Industry standard engine for Executive Order 14028 / SLSA compliant SBOM generation.

### 3. Role
- **Classification:** `PRIMARY` SBOM generation engine.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`, `INFRA_CONTAINER`.

### 5. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`, `CONTAINER_IMAGE`.

### 6. Upstream Version Policy
- **Pinned Version:** `v1.0.1`
- **Version Detection:** `syft version` -> Regex `version:\s*([0-9\.]+)`

### 7. Artifact / Installation Method
- Standalone GitHub release binary (`github_release_installer.py`).

### 8. Integrity / Provenance
- `windows_amd64`: `426be0eb2a297e6be9ea83664746f34586db30188aa1d3824ee18c15668db8c0`
- `linux_amd64`: `99ea78ab499c75fe95fa72ce66d3cfcbb86baebfca1a24dcaee263d91cf9679f`

### 9. Required Permissions
- Read-only workspace access.

### 10. Credential Requirements
- `NOT APPLICABLE`

### 11. Workspace Requirements
- Server-derived authorized workspace jail.

### 12. Network Requirements
- 100% offline SBOM generation.

### 13. Safety Policy
- Read-only package cataloging.

### 14. Rate Limit
- `NOT APPLICABLE`

### 15. Concurrency
- Single subprocess instance.

### 16. Timeout
- Startup: 5.0s. Execution: 60.0s.

### 17. Resource Limits
- Max memory: 512 MB.

### 18. Invocation Contract
```text
Executable: <resolved_syft_path>
Command Line: syft dir:<authorized_workspace_path> -o cyclonedx-json=<temp_output_file>
Stdout: Diagnostic logs
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `dir:<path>`, `image:<image>`, `-o cyclonedx-json=<file>`, `-o spdx-json=<file>`.

### 20. Forbidden Arguments
- Uncontrolled external uploads.

### 21. Input Schema
- Validated workspace filesystem path.

### 22. Output Format
- Standard CycloneDX 1.5 JSON or SPDX 2.3 JSON.

### 23. Output Schema
- Validated CycloneDX BOM containing `bomFormat: "CycloneDX"`, `specVersion: "1.5"`, `components[]`.

### 24. Exit Codes
- `0`: Success. `Non-zero`: Error.

### 25. Failure Semantics
- Falls back to native Python CycloneDX exporter.

### 26. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Temporary SBOM export files deleted after archiving.

### 28. Parser Specification
- Parses CycloneDX JSON, validates component records, and attaches SBOM artifact to scan session.

### 29. Finding Normalization
- `NOT APPLICABLE` (Generates asset inventory/SBOM artifact rather than direct vulnerability findings).

### 30. Severity Mapping
- `Severity.INFO` (0.0 CVSS).

### 31. Taxonomy Mapping
- `NIST SP 800-53`: `CM-8`, `SA-12`.

### 32. Evidence Mapping
- Complete serialized CycloneDX SBOM JSON string and SHA-256 evidence digest.

### 33. Secret Handling & Masking
- Sanitizes file paths in component metadata.

### 34. Correlation Strategy
- Feeds SBOM components directly into Grype for secondary vulnerability matching.

### 35. Validation Role
- `PRIMARY` software inventory authority.

### 36. Reproducibility Record
- Records Syft version, component count, and SBOM SHA-256 digest.

### 37. Update Policy
- Manifest digest updates.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_syft_adapter_cyclonedx_generation`
- `test_syft_spdx_generation`

### 40. Known Limitations
- Catalogs manifest and binary dependencies; does not analyze dynamic runtime memory loading.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/syft_adapter.py`).

---

## TOOL 17: OSV-Scanner

### 1. Identity
- **Tool ID:** `TOOL-OSV-SCANNER`
- **Display Name:** OSV-Scanner
- **Upstream Project:** Google (https://github.com/google/osv-scanner)
- **Security Domain:** Open Source Vulnerability Database SCA
- **CyberAssess Role:** `SPECIALIZED`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/osv_scanner_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Direct query interface into Google's authoritative Open Source Vulnerabilities (OSV) distributed database across npm, PyPI, Go, Maven, Rust, Packagist, and Debian.
- **What It Detects:** Published CVEs and GHSA advisories with precise commit-level vulnerability ranges.
- **What It Does NOT Detect:** Static code flaws, web DAST issues.
- **Why Present:** High-precision vulnerability intelligence backed directly by Google's OSV schema.

### 3. Role
- **Classification:** `SPECIALIZED` OSV intelligence engine.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`, `SAST_ONLY`.

### 5. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`.

### 6. Upstream Version Policy
- **Pinned Version:** `v1.7.0`
- **Version Detection:** `osv-scanner --version` -> Regex `v?([0-9\.]+)`

### 7. Artifact / Installation Method
- Standalone GitHub release binary (`github_release_installer.py`).

### 8. Integrity / Provenance
- `windows_amd64`: `9812e987c1cb50faeeeb14c330f878f0d8a7c2b6ca8858e999905f15d9715bf8`
- `linux_amd64`: `a3b836ec3b2a8d381048b6c59b66f272a0ba0508ffb6a7a7262078696ec09138`

### 9. Required Permissions
- Read-only workspace access.

### 10. Credential Requirements
- `NOT APPLICABLE`

### 11. Workspace Requirements
- Server-derived authorized workspace jail.

### 12. Network Requirements
- Outbound HTTPS access to `api.osv.dev` (or local offline lockfile matching).

### 13. Safety Policy
- Read-only package metadata inspection.

### 14. Rate Limit
- Bounded to OSV API limits.

### 15. Concurrency
- Single subprocess instance.

### 16. Timeout
- Startup: 5.0s. Execution: 60.0s.

### 17. Resource Limits
- Max memory: 512 MB.

### 18. Invocation Contract
```text
Executable: <resolved_osv_scanner_path>
Command Line: osv-scanner --json -r <authorized_workspace_path>
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `--json`, `-r <path>`, `--lockfile=<file>`, `--config=<file>`.

### 20. Forbidden Arguments
- Auto-remediation flags altering source lockfiles.

### 21. Input Schema
- Validated workspace filesystem path.

### 22. Output Format
- Standard OSV JSON schema.

### 23. Output Schema
- Validated JSON containing `results[].packages[].package.name`, `results[].packages[].package.version`, `results[].packages[].vulnerabilities[].id`.

### 24. Exit Codes
- `0`: No vulnerabilities. `1`: Vulnerabilities found. `Non-zero`: Error.

### 25. Failure Semantics
- Falls back to native dependency auditor.

### 26. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Descriptors closed on exit.

### 28. Parser Specification
- Parses JSON `results[]`, maps OSV/GHSA/CVE IDs to canonical `Finding` models.

### 29. Finding Normalization
- Third-Party Dependency Vulnerability -> Check ID `SAST-DEP-001`, Severity from OSV, CWE-1395.

### 30. Severity Mapping
- `CRITICAL` -> `Severity.CRITICAL` (9.8)
- `HIGH` -> `Severity.HIGH` (7.5)
- `MODERATE` / `MEDIUM` -> `Severity.MEDIUM` (5.3)
- `LOW` -> `Severity.LOW` (3.1)

### 31. Taxonomy Mapping
- `CWE-1395`, `OWASP A06:2021`, `NIST SA-12`.

### 32. Evidence Mapping
- Package name, version, OSV ID, advisory summary, evidence hash.

### 33. Secret Handling & Masking
- `NOT APPLICABLE`

### 34. Correlation Strategy
- Clustered with Trivy and Grype findings.

### 35. Validation Role
- `SPECIALIZED` Google OSV intelligence authority.

### 36. Reproducibility Record
- Records OSV-Scanner version, scanned lockfiles, and match count.

### 37. Update Policy
- Manifest digest updates.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_osv_scanner_adapter_json_parsing`
- `test_osv_scanner_cve_mapping`

### 40. Known Limitations
- Requires presence of supported package manager lockfiles (package-lock.json, poetry.lock, go.sum, etc.).

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/osv_scanner_adapter.py`).

---

## TOOL 18: Checkov

### 1. Identity
- **Tool ID:** `TOOL-CHECKOV`
- **Display Name:** Checkov
- **Upstream Project:** Bridgecrew / Prisma Cloud (https://github.com/bridgecrewio/checkov)
- **Security Domain:** Infrastructure-as-Code (IaC) & Cloud Posture
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/checkov_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Static code analysis for Infrastructure-as-Code (IaC) files covering Terraform, CloudFormation, Kubernetes YAML, Dockerfiles, ARM templates, and Serverless frameworks.
- **What It Detects:** Publicly exposed S3 buckets, unrestricted security groups (`0.0.0.0/0`), missing encryption at rest, root container processes, privileged Kubernetes pods, missing TLS policies.
- **What It Does NOT Detect:** Dynamic web injection bugs, live network services.
- **Why Present:** Authoritative multi-framework IaC security linter and CIS benchmark compliance engine.

### 3. Role
- **Classification:** `PRIMARY` IaC security analysis engine.

### 4. Supported CyberAssess Profiles
- `FULL_STACK`, `INFRA_ONLY`, `SAST_ONLY`, `INFRA_CONTAINER`.

### 5. Supported Target Types
- `LOCAL_PATH`, `REPOSITORY`, `IAC_MANIFEST`, `DOCKERFILE`.

### 6. Upstream Version Policy
- **Pinned Version:** Checkov 3.2.0+ (pip package).
- **Version Detection:** `checkov --version` -> Regex `([0-9\.]+)`

### 7. Artifact / Installation Method
- Installed via pip (`pip_installer.py`) in isolated venv.

### 8. Integrity / Provenance
- PyPI package verification in `requirements.txt`.

### 9. Required Permissions
- Read-only workspace access to IaC manifests.

### 10. Credential Requirements
- `NOT APPLICABLE` for static IaC file analysis.

### 11. Workspace Requirements
- Server-derived authorized workspace jail.

### 12. Network Requirements
- 100% offline static inspection.

### 13. Safety Policy
- Read-only file inspection; zero resource provisioning.

### 14. Rate Limit
- `NOT APPLICABLE`

### 15. Concurrency
- Multi-core CPU parallel parsing.

### 16. Timeout
- Startup: 5.0s. Execution: 60.0s.

### 17. Resource Limits
- Max memory: 1024 MB. Max stdout: 10 MB.

### 18. Invocation Contract
```text
Executable: <resolved_python_path> -m checkov
Command Line: checkov -d <authorized_workspace_path> -o json --quiet --compact
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `-d <dir>`, `-f <file>`, `-o json`, `--quiet`, `--compact`, `--framework <frameworks>`.

### 20. Forbidden Arguments
- External Bridgecrew cloud sync flags (`--bc-api-key`), telemetry uploads.

### 21. Input Schema
- Validated workspace filesystem path.

### 22. Output Format
- Checkov JSON report.

### 23. Output Schema
- Validated JSON containing `results.failed_checks[].check_id`, `results.failed_checks[].check_name`, `results.failed_checks[].file_path`, `results.failed_checks[].file_line_range`, `results.failed_checks[].guideline`.

### 24. Exit Codes
- `0`: All policies passed. `1`: Failed policies detected. `Non-zero`: Error.

### 25. Failure Semantics
- Falls back seamlessly to native Dockerfile, Kubernetes, and Terraform AST linters.

### 26. Cancellation Protocol
- Immediate process tree termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Descriptors closed on exit.

### 28. Parser Specification
- Parses JSON `failed_checks[]`, maps Checkov check IDs (e.g. `CKV_AWS_20`, `CKV_DOCKER_1`) to canonical `Finding` models.

### 29. Finding Normalization
- Public S3 Bucket -> `IAC-TF-001` (CWE-732), Severity `HIGH`, CVSS 7.5
- Unrestricted Ingress (0.0.0.0/0) -> `IAC-TF-002` (CWE-284), Severity `HIGH`, CVSS 7.5
- Container Root User -> `IAC-DOCKER-001` (CWE-250), Severity `HIGH`, CVSS 7.5
- Privileged K8s Pod -> `IAC-K8S-001` (CWE-732), Severity `CRITICAL`, CVSS 9.0

### 30. Severity Mapping
- Checkov `FAILED` checks mapped to `Severity.HIGH` or `Severity.CRITICAL` based on resource criticality.

### 31. Taxonomy Mapping
- `CWE-732`, `CWE-284`, `CWE-250`, `OWASP A05:2021`, `NIST SP 800-53`: `AC-3`, `AC-6`, `CM-7`.

### 32. Evidence Mapping
- File path, line range, failed policy name, guideline URL, code snippet, evidence hash.

### 33. Secret Handling & Masking
- Masks any hardcoded variables in IaC snippets.

### 34. Correlation Strategy
- Correlates with Dockle and native IaC engine findings.

### 35. Validation Role
- `PRIMARY` Infrastructure-as-Code security authority.

### 36. Reproducibility Record
- Records Checkov version, scanned framework list, and failed policy count.

### 37. Update Policy
- Pip package lockfile management.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_checkov_adapter_json_parsing`
- `test_checkov_s3_public_detection`
- `test_checkov_fallback`

### 40. Known Limitations
- Analyzes static configuration files; does not inspect live cloud runtime state.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/checkov_adapter.py`).

---

## TOOL 19: Prowler

### 1. Identity
- **Tool ID:** `TOOL-PROWLER`
- **Display Name:** Prowler
- **Upstream Project:** Prowler (https://github.com/prowler-cloud/prowler)
- **Security Domain:** Multi-Cloud Posture & CIS Benchmarks
- **CyberAssess Role:** `PRIMARY`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/prowler_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Multi-cloud security posture assessment (CSPM) across AWS, Azure, GCP, and Kubernetes for CIS Benchmarks, GDPR, HIPAA, and ISO 27001 compliance.
- **What It Detects:** Unencrypted cloud databases, missing MFA on root accounts, overly permissive IAM roles, public storage buckets, unlogged API gateways.
- **What It Does NOT Detect:** Static source code vulnerabilities, dynamic web injections.
- **Why Present:** Industry standard multi-cloud CIS benchmark compliance and audit engine.

### 3. Role
- **Classification:** `PRIMARY` cloud security posture engine.

### 4. Supported CyberAssess Profiles
- `INFRA_ONLY`, `FULL_STACK`.

### 5. Supported Target Types
- `CLOUD_ACCOUNT`, `KUBERNETES_CLUSTER`.

### 6. Upstream Version Policy
- **Pinned Version:** Prowler 4.1.0+ (pip package).
- **Version Detection:** `prowler -v` -> Regex `([0-9\.]+)`

### 7. Artifact / Installation Method
- Installed via pip (`pip_installer.py`).

### 8. Integrity / Provenance
- PyPI package verification in `requirements.txt`.

### 9. Required Permissions
- Read-only cloud audit credentials (`SecurityAudit` or `ViewOnlyAccess` IAM policies).

### 10. Credential Requirements
- Ephemeral cloud audit tokens injected via environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`).

### 11. Workspace Requirements
- `NOT APPLICABLE`

### 12. Network Requirements
- Outbound HTTPS access to cloud provider management APIs (AWS, Azure, GCP).

### 13. Safety Policy
- Read-only API queries strictly enforced; zero state-changing or resource modifying calls.

### 14. Rate Limit
- Bounded to cloud provider API rate limits.

### 15. Concurrency
- Single subprocess instance.

### 16. Timeout
- Startup: 5.0s. Execution: 120.0s.

### 17. Resource Limits
- Max memory: 1024 MB. Max stdout: 10 MB.

### 18. Invocation Contract
```text
Executable: <resolved_python_path> -m prowler
Command Line: prowler aws -M json-asff --output-filename <temp_output_path> --quiet
Stdout: Diagnostic logs
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `aws`, `azure`, `gcp`, `kubernetes`, `-M json-asff`, `--output-filename <path>`, `--quiet`, `--services <services>`, `--compliance <compliance>`.

### 20. Forbidden Arguments
- Any destructive or mutating flags.

### 21. Input Schema
- Validated cloud account target with scoped read-only credentials.

### 22. Output Format
- AWS Security Finding Format (ASFF) JSON report.

### 23. Output Schema
- Validated ASFF JSON containing `Findings[].Title`, `Findings[].Severity.Label`, `Findings[].Compliance.Status`, `Findings[].Remediation.Recommendation.Text`.

### 24. Exit Codes
- `0`: Scan completed. `Non-zero`: Authentication failure or API error.

### 25. Failure Semantics
- Falls back to native Terraform and Cloud posture checks.

### 26. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Injected temporary credentials wiped from process memory; report files deleted.

### 28. Parser Specification
- Parses ASFF JSON, extracts failed compliance controls, maps to `Finding` models.

### 29. Finding Normalization
- Cloud Posture Failure -> Check ID `IAC-CLOUD-001`, Severity from ASFF, CWE-284.

### 30. Severity Mapping
- `CRITICAL` -> `Severity.CRITICAL` (9.8)
- `HIGH` -> `Severity.HIGH` (7.5)
- `MEDIUM` -> `Severity.MEDIUM` (5.3)
- `LOW` -> `Severity.LOW` (3.1)

### 31. Taxonomy Mapping
- `CWE-284`, `CWE-732`, `OWASP A05:2021`, `NIST SP 800-53`: `AC-3`, `AC-6`, `IA-2`.

### 32. Evidence Mapping
- Cloud resource ARN, region, failed check ID, remediation text, evidence hash.

### 33. Secret Handling & Masking
- Sanitizes cloud account IDs and access keys in stored evidence.

### 34. Correlation Strategy
- Grouped by cloud resource identifier across scan sessions.

### 35. Validation Role
- `PRIMARY` cloud posture compliance authority.

### 36. Reproducibility Record
- Records Prowler version, cloud account ID, benchmark version, and finding count.

### 37. Update Policy
- Pip package lockfile management.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_prowler_adapter_asff_parsing`
- `test_prowler_cloud_finding_mapping`

### 40. Known Limitations
- Requires pre-configured read-only cloud credentials with appropriate IAM permissions.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/prowler_adapter.py`).

---

## TOOL 20: Kube-Bench

### 1. Identity
- **Tool ID:** `TOOL-KUBE-BENCH`
- **Display Name:** Kube-Bench
- **Upstream Project:** Aqua Security (https://github.com/aquasecurity/kube-bench)
- **Security Domain:** Kubernetes CIS Benchmark Auditing
- **CyberAssess Role:** `SPECIALIZED`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/kubebench_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Verifies whether a Kubernetes cluster is configured securely according to the CIS Kubernetes Benchmark standards.
- **What It Detects:** Insecure kubelet parameters, unencrypted etcd communication, anonymous authentication enabled on API server, missing RBAC policies.
- **What It Does NOT Detect:** Web application bugs, source code vulnerabilities.
- **Why Present:** Authoritative CIS Kubernetes benchmark compliance checker.

### 3. Role
- **Classification:** `SPECIALIZED` Kubernetes compliance engine.

### 4. Supported CyberAssess Profiles
- `INFRA_ONLY`, `FULL_STACK`.

### 5. Supported Target Types
- `KUBERNETES_CLUSTER`, `LOCAL_PATH` (Manifest mode).

### 6. Upstream Version Policy
- **Pinned Version:** `v0.7.0`
- **Version Detection:** `kube-bench version` -> Regex `v?([0-9\.]+)`

### 7. Artifact / Installation Method
- Standalone GitHub release binary (`github_release_installer.py`).

### 8. Integrity / Provenance
- Verified in `PINNED_TOOL_MANIFEST`.

### 9. Required Permissions
- Read-only access to Kubernetes cluster configuration files (`/etc/kubernetes/`) or manifest directory.

### 10. Credential Requirements
- `NOT APPLICABLE` in manifest mode; standard read-only kubeconfig in cluster mode.

### 11. Workspace Requirements
- Server-derived authorized workspace jail.

### 12. Network Requirements
- Offline in manifest mode; local cluster API access in in-cluster mode.

### 13. Safety Policy
- Read-only configuration auditing; zero pod execution.

### 14. Rate Limit
- `NOT APPLICABLE`

### 15. Concurrency
- Single subprocess instance.

### 16. Timeout
- Startup: 5.0s. Execution: 60.0s.

### 17. Resource Limits
- Max memory: 256 MB.

### 18. Invocation Contract
```text
Executable: <resolved_kube_bench_path>
Command Line: kube-bench --json
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `--json`, `--config-dir=<path>`, `--benchmark=<version>`, `--targets=master,node,etcd`.

### 20. Forbidden Arguments
- Root execution wrappers outside container sandbox.

### 21. Input Schema
- Validated Kubernetes manifest path or cluster context.

### 22. Output Format
- Kube-bench JSON schema.

### 23. Output Schema
- Validated JSON containing `Controls[].tests[].results[].test_number`, `test_desc`, `status`, `remediation`.

### 24. Exit Codes
- `0`: Completed. `Non-zero`: Error.

### 25. Failure Semantics
- Falls back to native Kubernetes YAML manifest auditor.

### 26. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Descriptors closed on exit.

### 28. Parser Specification
- Parses JSON `Controls[].tests[].results[]`, filters `status: "FAIL"`, maps to `Finding` models.

### 29. Finding Normalization
- Kubernetes CIS Benchmark Failure -> Check ID `IAC-K8S-002`, Severity `HIGH`/`MEDIUM`, CWE-284.

### 30. Severity Mapping
- `FAIL` on Master/API Server -> `Severity.HIGH` (7.5)
- `FAIL` on Node/Kubelet -> `Severity.MEDIUM` (5.3)
- `WARN` -> `Severity.LOW` (3.1)

### 31. Taxonomy Mapping
- `CWE-284`, `OWASP A05:2021`, `NIST SP 800-53`: `AC-3`, `CM-7`.

### 32. Evidence Mapping
- Test number, test description, remediation string, evidence hash.

### 33. Secret Handling & Masking
- Masks any cert paths or tokens in test descriptions.

### 34. Correlation Strategy
- Clustered with Checkov K8s findings.

### 35. Validation Role
- `SPECIALIZED` Kubernetes CIS benchmark authority.

### 36. Reproducibility Record
- Records Kube-bench version, CIS benchmark version, and failed test count.

### 37. Update Policy
- Manifest digest updates.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_kubebench_adapter_json_parsing`
- `test_kubebench_fail_status_mapping`

### 40. Known Limitations
- In-cluster execution requires host filesystem access to `/etc/kubernetes/`.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/kubebench_adapter.py`).

---

## TOOL 21: Dockle

### 1. Identity
- **Tool ID:** `TOOL-DOCKLE`
- **Display Name:** Dockle
- **Upstream Project:** GoodWithTech (https://github.com/goodwithtech/dockle)
- **Security Domain:** Container Image Hardening & CIS Docker
- **CyberAssess Role:** `SPECIALIZED`
- **Evidence Basis:** `VERIFIED FROM REPOSITORY` (`backend/app/adapters/dockle_adapter.py`)

### 2. Security Purpose
- **Problem Solved:** Container image linter verifying compliance with CIS Docker Benchmarks, best practices, and security hardening rules.
- **What It Detects:** Container processes running as root (`CIS-DI-0001`), hardcoded secrets/passwords in image layers (`CIS-DI-0005`), unneeded setuid/setgid permissions, missing Content Trust.
- **What It Does NOT Detect:** Dynamic web injection bugs, network port exposure.
- **Why Present:** High-precision container image hardening auditor for DevSecOps build pipelines.

### 3. Role
- **Classification:** `SPECIALIZED` container image hardening linter.

### 4. Supported CyberAssess Profiles
- `INFRA_CONTAINER`, `INFRA_ONLY`, `FULL_STACK`.

### 5. Supported Target Types
- `CONTAINER_IMAGE`, `DOCKERFILE`.

### 6. Upstream Version Policy
- **Pinned Version:** `v0.4.14`
- **Version Detection:** `dockle -v` -> Regex `version:\s*([0-9\.]+)`

### 7. Artifact / Installation Method
- Standalone GitHub release binary (`github_release_installer.py`).

### 8. Integrity / Provenance
- `windows_amd64`: `fca8987ec89da3b764b8bb26c3674681467ea309db8935c1ba9c0a373b9e4a8b`
- `linux_amd64`: `64d0a3ec74f63cbb2f97f740a6b98686fba7fa01f5c6adbc81c81ef4554b5ec9`

### 9. Required Permissions
- Read-only access to local Docker daemon or image tarball.

### 10. Credential Requirements
- `NOT APPLICABLE` for local images.

### 11. Workspace Requirements
- Server-derived authorized workspace jail.

### 12. Network Requirements
- 100% offline local image inspection.

### 13. Safety Policy
- Static image layer inspection; zero container execution.

### 14. Rate Limit
- `NOT APPLICABLE`

### 15. Concurrency
- Single subprocess instance.

### 16. Timeout
- Startup: 5.0s. Execution: 60.0s.

### 17. Resource Limits
- Max memory: 512 MB.

### 18. Invocation Contract
```text
Executable: <resolved_dockle_path>
Command Line: dockle -f json <image_name>
Stdout: Captures JSON results
Stderr: Diagnostic logs
```

### 19. Allowed Arguments
- `-f json`, `--exit-code 0`, `--ignore <codes>`, `<image_name>`.

### 20. Forbidden Arguments
- Uncontrolled remote socket execution.

### 21. Input Schema
- Validated container image name or archive path.

### 22. Output Format
- Dockle JSON report.

### 23. Output Schema
- Validated JSON containing `details[].code`, `details[].title`, `details[].level`, `details[].alerts[]`.

### 24. Exit Codes
- `0`: No fatal issues. `Non-zero`: Issues found or error.

### 25. Failure Semantics
- Falls back to native Dockerfile security linter.

### 26. Cancellation Protocol
- Process group termination via `ProcessSupervisor`.

### 27. Cleanup Policy
- Descriptors closed on exit.

### 28. Parser Specification
- Parses JSON `details[]`, extracts CIS Docker codes (`CIS-DI-0001` through `CIS-DI-0010`), maps to `Finding` models.

### 29. Finding Normalization
- `CIS-DI-0001` (Root User) -> `IAC-DOCKER-001` (CWE-250), Severity `HIGH`, CVSS 7.5
- `CIS-DI-0005` (Secret in Image) -> `IAC-DOCKER-002` (CWE-522), Severity `CRITICAL`, CVSS 9.0

### 30. Severity Mapping
- `FATAL` -> `Severity.CRITICAL` (9.0)
- `WARN` -> `Severity.HIGH` (7.5)
- `INFO` -> `Severity.LOW` (3.1)

### 31. Taxonomy Mapping
- `CWE-250`: Execution with Unnecessary Privileges
- `CWE-522`: Insufficiently Protected Credentials
- `OWASP A05:2021`: Security Misconfiguration
- `NIST SP 800-53`: `AC-6`, `IA-2`

### 32. Evidence Mapping
- CIS code, alert description, image layer hash, evidence hash.

### 33. Secret Handling & Masking
- Masks any secret tokens detected in image layer history.

### 34. Correlation Strategy
- Clustered with Trivy and Checkov Dockerfile findings.

### 35. Validation Role
- `SPECIALIZED` container image hardening authority.

### 36. Reproducibility Record
- Records Dockle version, image digest, and alert count.

### 37. Update Policy
- Manifest digest updates.

### 38. Deprecation Policy
- Active core tool.

### 39. Required Tests
- `test_dockle_adapter_json_parsing`
- `test_dockle_root_user_mapping`
- `test_dockle_fallback`

### 40. Known Limitations
- Requires local Docker daemon or exported container tarball.

### 41. Verification Status
- `VERIFIED FROM REPOSITORY` (`backend/app/adapters/dockle_adapter.py`).

---

# Part III: Verification, Test Traceability & Assurance Matrix

## 1. Tool-to-Contract Traceability Matrix

| Tool ID | Display Name | Role | Primary Check IDs | Test Suite Reference | Upstream Project |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `TOOL-NMAP` | Nmap | `PRIMARY` | `NET-PORT-001/2`, `NET-SVC-001` | `tests/test_adapters.py::TestNmapAdapter` | Insecure.Org |
| `TOOL-SSLYZE` | SSLyze | `PRIMARY` | `NET-TLS-001/2/3` | `tests/test_adapters.py::TestSslyzeAdapter` | Nabla C0d3 |
| `TOOL-SUBFINDER` | Subfinder | `PRIMARY` | `NET-OSINT-001` | `tests/test_adapters.py::TestSubfinderAdapter` | ProjectDiscovery |
| `TOOL-HTTPX` | httpx | `VALIDATION` | `NET-HTTP-001` | `tests/test_adapters.py::TestHttpxAdapter` | ProjectDiscovery |
| `TOOL-NUCLEI` | Nuclei | `PRIMARY` | `DAST-INJ-001`, `DAST-EXP-001` | `tests/test_adapters.py::TestNucleiAdapter` | ProjectDiscovery |
| `TOOL-FFUF` | FFuF | `SPECIALIZED` | `DAST-EXP-001`, `DAST-PARAM-001` | `tests/test_adapters.py::TestFfufAdapter` | FFuF |
| `TOOL-KATANA` | Katana | `PRIMARY` | `DAST-CRAWL-001` | `tests/test_adapters.py::TestKatanaAdapter` | ProjectDiscovery |
| `TOOL-SCHEMATHESIS` | Schemathesis | `SPECIALIZED` | `DAST-API-003` | `tests/test_adapters.py::TestSchemathesisAdapter` | Schemathesis |
| `TOOL-SEMGREP` | Semgrep | `PRIMARY` | `SAST-INJ-001`, `SAST-CMD-001` | `tests/test_adapters.py::TestSemgrepAdapter` | Semgrep Inc. |
| `TOOL-BANDIT` | Bandit | `SPECIALIZED` | `SAST-CMD-001`, `SAST-CRYP-001` | `tests/test_adapters.py::TestBanditAdapter` | PyCQA |
| `TOOL-GITLEAKS` | Gitleaks | `PRIMARY` | `SAST-SEC-001` | `tests/test_adapters.py::TestGitleaksAdapter` | Gitleaks |
| `TOOL-TRUFFLEHOG` | TruffleHog | `VALIDATION` | `SAST-SEC-001` | `tests/test_adapters.py::TestTruffleHogAdapter` | Truffle Security |
| `TOOL-RETIREJS` | Retire.js | `SPECIALIZED` | `SAST-DEP-001` | `tests/test_adapters.py::TestRetireJSAdapter` | Retire.js |
| `TOOL-TRIVY` | Trivy | `PRIMARY` | `SAST-DEP-001`, `IAC-DOCKER-001` | `tests/test_adapters.py::TestTrivyAdapter` | Aqua Security |
| `TOOL-GRYPE` | Grype | `VALIDATION` | `SAST-DEP-001` | `tests/test_adapters.py::TestGrypeAdapter` | Anchore |
| `TOOL-SYFT` | Syft | `PRIMARY` | `SAST-SBOM-001` | `tests/test_adapters.py::TestSyftAdapter` | Anchore |
| `TOOL-OSV-SCANNER` | OSV-Scanner | `SPECIALIZED` | `SAST-DEP-001` | `tests/test_adapters.py::TestOSVScannerAdapter` | Google |
| `TOOL-CHECKOV` | Checkov | `PRIMARY` | `IAC-TF-001/2`, `IAC-DOCKER-001` | `tests/test_adapters.py::TestCheckovAdapter` | Prisma Cloud |
| `TOOL-PROWLER` | Prowler | `PRIMARY` | `IAC-CLOUD-001` | `tests/test_adapters.py::TestProwlerAdapter` | Prowler |
| `TOOL-KUBE-BENCH` | Kube-Bench | `SPECIALIZED` | `IAC-K8S-002` | `tests/test_adapters.py::TestKubeBenchAdapter` | Aqua Security |
| `TOOL-DOCKLE` | Dockle | `SPECIALIZED` | `IAC-DOCKER-001/2` | `tests/test_adapters.py::TestDockleAdapter` | GoodWithTech |

---

## 2. Mandatory Test Coverage Invariant

Every tool adapter MUST have unit and integration test coverage in `tests/test_adapters.py` proving:
1. Deterministic version extraction from `--version` command.
2. Standard output parsing (JSON / XML / Line Stream).
3. Finding normalization to canonical check IDs, CWE, and NIST controls.
4. Mandatory multi-stage secret masking.
5. 100% graceful fallback to native Python checks when binary is missing or times out.
