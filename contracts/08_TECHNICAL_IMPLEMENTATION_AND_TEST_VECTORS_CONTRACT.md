# Contract 08: Technical Implementation, Execution Algorithms & Test Vectors Contract

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 8.0.0 (Enterprise ASPM & EASM Suite, 22-Tool Parity, Software Supply Chain & CIS Benchmarks Architecture Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Engine Implementation Algorithms, Test Vectors, Parser Mechanics & Remediation Templates  

---

## 1. Universal Engine Execution Lifecycle Pipeline

Every security check executed across all 5 engines and 10 adapters MUST operate according to this deterministic 6-stage lifecycle pipeline:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      STANDARDIZED CHECK EXECUTION PIPELINE                  │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. TARGET APPLICABILITY  ──► 2. RATE LIMITER TOKEN ACQUISITION              │
│ 3. ASYNC I/O WITH TIMEOUT ──► 4. ALGORITHMIC PARSING & DECISION TREE        │
│ 5. EVIDENCE & SECRET MASK ──► 6. REAL-TIME SSE EMISSION & LOCAL PERSISTENCE │
└─────────────────────────────────────────────────────────────────────────────┘
```

1. **Target Applicability Validation:** Verifies target type matches the check requirements.
2. **Rate Limiter Token Acquisition:** Acquires token from Token Bucket (default: 5 RPS) before any network I/O.
3. **Async I/O with Strict Timeout:** Executes bounded I/O wrapped in `asyncio.wait_for()` (HTTP $\le 10\text{s}$, Sockets $\le 2\text{s}$, DNS $\le 3\text{s}$, crt.sh $\le 10\text{s}$, Tool Adapters $\le 60\text{s}$).
4. **Algorithmic Decision Tree:** Evaluates raw response/AST/XML/JSON against canonical rule criteria.
5. **Evidence Formatting & Secret Masking:** Normalizes `observed_value`, `expected_value`, and redacts secrets.
6. **Real-time SSE Emission:** Instantly emits `event: finding`, `event: log`, and `event: tool_status` callbacks to connected clients.

---

## 2. Engine 1: Network Perimeter, TLS/SSL, DNS & OSINT (`network`)

### 2.1 TLS/SSL Certificate & Protocol Auditing (`tls_auditor.py`)
- **Dependencies:** `asyncio`, `ssl`, `cryptography.x509`

```python
# Technical Algorithm: Certificate Parsing & Expiration Calculation
async def audit_tls_certificate(hostname: str, port: int = 443) -> List[Finding]:
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    # 1. Establish async SSL socket
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(hostname, port, ssl=ssl_context),
        timeout=5.0
    )
    sslobj = writer.get_extra_info('ssl_object')
    der_cert = sslobj.getpeercert(binary_form=True)
    writer.close()
    await writer.wait_closed()
    
    # 2. Parse X.509 structure with cryptography library
    cert = x509.load_der_x509_certificate(der_cert)
    now = datetime.now(timezone.utc)
    expiry = cert.not_valid_after_utc
    days_left = (expiry - now).days
    
    # 3. Decision Tree:
    if days_left < 0:
        # NET-TLS-001: CRITICAL (CVSS 9.1)
        pass
    elif days_left <= 7:
        # NET-TLS-002: HIGH (CVSS 7.5)
        pass
    elif days_left <= 30:
        # NET-TLS-003: MEDIUM (CVSS 5.3)
        pass
```

- **SWEET32 & Deprecated Protocol Probing (`NET-TLS-005`, `NET-TLS-006`):**
  - Attempts handshakes using TLSv1.0/1.1 contexts and checks for 3DES ciphersuites (`3DES`, `DES-CBC3-SHA`).

---

### 2.2 DNS Records, Email Security & DNSSEC (`dns_hygiene.py`)
- **Dependencies:** `dnspython` (`dns.asyncresolver`, `dns.query`, `dns.zone`)

```python
# Technical Algorithm: SPF, DMARC, MTA-STS, DNSSEC & AXFR Probes
async def audit_dns_hygiene(domain: str) -> List[Finding]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 3.0
    
    # 1. SPF TXT Query
    txt_records = await resolver.resolve(domain, 'TXT')
    spf = [r.to_text().strip('"') for r in txt_records if 'v=spf1' in r.to_text()]
    # If missing -> NET-DNS-001 (MEDIUM)
    # If '+all' in spf[0] -> NET-DNS-002 (HIGH)
    
    # 2. DMARC Query
    dmarc_records = await resolver.resolve(f"_dmarc.{domain}", 'TXT')
    # If NXDOMAIN -> NET-DNS-003 (MEDIUM)
    # If 'p=none' -> NET-DNS-004 (LOW)
    
    # 3. MTA-STS & TLS-RPT Queries
    mta_sts = await resolver.resolve(f"_mta-sts.{domain}", 'TXT') # NET-DNS-006
    
    # 4. DNSSEC (DNSKEY & DS Records)
    dnskeys = await resolver.resolve(domain, 'DNSKEY') # NET-DNS-007
    
    # 5. Zone Transfer (AXFR) Test
    ns_records = await resolver.resolve(domain, 'NS')
    for ns in ns_records:
        ns_ip = str(ns)
        # Attempt safe non-destructive AXFR
        # If records returned -> NET-DNS-008 (HIGH)
```

---

### 2.3 Exposed Ports & Service Daemon Banner Grabbing (`port_checker.py`, `banner_grabber.py`)
- **Port Matrix:** `21` (FTP), `22` (SSH), `23` (Telnet), `3306` (MySQL), `5432` (PostgreSQL), `6379` (Redis), `27017` (MongoDB), `9200` (Elasticsearch).
- **Banner Grabbing Algorithm:**
  - Connects to open port, reads first 256 bytes with 1.5s timeout.
  - Matches version signatures (e.g. `OpenSSH_7.4`, `Apache/2.2.15`, `vsftpd 2.3.4`) triggering `NET-SVC-001`.

---

### 2.4 Passive OSINT & Subdomain Takeover Auditor (`subdomain_recon.py`)
- **Algorithm:**
  - Queries `https://crt.sh/?q=%25.{domain}&output=json` with 10s timeout.
  - Extracts unique subdomains from `name_value` fields.
  - Queries DNS CNAME records for each subdomain.
  - Inspects CNAME targets against known dangling cloud signatures (e.g. `*.s3.amazonaws.com`, `*.github.io`, `*.herokuapp.com`, `*.azurewebsites.net`).
  - If CNAME points to unclaimed bucket/page or NXDOMAIN, flags `NET-OSINT-001` (CRITICAL, CVSS 9.1).
  - If subdomain has prefix `admin`, `staging`, `dev`, `internal`, flags `NET-OSINT-002` (MEDIUM, CVSS 5.3).

---

## 3. Engine 2: Web Application, API DAST & Parameter Fuzzer (`web_dast`)

**Primary Dependencies:** `httpx.AsyncClient`, `bs4.BeautifulSoup`, `urllib.parse`

### 3.1 Security Headers & Cookie Policies (`headers_cookies.py`)
- Audits CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Server disclosure, and cookie flags across **all discovered crawled endpoints**.

### 3.2 CORS & API Exposure (`cors_analyzer.py`, `api_inspector.py`)
- Tests origin reflection with credentials (`DAST-CORS-001`), public `.env` (`DAST-EXP-001`), `.git/HEAD` (`DAST-EXP-002`), Spring Boot Actuator (`DAST-EXP-003`), and OpenAPI specs (`DAST-EXP-004`).

### 3.3 Scoped Web Discovery Crawler (`crawler.py`) & Auth Session (`auth_session.py`)
- BFS link discovery with static asset filter (`.js`, `.css`, `.png`, etc.), form discovery, anti-CSRF token extraction, and session heartbeat.

### 3.4 Active Parameter Fuzzing & Injection Engine (`parameter_fuzzer.py`)
- **Fuzzing Targets:** All discovered GET query parameters and POST/PUT form input fields.
- **Benign Probes & Verification:**
  1. **Time-Based SQL Injection (`DAST-INJ-001`):**
     - Sends baseline request, measures baseline latency $T_0$.
     - Sends probe: `1' AND (SELECT 1 FROM (SELECT(SLEEP(2)))a)-- ` (MySQL) or `1' AND pg_sleep(2)--` (Postgres).
     - If response latency $T_{\text{probe}} \ge T_0 + 1.8\text{s}$, confirms time-based blind SQLi (CRITICAL, CVSS 9.8).
  2. **Boolean-Differential SQL Injection (`DAST-INJ-001`):**
     - Injects `1' AND '1'='1` vs `1' AND '1'='2`.
     - If response hash / length significantly diverges between true and false states, confirms boolean-differential SQLi.
  3. **Canary Reflected XSS (`DAST-XSS-001`):**
     - Generates unique hex token: `_CYBERASSESS_XSS_<hex>_`.
     - Injects `_CYBERASSESS_XSS_<hex>_"<script>_` into parameter.
     - Inspects response HTML; if unescaped `<` or exact canary tag reflects, confirms Reflected XSS (HIGH, CVSS 7.5).
  4. **Read-Only Local File Inclusion / Path Traversal (`DAST-LFI-001`):**
     - Injects `../../../../etc/passwd` and `..\..\..\..\windows\win.ini`.
     - Matches `root:.*:0:0:` or `\[fonts\]` signatures in response body (HIGH, CVSS 8.6).
  5. **Server-Side Template Injection (`DAST-SSTI-001`):**
     - Injects `{{7*7}}` and `${7*7}`.
     - Checks if response body replaces expression with computed `49` (CRITICAL, CVSS 9.8).
  6. **Open Redirection (`DAST-REDIR-001`):**
     - Injects `//attacker.invalid` and `https://attacker.invalid`.
     - Checks if response status is 301/302/307/308 with `Location:` containing `attacker.invalid` (MEDIUM, CVSS 6.1).
- **Reproduction cURL Synthesis:**
  - For every confirmed finding, automatically formats a copy-pasteable command:
  ```bash
  curl -i -s -k -X GET "https://target.example.com/item?id=1'+AND+(SELECT+1+FROM+(SELECT(SLEEP(2)))a)--+"
  ```

---

## 4. Engine 3: Static Code Analysis, Secrets, AST Taint & SCA (`code_sast`)

**Primary Dependencies:** `re`, `math`, `ast`, `json`

### 4.1 Secret Scanner Rules & Shannon Entropy (`secret_scanner.py`)
- Regex patterns for AWS, GitHub, Stripe, Google Cloud, Slack tokens, private keys, database URIs.
- Automatic secret masking guarantee: `AKIA****************`.

### 4.2 Git Commit History Secret Hunter (`git_history_scanner.py`)
- Executes `git log -p -n 100` in repository directory.
- Analyzes newly added diff lines (`+...`) across past commits using secret regex rules and Shannon entropy.
- If unmasked secret is found in commit history, triggers `SAST-GIT-001` (HIGH, CVSS 8.6).

### 4.3 Interprocedural AST Taint Flow Analysis (`ast_taint_analyzer.py`)
- Uses Python `ast.parse()` to build Abstract Syntax Trees for repository `.py` files.
- **Taint Sources:** `request.args.get()`, `request.form.get()`, `request.json`, `sys.argv`.
- **Taint Sinks:** `cursor.execute()`, `db.engine.execute()`, `subprocess.Popen(..., shell=True)`, `os.system()`.
- **Dataflow Propagation:** Tracks variable assignments and string interpolations (`f"..."`, `.format()`, `%`) from source to sink.
- Generates structured `taint_trace` list (e.g. `["Source: user_id = request.args.get('id')", "Propagate: query = f'SELECT * FROM users WHERE id={user_id}'", "Sink: cursor.execute(query)"]`).
- Triggers `SAST-TAINT-001` (SQLi Sink) or `SAST-TAINT-002` (Command Injection Sink).

### 4.4 Software Composition Analysis (`dependency_auditor.py`)
- Matches manifest lockfiles against known vulnerable CVE versions (`SAST-DEP-001`).

---

## 5. Engine 4: Infrastructure & Container IaC (`infra_iac`)

- Audits Dockerfile (`IAC-DOCK-001` to `006`), Docker Compose (`IAC-CMP-001` to `003`), Kubernetes manifests (`IAC-K8S-001` to `004`), and Terraform templates (`IAC-TF-001` to `004`).

---

## 6. Engine 5: CI/CD Pipeline & Workflow Security (`cicd_audit`)

- Audits GitHub Actions workflows for `pull_request_target` checkout (`CICD-GHA-001`), unpinned actions (`CICD-GHA-002`), script injection (`CICD-GHA-003`), and `permissions: write-all` (`CICD-GHA-004`).

---

## 7. Pentester Workbench & Remediation Templates

### 7.1 Interactive HTTP Repeater Engine (`backend/app/api/tools.py`)
- Asynchronously sends raw HTTP requests via `httpx.AsyncClient` with custom headers, methods, and payloads, returning exact response headers, timing in milliseconds, and TLS session details.

### 7.2 Standardized Code Remediation Templates
- Provides copyable configuration blocks for Nginx, Apache, Docker, Kubernetes, SQL Parameterization, and Subdomain DNS cleanups.

---

## 8. Adapters First-in-Line & Parser Mechanics (`backend/app/adapters/`)

### 8.1 Nmap Subprocess & XML Parsing (`nmap_adapter.py`)
- **Invocation:**
  ```python
  cmd = [nmap_path, "-sV", "-sC", "--version-light", "-T4", "-oX", "-", target_host]
  process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
  stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60.0)
  ```
- **Parsing Mechanics:**
  - Parses standard Nmap XML using `xml.etree.ElementTree`.
  - Iterates `<host><ports><port>` extracting `portid`, `protocol`, `<state state="...">`, `<service name="..." product="..." version="...">`.
  - Normalizes open database, cache, or remote admin ports to `NET-PORT-xxx` and daemon banners to `NET-SVC-001` with `source_tool="nmap"`.

### 8.2 SSLyze Subprocess & JSON Parsing (`sslyze_adapter.py`)
- **Invocation:**
  ```python
  cmd = [sslyze_path, "--json_out=-", f"{target_host}:{target_port}"]
  process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
  stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60.0)
  ```
- **Parsing Mechanics:**
  - Parses JSON output evaluating TLS 1.0/1.1 cipher support (`NET-TLS-002`), weak ciphers (`NET-TLS-003`), certificate expiration (`NET-TLS-001`), and hostname validation (`NET-TLS-004`) with `source_tool="sslyze"`.

### 8.3 Nuclei Subprocess & JSON Stream Parsing (`nuclei_adapter.py`)
- **Invocation:**
  ```python
  cmd = [nuclei_path, "-u", target_url, "-j", "-silent", "-tags", "cve,misconfig", "-severity", "low,medium,high,critical"]
  process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
  ```
- **Parsing Mechanics:**
  - Reads `stdout` line-by-line; each line is parsed via `json.loads()`.
  - Extracts `template-id`, `info.name`, `info.severity`, `info.classification.cwe-id`, `matched-at`, `curl-command`.
  - Generates `Finding` object with `source_tool="nuclei"` and `reproduction_curl`.

### 8.4 FFuF Subprocess & JSON Parsing (`ffuf_adapter.py`)
- **Invocation:**
  ```python
  cmd = [ffuf_path, "-u", f"{target_url}/FUZZ", "-w", wordlist_path, "-mc", "200,204,301,302,307,401,403", "-o", "-", "-of", "json", "-t", "5", "-rate", "10"]
  process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
  stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60.0)
  ```
- **Parsing Mechanics:**
  - Parses JSON results object `results[]`, extracting `input.FUZZ`, `status`, `length`, `words`, and `redirectlocation`.
  - Creates `DiscoveredEndpoint` models and `Finding` objects (`DAST-EXP-xxx`) with `source_tool="ffuf"`.

### 8.5 Nikto Subprocess & JSON Parsing (`nikto_adapter.py`)
- **Invocation:**
  ```python
  cmd = [nikto_path, "-h", target_url, "-Format", "json", "-output", "-", "-Tuning", "1,2,3,4,8,9,a,b,c"]
  process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
  stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60.0)
  ```
- **Parsing Mechanics:**
  - Parses JSON vulnerability array `vulnerabilities[]`, extracting OSVDB IDs, HTTP method, URI, and description.
  - Normalizes into `Finding` with `source_tool="nikto"`.

### 8.6 Semgrep Subprocess & AST Rule Output Parsing (`semgrep_adapter.py`)
- **Invocation:**
  ```python
  cmd = [semgrep_path, "scan", "--config", "auto", "--json", repo_path]
  ```
- **Parsing Mechanics:**
  - Parses JSON output: `results` list containing `check_id`, `path`, `start.line`, `extra.message`, `extra.metadata.cwe`.
  - Normalizes into `Finding` with `source_tool="semgrep"` and code snippet.

### 8.7 Gitleaks Subprocess & Git Secret Parsing (`gitleaks_adapter.py`)
- **Invocation:**
  ```python
  cmd = [gitleaks_path, "detect", "--source", repo_path, "--report-format", "json", "--report-path", "-"]
  code, stdout, stderr = await self.execute_command(cmd, timeout=60.0)
  ```
- **Parsing Mechanics:**
  - Parses JSON array of leak objects extracting `RuleID`, `Description`, `StartLine`, `File`, `Commit`, `Secret`.
  - Enforces mandatory `mask_secret()` on evidence values and produces `Finding` with `source_tool="gitleaks"`.

### 8.8 Bandit Subprocess & Python AST Parsing (`bandit_adapter.py`)
- **Invocation:**
  ```python
  cmd = [bandit_path, "-r", repo_path, "-f", "json"]
  code, stdout, stderr = await self.execute_command(cmd, timeout=60.0)
  ```
- **Parsing Mechanics:**
  - Parses JSON results `results[]` extracting `test_id`, `issue_severity`, `issue_confidence`, `issue_text`, `line_number`, `filename`, `code`.
  - Normalizes into `Finding` with `source_tool="bandit"`.

### 8.9 Trivy Subprocess & SCA/Container Parsing (`trivy_adapter.py`)
- **Invocation:**
  ```python
  cmd = [trivy_path, "fs", "--format", "json", repo_path]
  code, stdout, stderr = await self.execute_command(cmd, timeout=60.0)
  ```
- **Parsing Mechanics:**
  - Parses JSON output: `Results[].Vulnerabilities[]` extracting `VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`, `PrimaryURL`.
  - Normalizes into `Finding` with `source_tool="trivy"`.

### 8.10 Checkov Subprocess & IaC Policy Parsing (`checkov_adapter.py`)
- **Invocation:**
  ```python
  cmd = [checkov_path, "-d", repo_path, "-o", "json", "--compact"]
  code, stdout, stderr = await self.execute_command(cmd, timeout=60.0)
  ```
- **Parsing Mechanics:**
  - Parses JSON output: `results.failed_checks[]` extracting `check_id`, `check_name`, `file_path`, `file_line_range`, `resource`, `guideline`.
  - Normalizes into `Finding` with `source_tool="checkov"`.

---

## 9. In-App Tool Installation Engine Algorithms & Binary Resolution

### 9.1 Asset Matrix for Standalone Pre-compiled Binaries (`GithubReleaseInstaller`)

The installer dynamically maps host OS (`sys.platform` / `platform.system()`) and machine architecture (`platform.machine()`) to official release assets:

| Tool | GitHub Repository | Windows (x86_64) Asset Pattern | Linux (x86_64) Asset Pattern | macOS (ARM64) Asset Pattern |
| :--- | :--- | :--- | :--- | :--- |
| **`nuclei`** | `projectdiscovery/nuclei` | `nuclei_*_windows_amd64.zip` | `nuclei_*_linux_amd64.zip` | `nuclei_*_macOS_arm64.zip` |
| **`ffuf`** | `ffuf/ffuf` | `ffuf_*_windows_amd64.zip` | `ffuf_*_linux_amd64.tar.gz` | `ffuf_*_macOS_arm64.tar.gz` |
| **`gitleaks`** | `gitleaks/gitleaks` | `gitleaks_*_windows_x64.zip` | `gitleaks_*_linux_x64.tar.gz` | `gitleaks_*_darwin_arm64.tar.gz` |
| **`trivy`** | `aquasecurity/trivy` | `trivy_*_windows-64bit.zip` | `trivy_*_Linux-64bit.tar.gz` | `trivy_*_macOS-ARM64.tar.gz` |

### 9.2 Thread-Isolated Pip Package Installation Execution Algorithm (`PipToolInstaller`)
```python
# Technical Algorithm: Safe Pip Subprocess Invocation with Thread-Bridge Queue Streaming
import subprocess, threading, asyncio

async def install_pip_package(package_name: str, emit_log: Callable[[str], Awaitable[None]]) -> bool:
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", package_name]
    loop = asyncio.get_running_loop()
    queue = asyncio.Queue()

    def _worker():
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        for line in iter(proc.stdout.readline, ""):
            asyncio.run_coroutine_threadsafe(queue.put(line.rstrip()), loop)
        proc.stdout.close()
        proc.wait()
        asyncio.run_coroutine_threadsafe(queue.put(None), loop)
        return proc.returncode

    worker_thread = threading.Thread(target=_worker, daemon=True)
    worker_thread.start()

    while True:
        line = await queue.get()
        if line is None:
            break
        await emit_log(line)
        
    await asyncio.to_thread(worker_thread.join)
    return True
```

### 9.3 ZipSlip Path Traversal Protection & Archive Unpacking
```python
import zipfile, tarfile, os

def safe_extract_zip(zip_path: str, target_dir: str) -> None:
    target_dir = os.path.abspath(target_dir)
    with zipfile.ZipFile(zip_path, 'r') as z:
        for member in z.namelist():
            dest_path = os.path.abspath(os.path.join(target_dir, member))
            if not dest_path.startswith(target_dir + os.sep) and dest_path != target_dir:
                raise SecurityError(f"ZipSlip traversal attempt detected: {member}")
        z.extractall(target_dir)
```

### 9.4 Real-time SSE Telemetry Broadcast Pipeline
1. Client connects to `/api/system/tools/events`.
2. As installer executes, it yields chunks formatted as standard SSE frames (`event: install_progress`, `event: install_log`, `event: install_completed`, `event: install_failed`).
3. Frontend listens with `EventSource` and appends output to the live terminal console.

### 9.5 Deterministic 5-Tier Binary Resolution & Windows Registry Auto-Discovery
```python
# Technical Algorithm: Deterministic 5-Tier Executable Resolution
def resolve_tool_binary(tool_name: str, custom_path: Optional[str] = None, local_bin_dir: Optional[str] = None) -> Optional[str]:
    # Tier 1: Explicit custom configured path
    if custom_path:
        if os.path.isfile(custom_path): return os.path.abspath(custom_path)
        resolved = shutil.which(custom_path)
        if resolved: return resolved

    # Tier 2: In-App Managed Binaries ('backend/bin/<tool>[.exe|.bat|.cmd|.pl]')
    bin_dir = local_bin_dir or get_default_bin_dir()
    for ext in [".exe", ".bat", ".cmd", ".pl", ""]:
        cand = os.path.join(bin_dir, f"{tool_name}{ext}")
        if os.path.isfile(cand): return os.path.abspath(cand)

    # Tier 3: Python Environment Scripts (for pip-installed CLI tools)
    py_dir = os.path.dirname(sys.executable)
    for c in [os.path.join(py_dir, "Scripts", f"{tool_name}.exe"), os.path.join(sys.prefix, "Scripts", f"{tool_name}.exe")]:
        if os.path.isfile(c): return os.path.abspath(c)

    # Tier 4: System PATH lookup
    path_match = shutil.which(tool_name)
    if path_match: return path_match

    # Tier 5: Windows Registry Scan & Multi-Drive Discovery
    if sys.platform == "win32":
        # 5a: Winreg Uninstall Key Scan (HKLM & HKCU DisplayName/InstallLocation/DisplayIcon)
        reg_match = _find_in_windows_registry(tool_name)
        if reg_match: return reg_match

        # 5b: Active Drive Scan (C:, D:, E:, etc. in Program Files / tools)
        std_match = _find_in_windows_standard_paths(tool_name)
        if std_match: return std_match
    return None
```

### 9.6 System Tool Health & Version Verification Gate
To prevent false-positive capability reporting (e.g. Git-bundled Perl missing CPAN modules required by Nikto), system tools (`SYSTEM_PACKAGE_MANAGER`) MUST satisfy the following health gate before status is set to `INSTALLED`:
1. Binary path resolved via `resolve_tool_binary()`.
2. Version check command returns exit code `0`.
3. STDOUT/STDERR contains valid version string and zero error keywords (`error:`, `not found`, `can't locate`, `failed`).
4. If health gate fails, status remains `NOT_INSTALLED`, directing the user to the interactive in-app setup guide.

---

## 10. Production Containerization & Cloud Registry Distribution

### 10.1 Multi-Stage Hardened Production Dockerfile Specification (`Dockerfile`)

```dockerfile
# Stage 1: Builder Stage (Download & verify official pre-compiled tool binaries)
FROM --platform=$BUILDPLATFORM python:3.11-slim-bookworm AS builder

ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    tar \
    unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/bin

# 1. Nuclei (v3.2.0)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_arm64.zip -o nuclei.zip; \
    else \
      curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip -o nuclei.zip; \
    fi && \
    unzip -q nuclei.zip nuclei && \
    chmod +x nuclei && \
    rm nuclei.zip

# 2. FFuF (v2.1.0)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_arm64.tar.gz | tar -xz ffuf; \
    else \
      curl -sSL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz | tar -xz ffuf; \
    fi && \
    chmod +x ffuf

# 3. Gitleaks (v8.18.2)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_arm64.tar.gz | tar -xz gitleaks; \
    else \
      curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz | tar -xz gitleaks; \
    fi && \
    chmod +x gitleaks

# 4. Trivy (v0.49.1)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/aquasecurity/trivy/releases/download/v0.49.1/trivy_0.49.1_Linux-ARM64.tar.gz | tar -xz trivy; \
    else \
      curl -sSL https://github.com/aquasecurity/trivy/releases/download/v0.49.1/trivy_0.49.1_Linux-64bit.tar.gz | tar -xz trivy; \
    fi && \
    chmod +x trivy

# Stage 2: Final Hardened Production Runtime
FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="CyberAssess Security Assessment Platform" \
      org.opencontainers.image.description="Full-Stack Automated Security Assessment & Vulnerability Management Platform" \
      org.opencontainers.image.vendor="CyberAssess" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8000

# Install runtime system packages: Nmap, Perl with CPAN XML::Writer, Git, Curl, procps
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    perl \
    libxml-writer-perl \
    libnet-ssleay-perl \
    git \
    curl \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Nikto via official upstream GitHub repo
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# Copy pre-compiled standalone binaries from builder stage
COPY --from=builder /tmp/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /tmp/bin/ffuf /usr/local/bin/ffuf
COPY --from=builder /tmp/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=builder /tmp/bin/trivy /usr/local/bin/trivy

# Create application directories
WORKDIR /app
RUN mkdir -p /app/data/scans /app/backend /app/frontend

# Install Python requirements (Bandit, SSLyze, Semgrep, Checkov, FastAPI, etc.)
COPY backend/requirements.txt /app/backend/
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend application, frontend HUD assets, and root runner
COPY backend/ /app/backend/
COPY frontend/ /app/frontend/
COPY run_platform.py /app/

# Expose Web SOC HUD port
EXPOSE 8000

# Healthcheck probe against FastAPI system health API
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/api/system/health || exit 1

# Launch Platform
CMD ["python", "run_platform.py"]
```

### 10.2 Production Docker Compose Orchestration (`docker-compose.yml`)

```yaml
version: '3.8'

services:
  cyberassess:
    build:
      context: .
      dockerfile: Dockerfile
    image: ghcr.io/andresslacson1989/cyberassess:latest
    container_name: cyberassess-platform
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - HOST=0.0.0.0
      - PORT=8000
      - PYTHONUNBUFFERED=1
    volumes:
      # Persistent storage for scans and reports
      - ./data:/app/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/system/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
```

### 10.3 Build Context Exclusion (`.dockerignore`)

```dockerignore
.git
.github
.pytest_cache
__pycache__
*.pyc
*.pyo
*.pyd
venv/
.venv/
env/
data/scans/*
tests/
contracts/
.idea/
.vscode/
*.log
```

### 10.4 GitHub Actions Automated CI/CD Lifecycle Specification (`.github/workflows/docker-publish.yml`)

To achieve rapid developer feedback while guaranteeing enterprise universal architecture compatibility in production, the CI/CD pipeline implements a **two-tier build strategy**:

#### 1. Fast Development Iteration (Routine Pushes to `main`)
- Builds native `linux/amd64` directly on standard runners with zero QEMU software CPU emulation.
- Completes in **~2 to 3 minutes**, publishing `latest` and `sha-<commit>` tags for continuous integration testing.

#### 2. Production Release Publishing (Version Tags `v*.*.*` & Manual Dispatch)
- Triggers full multi-architecture build (`linux/amd64,linux/arm64`).
- Generates universal multi-arch manifest lists on GHCR tagged with semantic versioning (`v8.0.0`, `v8.0`, `v8`).

#### Production Release Step-by-Step Procedure:
1. Verify 100% test pass rate locally: `pytest tests/ -v`.
2. Create and push a semantic version tag:
   ```bash
   git tag -a v8.0.0 -m "Release v8.0.0 - 22-Tool Enterprise Security Platform"
   git push origin v8.0.0
   ```
3. GitHub Actions automatically detects the `v*.*.*` tag and publishes the universal multi-arch container to `ghcr.io`.

```yaml
name: Build & Publish Container Image to GHCR

on:
  push:
    branches: [ "main" ]
    tags: [ 'v*.*.*' ]
  workflow_dispatch:

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up QEMU for multi-arch builds (Production Releases Only)
        if: startsWith(github.ref, 'refs/tags/v')
        uses: docker/setup-qemu-action@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract Docker metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=raw,value=latest,enable={{is_default_branch}}
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=sha,format=short

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          file: ./Dockerfile
          platforms: ${{ startsWith(github.ref, 'refs/tags/v') && 'linux/amd64,linux/arm64' || 'linux/amd64' }}
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

### 10.5 LocalCI On-Premises Pipeline Integration Specification (`.localci/ci.sh`)

To enable instant, zero-cost test execution and Continuous Integration on local infrastructure without consuming cloud runner quotas or incurring public cloud billing, the platform integrates with **LocalCI** (`https://localci.pixelretrobooth.com` / `192.168.99.211`).

#### 1. Topology & Target Appliance Environment
- **Appliance Container:** Proxmox Node `192.168.99.2` (`CT107` / `localci-clean107`)
- **Pipeline Profile:** `python313` (Python 3.13 LTS, pip, venv, pytest)
- **Public Gateway:** `https://localci.pixelretrobooth.com` (Cloudflare Access Service Token auth)
- **Direct LAN IP:** `https://192.168.99.211` (`Host: localci-clean107.local`, self-signed TLS)
- **Protected Invariant:** `CT104` is a protected production container and MUST NEVER be touched or tested on.

#### 2. Pipeline Execution Script Specification (`.localci/ci.sh`)
```bash
#!/usr/bin/env bash
set -eu

echo "========================================================"
echo "   CyberAssess Platform - LocalCI Automated Pipeline"
echo "========================================================"
echo "Python Version: $(python3 --version)"
echo "Working Directory: $(pwd)"

# 1. Prepare Virtual Environment
python3 -m venv .venv
. .venv/bin/activate

# 2. Install Core Dependencies & Testing Framework
pip install --upgrade pip setuptools wheel
pip install -r backend/requirements.txt pytest

# 3. Execute 100% Comprehensive Acceptance Test Suite
echo "=== Running Full Pytest Test Suite (153 Tests across 25 Scenarios) ==="
pytest tests/ -v --tb=short

# 4. Generate & Validate Output Artifacts
mkdir -p /output
echo "=== Validating System Capabilities Registry ==="
python3 -c "
import sys, os
sys.path.insert(0, 'backend')
from app.core.models import SystemCapabilities
from app.adapters import discover_system_capabilities
caps = discover_system_capabilities()
print(f'Discovered System Capabilities: {len(caps.tools)} tools registered')
" || true

echo "========================================================"
echo "   LocalCI Pipeline Completed Successfully (100% Pass)"
echo "========================================================"
```

#### 3. API Execution & Polling Flow
1. Client generates idempotency key (`sec-platform-<timestamp>-<commit_hash>`).
2. Client submits job via `POST /api/v1/jobs` with payload:
   ```json
   {
     "repository": "andresslacson1989/security-assessment-platform",
     "head_ref": "refs/heads/main",
     "pipeline_id": "python313",
     "idempotency_key": "sec-platform-..."
   }
   ```
3. Authenticates with Cloudflare Access Service Token headers (`CF-Access-Client-Id` and `CF-Access-Client-Secret` from `F:\cf.txt`).
4. Polls `GET /api/v1/jobs/{job_id}` for lifecycle transition (`queued` -> `preparing` -> `running` -> `completed`).
5. Fetches logs from `GET /api/v1/jobs/{job_id}/logs` and validates `conclusion == "success"`.

---

## 11. Expanded 22-Tool Enterprise Specifications & Execution Mechanics

### 11.1 Subfinder Adapter (`SubfinderAdapter`)
- **CLI Invocation:** `subfinder -d <domain> -silent -oJ`
- **Output Parsing:** Streams JSON objects per line `{"host":"sub.example.com","sources":["crtsh","censys"]}`.
- **Normalization:** Emits `DiscoveredSubdomain` with discovered IP resolution and `EASM-SUB-001` findings.

### 11.2 Httpx Adapter (`HttpxAdapter`)
- **CLI Invocation:** `httpx -u <target> -json -silent -title -tech-detect -status-code -location -tls-grab`
- **Output Parsing:** Parses JSON response details containing status code, tech stack array, title, TLS version, and redirects.
- **Normalization:** Emits `DiscoveredEndpoint` models and `EASM-EXPOSURE-001` findings.

### 11.3 Katana Adapter (`KatanaAdapter`)
- **CLI Invocation:** `katana -u <target> -jsonl -silent -headless -d 3 -jc -aff`
- **Output Parsing:** Ingests dynamic DOM links, form actions, and AJAX/Fetch request routes rendered in headless Chromium.
- **Normalization:** Emits `DiscoveredEndpoint` models with `has_forms` flags and feeds routes into `Nuclei` / `FFuF`.

### 11.4 Syft Adapter (`SyftAdapter`)
- **CLI Invocation:** `syft <dir> -o cyclonedx-json`
- **Output Parsing:** Ingests CycloneDX 1.5 JSON containing components, packages, purls, and licenses.
- **Normalization:** Populates `SBOMReport` and feeds component list into `Grype` / `OSV-Scanner`.

### 11.5 Grype Adapter (`GrypeAdapter`)
- **CLI Invocation:** `grype <dir> -o json`
- **Output Parsing:** Parses JSON vulnerability list `matches[].vulnerability` and `artifact`.
- **Normalization:** Emits `Finding` with `check_id="SCA-SBOM-001"`, CVSS scores, and fixed package versions.

### 11.6 OSV-Scanner Adapter (`OSVScannerAdapter`)
- **CLI Invocation:** `osv-scanner scan --format json -r <dir>`
- **Output Parsing:** Parses JSON `results[].packages[].vulnerabilities[]` from Google's OSV database.
- **Normalization:** Emits `Finding` with `check_id="SCA-OSV-001"`, CWE, CVSS score, and affected commit ranges.

### 11.7 Retire.js Adapter (`RetireJSAdapter`)
- **CLI Invocation:** `retire --path <dir> --outputformat json`
- **Output Parsing:** Parses JSON array of vulnerable client-side JavaScript libraries (jQuery, Bootstrap, Angular, Lodash).
- **Normalization:** Emits `Finding` with `check_id="SCA-JS-001"` and remediation suggestions.

### 11.8 TruffleHog Adapter (`TruffleHogAdapter`)
- **CLI Invocation:** `trufflehog filesystem <dir> --json --no-verification=false`
- **Output Parsing:** Parses JSON lines containing verified secrets `{"DetectorName":"AWS","Verified":true,"Raw":"AKIA..."}`.
- **Normalization:** Emits `Finding` with `check_id="SEC-VERIFIED-001"`, CVSS 10.0, masked secret, and verified authorization metadata.

### 11.9 Prowler Adapter (`ProwlerAdapter`)
- **CLI Invocation:** `prowler <provider> -M json`
- **Output Parsing:** Parses CIS Foundations benchmark check results.
- **Normalization:** Emits `Finding` with `check_id="CLOUD-CIS-001"` and `CISBenchmarkResult` models.

### 11.10 Kube-bench Adapter (`KubeBenchAdapter`)
- **CLI Invocation:** `kube-bench run --json`
- **Output Parsing:** Parses CIS Kubernetes Benchmark results `Controls[].Tests[].Results[]`.
- **Normalization:** Emits `Finding` with `check_id="K8S-CIS-001"` and remediation commands.

### 11.11 Dockle Adapter (`DockleAdapter`)
- **CLI Invocation:** `dockle -f json <image_tar>`
- **Output Parsing:** Parses CIS Docker benchmark image audits (`CIS-DI-0001` to `CIS-DI-0010`).
- **Normalization:** Emits `Finding` with `check_id="DOCKER-CIS-001"` and CIS remediation details.

### 11.12 Schemathesis Adapter (`SchemathesisAdapter`)
- **CLI Invocation:** `schemathesis run <schema_url> --report-format json`
- **Output Parsing:** Parses property-based test results, unhandled 500 errors, and broken schema contracts.
- **Normalization:** Emits `Finding` with `check_id="API-SCHEMA-001"` and reproduction cURL commands.





