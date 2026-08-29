# Contract 08: Technical Implementation, Execution Algorithms & Test Vectors Contract

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 4.1.0 (Enterprise Hybrid Tool Adapter & Penetration Testing Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Engine Implementation Algorithms, Test Vectors, Parser Mechanics & Remediation Templates  

---

## 1. Universal Engine Execution Lifecycle Pipeline

Every security check executed across all 5 engines and 4 adapters MUST operate according to this deterministic 6-stage lifecycle pipeline:

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

## 8. Hybrid Tool Adapters & Parser Mechanics (`backend/app/adapters/`)

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

### 8.2 Nuclei Subprocess & JSON Stream Parsing (`nuclei_adapter.py`)
- **Invocation:**
  ```python
  cmd = [nuclei_path, "-u", target_url, "-j", "-silent", "-tags", "cve,misconfig", "-severity", "low,medium,high,critical"]
  process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
  ```
- **Parsing Mechanics:**
  - Reads `stdout` line-by-line; each line is parsed via `json.loads()`.
  - Extracts `template-id`, `info.name`, `info.severity`, `info.classification.cwe-id`, `matched-at`, `curl-command`.
  - Generates `Finding` object with `source_tool="nuclei"` and `reproduction_curl`.

### 8.3 Semgrep Subprocess & AST Rule Output Parsing (`semgrep_adapter.py`)
- **Invocation:**
  ```python
  cmd = [semgrep_path, "scan", "--config", "auto", "--json", repo_path]
  ```
- **Parsing Mechanics:**
  - Parses JSON output: `results` list containing `check_id`, `path`, `start.line`, `extra.message`, `extra.metadata.cwe`.
  - Normalizes into `Finding` with `source_tool="semgrep"` and code snippet.

### 8.4 Trivy Subprocess & SCA/Container Parsing (`trivy_adapter.py`)
- **Invocation:**
  ```python
  cmd = [trivy_path, "fs", "--format", "json", repo_path]
  ```
- **Parsing Mechanics:**
  - Parses JSON output: `Results[].Vulnerabilities[]` extracting `VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`, `PrimaryURL`.
  - Normalizes into `Finding` with `source_tool="trivy"`.


