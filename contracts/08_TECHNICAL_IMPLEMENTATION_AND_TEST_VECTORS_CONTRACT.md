# Contract 08: Technical Implementation, Execution Algorithms & Test Vectors Contract

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 3.0.0 (Authoritative Technical Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Engine Implementation Algorithms, Test Vectors, Parser Mechanics & Remediation Templates  

---

## 1. Universal Engine Execution Lifecycle Pipeline

Every security check executed across all 5 engines MUST operate according to this deterministic 6-stage lifecycle pipeline:

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
3. **Async I/O with Strict Timeout:** Executes bounded I/O wrapped in `asyncio.wait_for()` (HTTP $\le 10\text{s}$, Sockets $\le 2\text{s}$, DNS $\le 3\text{s}$).
4. **Algorithmic Decision Tree:** Evaluates raw response/AST against the canonical rule criteria.
5. **Evidence Formatting & Secret Masking:** Normalizes `observed_value`, `expected_value`, and redacts secrets.
6. **Real-time SSE Emission:** Instantly emits `event: finding` and `event: log` callbacks to connected clients.

---

## 2. Engine 1: Network Perimeter, TLS/SSL & DNS (`network`)

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

- **Deprecated Protocol Handshake Probing (`NET-TLS-005`, `NET-TLS-006`):**
  - Attempts handshakes using dedicated contexts for `ssl.TLSVersion.TLSv1`, `ssl.TLSVersion.TLSv1_1`, and `ssl.PROTOCOL_SSLv3`.
  - If TCP connection and SSL handshake complete without `ssl.SSLError`, finding is triggered.

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

### 2.3 Exposed Management & Database Ports (`port_checker.py`)
- **Port Matrix:** `21` (FTP), `22` (SSH), `23` (Telnet), `3306` (MySQL), `5432` (PostgreSQL), `6379` (Redis), `27017` (MongoDB), `9200` (Elasticsearch), `8080`, `8443`.
- **Mechanism:** Concurrently executes `asyncio.open_connection(target_ip, port)` with 1.5s timeout. Immediate `writer.close()` upon connect.

---

## 3. Engine 2: Web Application & REST/GraphQL API DAST (`web_dast`)

**Primary Dependencies:** `httpx.AsyncClient`, `bs4.BeautifulSoup`, `urllib.parse`

### 3.1 Security Headers & Cookie Policies (`headers_cookies.py`)
- **Headers Inspected:**
  1. `Content-Security-Policy`: Checks presence and flags `unsafe-inline` / `unsafe-eval` (`DAST-HDR-001`).
  2. `Strict-Transport-Security`: Verifies presence on HTTPS and checks `max-age >= 15552000` (`DAST-HDR-002`, `DAST-HDR-003`).
  3. `X-Frame-Options`: Checks for `DENY` or `SAMEORIGIN` (`DAST-HDR-004`).
  4. `X-Content-Type-Options`: Checks for `nosniff` (`DAST-HDR-005`).
  5. `Referrer-Policy`: Checks for strict policy (`DAST-HDR-006`).
  6. `Server` / `X-Powered-By`: Regex search for version disclosure `\d+\.\d+` (`DAST-HDR-007`).
  7. `Permissions-Policy`: Verifies restrictions on `camera`, `microphone`, `geolocation` (`DAST-HDR-008`).
  8. `Cross-Origin-Opener-Policy` & `Cross-Origin-Embedder-Policy` (`DAST-HDR-009`).
- **Cookie Security:**
  - Iterates over all `Set-Cookie` headers:
    - Flags missing `HttpOnly` on session tokens (`DAST-COOKIE-001`).
    - Flags missing `Secure` on HTTPS connections (`DAST-COOKIE-002`).
    - Flags missing or improper `SameSite` attribute (`DAST-COOKIE-003`).

### 3.2 CORS Misconfiguration Analyzer (`cors_analyzer.py`)
- **Probe 1:** Sends request with `Origin: https://evil-attacker.com`.
  - Flag if `Access-Control-Allow-Origin: https://evil-attacker.com` AND `Access-Control-Allow-Credentials: true` (`DAST-CORS-001`, HIGH, CVSS 8.1).
- **Probe 2:** Sends request with `Origin: null`.
  - Flag if `Access-Control-Allow-Origin: null` AND `Access-Control-Allow-Credentials: true` (`DAST-CORS-003`, HIGH, CVSS 7.5).

### 3.3 Sensitive Path & API Probing (`api_inspector.py`)
- **Wordlist Probes:**
  - `/.env`: Matches `[A-Z0-9_]+=[^\r\n]+` with HTTP 200 (`DAST-EXP-001`, CRITICAL, CVSS 9.8).
  - `/.git/HEAD`: Matches `^ref: refs/heads/` with HTTP 200 (`DAST-EXP-002`, CRITICAL, CVSS 9.8).
  - `/actuator/health` or `/actuator/env`: Matches Spring Boot JSON actuator structure (`DAST-EXP-003`, HIGH, CVSS 7.5).
  - `/swagger.json` or `/openapi.json`: Matches OpenAPI definition (`DAST-EXP-004`, LOW, CVSS 3.7).
- **HTTP Methods:** Probes `TRACE / HTTP/1.1` to detect Cross-Site Tracing (`DAST-METH-001`, MEDIUM, CVSS 4.3).

### 3.4 Modern Browser & GraphQL Auditing (`browser_posture.py`, `graphql_auditor.py`)
- **Subresource Integrity (`DAST-SRI-001`):** Parses DOM `<script src="...">` and `<link rel="stylesheet">` from external domains lacking `integrity="sha..."`.
- **GraphQL Introspection (`DAST-GQL-001`):** Sends `POST /graphql` with `{"query": "{ __schema { types { name } } }"}`. Flag if types schema returned.

### 3.5 Scoped Web Discovery Crawler (`crawler.py`)
- **Algorithm:** Asynchronous Breadth-First Search (BFS) spider.
- **Link Extraction:** Parses HTML response with `BeautifulSoup` extracting `<a href>`, `<form action>`, `<link href>`, `<script src>`.
- **URL Normalization:** Resolves relative URLs via `urllib.parse.urljoin`, removes anchor fragments via `urldefrag`, and normalizes parameters.
- **Scope Guard:** Compares `urlparse(url).netloc == urlparse(target).netloc`. Rejects external third-party domains.
- **Loop & Depth Limits:** Tracks visited SHA-256 URL hashes, enforcing `depth <= max_depth` (default: 3) and `count <= max_pages` (default: 50).
- **Robots & Sitemap Seeds:** Fetches `/robots.txt` and `/sitemap.xml` to seed the discovery queue.

### 3.6 Authentication & Session Manager (`auth_session.py`)
- **Authentication Handlers:**
  1. `HEADER`: Injects `Authorization: Bearer <token>` or custom headers into `httpx.AsyncClient`.
  2. `COOKIE`: Populates `httpx.Cookies` jar with supplied session tokens.
  3. `FORM_LOGIN`: Automated login workflow:
     - `GET login_url`: Parses HTML form to identify input fields and auto-extract anti-CSRF token (`name="csrf_token"`, `_csrf`, `authenticity_token`, `_token`).
     - `POST login_url`: Submits credentials + extracted CSRF token with `follow_redirects=True`.
     - Collects and persists session cookies across subsequent crawl and DAST requests.
- **Logout URL Blacklisting:** Automatically skips any URL matching `logout`, `signout`, `sign_out`, `log_out`, `exit`, `destroy`.
- **Session Heartbeat & Re-authentication:** Periodically tests responses against `logged_in_indicator`. If a 401/403 or redirect to login is observed, automatically executes re-authentication.
- **Differential Access Control Probe (`DAST-AUTH-003`):** Probes authenticated URLs without cookies/headers. If protected endpoint returns HTTP 200 with identical sensitive response, flags broken access control.

---

## 4. Engine 3: Static Code Analysis, Secrets & SCA (`code_sast`)

**Primary Dependencies:** `re`, `math`, `ast`, `json`

### 4.1 Secret Scanner Rules & Shannon Entropy (`secret_scanner.py`)

#### Shannon Entropy Calculation:
$$H(X) = -\sum_{i=1}^n P(x_i) \log_2 P(x_i)$$
Strings with $H(X) \ge 4.5$ and length $\ge 20$ assigned to sensitive variable names trigger high-entropy secret detection.

#### Master Secret Regex Patterns:
```python
SECRET_PATTERNS = {
    "SAST-SEC-001": (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "HIGH", 8.6),
    "SAST-SEC-002": (r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]", "AWS Secret Access Key", "CRITICAL", 9.8),
    "SAST-SEC-003": (r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}", "GitHub Personal Access Token", "HIGH", 8.5),
    "SAST-SEC-004": (r"sk_live_[0-9a-zA-Z]{24,34}", "Stripe Live Secret Key", "CRITICAL", 9.1),
    "SAST-SEC-005": (r"AIza[0-9A-Za-z\\-_]{35}", "Google Cloud / Maps API Key", "HIGH", 7.5),
    "SAST-SEC-006": (r"https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8}\/B[0-9A-Z]{8}\/[0-9a-zA-Z]{24}", "Slack Webhook URL", "MEDIUM", 5.3),
    "SAST-SEC-007": (r"-----BEGIN ((RSA|EC|DSA|OPENSSH) )?PRIVATE KEY-----", "Private Cryptographic Key", "CRITICAL", 9.8),
    "SAST-SEC-008": (r"(postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.-]+", "Database URI with Password", "HIGH", 8.6),
    "SAST-SEC-009": (r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", "Internal RFC 1918 IP Address", "LOW", 3.1)
}
```

#### Mandatory Automated Secret Masking Contract:
```python
def mask_secret(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "*" * (len(secret) - 7) + secret[-3:]
```

### 4.2 Code Linting & Anti-Patterns (`crypto_lint.py`, `injection_lint.py`)
- **Weak Cryptography (`SAST-CRY-001` to `003`):** Scans for `hashlib.md5(`, `hashlib.sha1(`, `crypto.createHash('md5')`, and AES `MODE_ECB`.
- **Insecure PRNG (`SAST-CRY-002`):** Scans for `random.random()`, `Math.random()` in token/password contexts.
- **SQL & Shell Injection (`SAST-INJ-001` to `003`):** Detects unparameterized string formatting inside SQL `execute()` and `subprocess.Popen(..., shell=True)`.

### 4.3 Software Composition Analysis (`dependency_auditor.py`)
- Parses `requirements.txt`, `package.json`, `package-lock.json`, and `go.mod`.
- Checks for known CVE versions (`SAST-DEP-001`) and wildcard versions (`*`, `>=0.0.0`) (`SAST-DEP-002`).

---

## 5. Engine 4: Infrastructure & Container IaC (`infra_iac`)

### 5.1 Dockerfile Hardening (`dockerfile_auditor.py`)
- **`IAC-DOCK-001` (Root User):** Parses `Dockerfile`. If no `USER <non-root>` is defined before `CMD`/`ENTRYPOINT`, flags as `HIGH` (CVSS 7.8, CWE-250).
- **`IAC-DOCK-002` (Unpinned Base Image):** Flags `FROM <image>:latest` or `FROM <image>` without tag.
- **`IAC-DOCK-003` (Missing HEALTHCHECK):** Flags omission of `HEALTHCHECK` directive.
- **`IAC-DOCK-004` (Secrets in ENV/ARG):** Flags `ENV` or `ARG` lines defining `SECRET`, `PASSWORD`, `API_KEY`.
- **`IAC-DOCK-005` (Cache Retention):** Flags `RUN apt-get` without `rm -rf /var/lib/apt/lists/*`.
- **`IAC-DOCK-006` (Sudo in RUN):** Flags `sudo` usage in container build layers.

### 5.2 Compose, Kubernetes & Terraform (`compose_auditor.py`, `k8s_manifest_auditor.py`, `terraform_auditor.py`)
- **Compose (`IAC-CMP-001` to `003`):** Checks `privileged: true`, `/var/run/docker.sock` volume mounts, and `0.0.0.0` database port bindings.
- **Kubernetes (`IAC-K8S-001` to `004`):** Checks `securityContext.privileged: true`, `hostPID: true`, missing `readOnlyRootFilesystem: true`, and missing CPU/Memory resource limits.
- **Terraform (`IAC-TF-001` to `004`):** Checks public S3 buckets (`public-read`), security groups with `0.0.0.0/0` on port 22/3389, unencrypted EBS storage, and wildcard IAM policies (`Action: "*"`).

---

## 6. Engine 5: CI/CD Pipeline & Workflow Security (`cicd_audit`)

### 6.1 GitHub Actions Security (`github_actions_auditor.py`)
- **`CICD-GHA-001` (Insecure `pull_request_target`):** Flags workflow files where trigger is `pull_request_target` AND step contains `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}`.
- **`CICD-GHA-002` (Unpinned Action Version):** Flags actions referenced via mutable tags (`@main`, `@master`, `@v1`) instead of 40-character commit SHAs.
- **`CICD-GHA-003` (Script Injection):** Flags inline `run:` scripts interpolating untrusted expressions (`${{ github.event.issue.title }}`).
- **`CICD-GHA-004` (Excessive GITHUB_TOKEN Permissions):** Flags top-level or job-level `permissions: write-all`.

---

## 7. Standardized Code Remediation Template Engine

Every finding generated by the platform MUST provide an actionable, syntax-highlighted code remediation snippet. Standard templates:

### 7.1 Nginx Security Headers Template
```nginx
# Remediation for DAST-HDR-001, DAST-HDR-002, DAST-HDR-004, DAST-HDR-005
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

### 7.2 Hardened Dockerfile Template
```dockerfile
# Remediation for IAC-DOCK-001, IAC-DOCK-002, IAC-DOCK-003, IAC-DOCK-005
FROM node:20.11.0-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .

# Run as non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

EXPOSE 3000
CMD ["node", "server.js"]
```

### 7.3 Hardened Kubernetes Pod SecurityContext Template
```yaml
# Remediation for IAC-K8S-001, IAC-K8S-002, IAC-K8S-003, IAC-K8S-004
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
  containers:
    - name: app
      image: registry.example.com/app:v1.2.3
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          cpu: "500m"
          memory: "512Mi"
        requests:
          cpu: "100m"
          memory: "128Mi"
```
