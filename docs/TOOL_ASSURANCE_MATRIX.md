# CyberAssess v14 — Enterprise Tool Assurance Program & Methodology Matrix

## Document Purpose & Authority
This specification serves as the **Audit & Assurance Matrix** for all 21 external security tools integrated into the CyberAssess platform.

- **Authoritative Implementation Contract:** [`contracts/09_TOOL_IMPLEMENTATION_CONTRACT.md`](../contracts/09_TOOL_IMPLEMENTATION_CONTRACT.md) defines the canonical 41-point implementation requirements, invocation boundaries, schemas, and security controls.
- **Audit & Assurance View:** This document provides the high-level methodology overview, evaluation taxonomy, and operational governance mappings.

---

## 1. Tool Taxonomy & Role Classification Strategy

| Security Domain | Tool Name | Tool ID | Tool Role | Primary / Fallback Purpose | Upstream Artifact Type |
|---|---|---|---|---|---|
| **Network / EASM** | Nmap | `TOOL-NMAP` | PRIMARY | Network Port Probing & Service Fingerprinting | Compiled System Executable / WinGet |
| **Network / TLS** | SSLyze | `TOOL-SSLYZE` | PRIMARY | Comprehensive TLS Protocol & Cipher Suite Analysis | Pure Python Package (pip) |
| **Perimeter / EASM** | Subfinder | `TOOL-SUBFINDER` | PRIMARY | Passive Multi-Source Subdomain Enumeration | Standalone Go Binary (GitHub Release) |
| **HTTP Probing** | httpx | `TOOL-HTTPX` | VALIDATION | High-Speed HTTP Endpoint Verification & Technology Detection | Standalone Go Binary (GitHub Release) |
| **Web DAST** | Nuclei | `TOOL-NUCLEI` | PRIMARY | Template-Driven CVE & Misconfiguration Scanning | Standalone Go Binary (GitHub Release) |
| **Web Fuzzing** | FFuF | `TOOL-FFUF` | SPECIALIZED | Active Parameter, Directory & Header Fuzzing | Standalone Go Binary (GitHub Release) |
| **Web Crawling** | Katana | `TOOL-KATANA` | PRIMARY | Next-Gen Headless & Standard DOM Crawling | Standalone Go Binary (GitHub Release) |
| **API Contract DAST** | Schemathesis | `TOOL-SCHEMATHESIS` | SPECIALIZED | Property-Based OpenAPI / GraphQL Contract Fuzzing | Pure Python Package (pip) |
| **Code SAST** | Semgrep | `TOOL-SEMGREP` | PRIMARY | AST Pattern Matching & Polyglot Code Auditing | Standalone Binary / Python CLI |
| **Code SAST (Python)**| Bandit | `TOOL-BANDIT` | SPECIALIZED | Deep Python AST Vulnerability & Crypto Linting | Pure Python Package (pip) |
| **Secret Scanning** | Gitleaks | `TOOL-GITLEAKS` | PRIMARY | Git Commit History & Filesystem Secret Scanner | Standalone Go Binary (GitHub Release) |
| **Secret Verification**| TruffleHog | `TOOL-TRUFFLEHOG` | VALIDATION | Live Real-Time Credential Validation Engine | Standalone Go Binary (GitHub Release) |
| **Client-Side JS** | Retire.js | `TOOL-RETIREJS` | SPECIALIZED | Vulnerable JavaScript Library Auditor | Standalone Node/Go Binary |
| **Container / SCA** | Trivy | `TOOL-TRIVY` | PRIMARY | Multi-Domain Container, FS & Dependency Scanner | Standalone Go Binary (GitHub Release) |
| **SCA Vulnerability** | Grype | `TOOL-GRYPE` | VALIDATION | Fast Dependency Vulnerability Identification | Standalone Go Binary (GitHub Release) |
| **SBOM Generation** | Syft | `TOOL-SYFT` | PRIMARY | CycloneDX & SPDX Software Bill of Materials Engine | Standalone Go Binary (GitHub Release) |
| **OSV Intelligence** | OSV-Scanner | `TOOL-OSV-SCANNER` | SPECIALIZED | Google Open Source Vulnerabilities (OSV) Lookup | Standalone Go Binary (GitHub Release) |
| **Infrastructure IaC**| Checkov | `TOOL-CHECKOV` | PRIMARY | Terraform, Kubernetes, CloudFormation & Dockerfile SAST | Pure Python Package (pip) |
| **Cloud Posture** | Prowler | `TOOL-PROWLER` | PRIMARY | AWS, Azure, GCP & K8s CIS Benchmark Auditing | Pure Python Package (pip) |
| **Kubernetes CIS** | Kube-Bench | `TOOL-KUBE-BENCH` | SPECIALIZED | In-Cluster / Manifest CIS Kubernetes Benchmark Checker | Standalone Go Binary (GitHub Release) |
| **Container Linter** | Dockle | `TOOL-DOCKLE` | SPECIALIZED | Container Image Best Practice & CIS Docker Linter | Standalone Go Binary (GitHub Release) |

---

## 2. Individual Tool Assurance Reviews

### 1. Nmap (Network Port & Service Discovery)
- **Security Domain**: Network / Perimeter / EASM
- **Tool ID**: `TOOL-NMAP`
- **Purpose**: Network port discovery, service version detection, TLS certificate & SSH cipher enumeration.
- **Enterprise Maturity**: Production-Mature (Industry Standard).
- **Approved Release Version**: `7.95` (`Nmap 7.95` exact pinning; `actual_version == approved_version`).
- **Supply-Chain Trust Mode**: `PACKAGE_MANAGER_MODE` (System Package Manager / WinGet / apt).
- **Upstream Project**: https://nmap.org (Insecure.Org).
- **Execution Method**: Sandboxed subprocess via `ProcessSupervisor` with process tree tracking and 60s bounded timeout.
- **Target Types**: `IP`, `DOMAIN`, `URL` via immutable `ValidatedTarget`. Invokes target `ValidatedTarget.selected_destination` (IP) with `--script-args http.host=<canonical_value>`.
- **Safety Controls**: Three-tier intrusive authorization gate (Tool Capability + Profile Authorization + Tenant Scope Authorization), pre-resolved IP destination binding, zero raw CLI argument injection.
- **Approved NSE Script Allowlist**: `banner`, `ssl-cert`, `http-title`, `ssh2-enum-algos`, `dns-nsec-enum` (`dns-nsec-enum` restricted strictly to DOMAIN targets with explicit DNS zone authorization; aggregate `-sC` prohibited).
- **Output Format & Parser**: XML output (`-oX -`) parsed via hardened XML parser resilient against malformed inputs and entity expansion.
- **Secret Sanitization**: High-entropy tokens, passwords, and API keys masked in banners and script outputs (`sanitize_banner_or_script`).
- **Finding Normalization**: Check IDs `NET-PORT-001` (Database Ports - High), `NET-PORT-002` (NoSQL/Cache Ports - High), `NET-PORT-003` (Remote Mgmt - Medium), `NET-SVC-001` (Service Posture - Info).
- **Failure Handling**: Zero cascade failure; missing or failed Nmap preserves `tool_failed` event log, degrades assessment coverage (`COVERAGE_DEGRADED`), and activates native fallback tagged with `source_tool="native"`.
- **Role Strategy**: **PRIMARY**. Retain native port checker as non-blocking fallback.
- **Implementation Status**: `REPOSITORY_VERIFIED` (Passed all 13 security assurance tests, 53 adapter tests, 30 adversarial tests, and 32 acceptance scenarios).

### 2. SSLyze (TLS/SSL Cipher Suite & Protocol Analyzer)
- **Security Domain**: Network / TLS
- **Purpose**: Evaluates SSLv2/SSLv3/TLSv1.0/1.1/1.2/1.3 protocol support, weak ciphers (RC4, 3DES, EXPORT, NULL), certificate chains, and expiration.
- **Enterprise Maturity**: Production-Mature.
- **Upstream Project**: https://github.com/nabla-c0d3/sslyze (Python library & CLI).
- **Execution Method**: Async Python API invocation / `ProcessSupervisor` subprocess.
- **Safety Controls**: Universal target gateway, pre-resolved hostname verification.
- **Finding Normalization**: Check IDs `NET-TLS-001` (Insecure TLS 1.0/1.1), `NET-TLS-002` (Weak Ciphers), `NET-TLS-003` (Expiring/Expired Certs), CWE-326, CWE-327.
- **Role Strategy**: **PRIMARY**. Complemented by native TLS auditor.

### 3. Subfinder (Passive Subdomain Enumeration)
- **Security Domain**: Perimeter / EASM
- **Purpose**: Discovers valid subdomains passively via Certificate Transparency logs, VirusTotal, SecurityTrails, and DNS datasets without active probing.
- **Enterprise Maturity**: Implementation in progress; repository controls are partially verified.
- **Upstream Project**: ProjectDiscovery (https://github.com/projectdiscovery/subfinder).
- **Version Pinning & Integrity**: Pinned in `PINNED_TOOL_MANIFEST` with exact SHA-256 binary digests.
- **Safety Controls**: Structured allowlisted command, exact-version gate, JSONL-only parsing, deterministic hostname validation, authorized-root scope classification, and no automatic DNS probing or inventory admission. Provider egress policy/credential injection remains unimplemented.
- **Output Format & Parser**: Line-by-line JSON output (`-json -silent`).
- **Finding Normalization**: Emits discovery observations and `NET-OSINT-001` informational findings; out-of-scope and malformed records are rejected with warnings and are not emitted as candidates.
- **Role Strategy**: **PRIMARY**. Complemented by native `crt.sh` client. Discovery is not authorization and does not itself create an active scan target.

### 4. httpx (High-Speed Multi-Purpose HTTP Prober)
- **Security Domain**: HTTP Probing & Discovery
- **Purpose**: Probes discovered subdomains/IPs for live HTTP/HTTPS services, status codes, title, technology stack, and TLS SANs.
- **Enterprise Maturity**: Production-Mature.
- **Upstream Project**: ProjectDiscovery (https://github.com/projectdiscovery/httpx).
- **Safety Controls**: Pre-resolved IP validation, bounded concurrency (`-t 10`), SSRF blocklist enforcement.
- **Output Format & Parser**: JSON Lines parsed safely line by line.
- **Role Strategy**: **VALIDATION**. Enriches discovered attack surface before DAST execution.

### 5. Nuclei (Template-Based DAST & Vulnerability Scanner)
- **Security Domain**: Web DAST
- **Purpose**: Fast, template-based vulnerability assessment covering CVEs, default credentials, security misconfigurations, and exposed panels.
- **Enterprise Maturity**: Production-Mature.
- **Upstream Project**: ProjectDiscovery (https://github.com/projectdiscovery/nuclei).
- **Template Trust Policy**: Uses official curated `nuclei-templates` release; arbitrary user-provided template execution is restricted to authorized admin tenants.
- **Safety Controls**: Concurrency capped at 10 requests/sec, rate limiting enforced, reproduction curl commands sanitized.
- **Finding Normalization**: Maps `template-id` to canonical check catalog, extracts `reproduction_curl`, CVSS score, CWE mapping.
- **Role Strategy**: **PRIMARY**. Complements native DAST engine.

### 6. FFuF (Fast Web Parameter & Endpoint Fuzzer)
- **Security Domain**: Web Fuzzing
- **Purpose**: Active fuzzing of hidden GET/POST parameters, endpoints, and authentication headers.
- **Enterprise Maturity**: Production-Mature.
- **Upstream Project**: https://github.com/ffuf/ffuf.
- **Safety Controls**: Explicit assessment profiles (Safe/Standard/Aggressive), bounded rate limiting, exclude destructive keywords (`logout`, `delete`, `reset`).
- **Output Format & Parser**: JSON output (`-o out.json -of json`).
- **Finding Normalization**: Check IDs `DAST-INJ-001` (SQLi), `DAST-XSS-001` (Reflected XSS), `DAST-PARAM-001` (Hidden Parameter Exposure).
- **Role Strategy**: **SPECIALIZED**. Runs under active fuzzing profile.

### 7. Katana (Next-Gen Headless & DOM Web Crawler)
- **Security Domain**: Web Crawling & Discovery
- **Purpose**: Crawls modern JavaScript Single-Page Applications (SPAs) and traditional HTML sites to map attack surface.
- **Enterprise Maturity**: Production-Mature.
- **Upstream Project**: ProjectDiscovery (https://github.com/projectdiscovery/katana).
- **Safety Controls**: Maximum crawl depth (ge=1, le=5), page limit bounding (max 50), same-origin scope confinement, automatic logout pattern exclusions.
- **Output Format & Parser**: JSON stream parsed into `DiscoveredEndpoint` objects.
- **Role Strategy**: **PRIMARY**. Feeds endpoints to DAST and fuzzing engines.

### 8. Schemathesis (Property-Based API Contract Security)
- **Security Domain**: API Security
- **Purpose**: Property-based contract testing against OpenAPI (Swagger) 2.0/3.0 and GraphQL schemas to detect server crashes, 500 errors, and schema violations.
- **Enterprise Maturity**: Production-Mature.
- **Upstream Project**: https://github.com/schemathesis/schemathesis.
- **Safety Controls**: Rate-limited, bounded execution timeout, schema sandboxing.
- **Finding Normalization**: Check IDs `API-SPEC-001` (Schema Violation), `API-FLAW-001` (Unhandled 500 Server Error).
- **Role Strategy**: **SPECIALIZED**. Executed during API-focused assessment profiles.

### 9. Semgrep (Polyglot AST Static Analysis Engine)
- **Security Domain**: Code SAST
- **Purpose**: Fast syntax-aware and semantic code analysis across 30+ programming languages.
- **Enterprise Maturity**: Enterprise-Grade.
- **Upstream Project**: Semgrep (https://github.com/semgrep/semgrep).
- **Rule Governance**: Pinned official Semgrep rulesets (`auto`, `security`, `p/owasp-top-ten`).
- **Safety Controls**: Workspace path sandboxing, absolute root confinement, symlink traversal prevention.
- **Output Format & Parser**: JSON output (`--json`) parsed into `Finding` records with AST line numbers and code snippets.
- **Finding Normalization**: Maps Semgrep check IDs to `SAST-INJ-xxx`, `SAST-SEC-xxx`, `SAST-CRYPTO-xxx`.
- **Role Strategy**: **PRIMARY**. Complemented by native Python AST taint analyzer.

### 10. Bandit (Python AST Security Linter)
- **Security Domain**: Code SAST (Python)
- **Purpose**: In-depth Python AST inspection for dangerous function calls (e.g. `eval`, `pickle.loads`, `os.system`, weak pseudo-random generators).
- **Enterprise Maturity**: Production-Mature.
- **Upstream Project**: PyCQA (https://github.com/PyCQA/bandit).
- **Safety Controls**: Sandboxed execution on authorized workspace directory.
- **Output Format & Parser**: JSON output (`-f json`).
- **Finding Normalization**: Check IDs `SAST-PY-001` (Dangerous Eval/Exec), `SAST-CRYPTO-001` (Insecure Hash/Cipher), CWE-94, CWE-327.
- **Role Strategy**: **SPECIALIZED**. Deep inspection for Python repositories.

### 11. Gitleaks (High-Speed Git Commit & Filesystem Secret Scanner)
- **Security Domain**: Secret Detection
- **Purpose**: High-speed regex and entropy scanning across git commit history and working tree files.
- **Enterprise Maturity**: Enterprise-Grade.
- **Upstream Project**: https://github.com/gitleaks/gitleaks.
- **Safety Controls**: Evidence secret masking (secrets are sanitized to `AKIA****` or `sha256(secret)` before storage/logging).
- **Output Format & Parser**: JSON report (`--report-format json`).
- **Finding Normalization**: Check IDs `SAST-SEC-001` (Hardcoded Secret), CWE-798, CWE-259.
- **Role Strategy**: **PRIMARY**. Complemented by TruffleHog live verification.

### 12. TruffleHog (Live-Verified Secret & Credential Scanner)
- **Security Domain**: Secret Verification
- **Purpose**: Detects 800+ credential types and performs safe, non-destructive active canary validation against upstream identity providers.
- **Enterprise Maturity**: Enterprise-Grade.
- **Upstream Project**: Truffle Security (https://github.com/trufflesecurity/trufflehog).
- **Evidence Handling**: Stores `VerifiedSecretEvidence` with live confirmation flag, masked account ID, and verified permissions while redacting raw secret.
- **Role Strategy**: **VALIDATION**. Upgrades secret confidence from `DETECTED` to `VALIDATED`.

### 13. Retire.js (JavaScript Dependency Vulnerability Scanner)
- **Security Domain**: Client-Side SCA
- **Purpose**: Identifies vulnerable and outdated JavaScript libraries (jQuery, AngularJS, Bootstrap, Lodash, React) in source code and web endpoints.
- **Enterprise Maturity**: Production-Mature.
- **Upstream Project**: https://github.com/RetireJS/retire.js.
- **Finding Normalization**: Check ID `SAST-DEP-002` (Vulnerable Client-Side Library), CWE-1395.
- **Role Strategy**: **SPECIALIZED**. Web client-side supply chain analysis.

### 14. Trivy (Container, Filesystem & IaC Vulnerability Scanner)
- **Security Domain**: Container / SCA / IaC
- **Purpose**: Comprehensive security scanner for container images, rootfs, git repos, and configuration manifests.
- **Enterprise Maturity**: Enterprise-Grade.
- **Upstream Project**: Aqua Security (https://github.com/aquasecurity/trivy).
- **Safety Controls**: Path sandbox confinement, pinned DB cache, zero external network dependency during offline scans.
- **Output Format & Parser**: Structured JSON output (`--format json`).
- **Finding Normalization**: Extracts CVE ID, CVSS score, package name, installed/fixed version into `SAST-DEP-001`.
- **Role Strategy**: **PRIMARY**. Container and package auditing.

### 15. Grype (Fast Dependency Vulnerability Scanner)
- **Security Domain**: SCA
- **Purpose**: Scans software packages and container images against multiple vulnerability databases (NVD, GitHub Advisories, Red Hat, Debian, Ubuntu).
- **Enterprise Maturity**: Enterprise-Grade.
- **Upstream Project**: Anchore (https://github.com/anchore/grype).
- **Output Format & Parser**: JSON output (`-o json`).
- **Role Strategy**: **VALIDATION**. Cross-verifies Trivy SCA vulnerability findings.

### 16. Syft (Comprehensive SBOM Generation Engine)
- **Security Domain**: Software Supply Chain & SBOM
- **Purpose**: Generates compliant Software Bill of Materials (SBOM) in CycloneDX 1.5 JSON and SPDX 2.3 JSON formats.
- **Enterprise Maturity**: Enterprise-Grade.
- **Upstream Project**: Anchore (https://github.com/anchore/syft).
- **Output Format**: Native CycloneDX 1.5 JSON and SPDX 2.3 JSON.
- **Integration**: Captured as `SBOMReport` and linked to scan job and target asset.
- **Role Strategy**: **PRIMARY**. Authoritative SBOM generation.

### 17. OSV-Scanner (Google Open Source Vulnerabilities Scanner)
- **Security Domain**: SCA / Open Source Intelligence
- **Purpose**: Scans project lockfiles (`package-lock.json`, `poetry.lock`, `go.sum`, `Cargo.lock`) against Google's distributed OSV database.
- **Enterprise Maturity**: Production-Mature.
- **Upstream Project**: Google (https://github.com/google/osv-scanner).
- **Role Strategy**: **SPECIALIZED**. Precision lockfile auditing.

### 18. Checkov (Static Analysis for Infrastructure-as-Code)
- **Security Domain**: IaC Security
- **Purpose**: Static analysis of Terraform, Kubernetes manifests, Dockerfiles, CloudFormation, and GitHub Actions workflows for security misconfigurations.
- **Enterprise Maturity**: Enterprise-Grade.
- **Upstream Project**: Bridgecrew / Palo Alto Networks (https://github.com/bridgecrewio/checkov).
- **Finding Normalization**: Maps Checkov policy IDs to `IAC-MISCONF-001`, `IAC-K8S-001`, `IAC-DOCKER-001`, CWE-16.
- **Role Strategy**: **PRIMARY**. Complements native IaC auditor.

### 19. Prowler (Cloud Security Posture Assessment)
- **Security Domain**: Cloud Security (CSPM)
- **Purpose**: Assesses AWS, Azure, GCP, and Kubernetes environments against CIS Benchmarks, NIST SP 800-53, and ISO 27001.
- **Enterprise Maturity**: Enterprise-Grade.
- **Upstream Project**: Prowler (https://github.com/prowler-cloud/prowler).
- **Credential Governance**: Restricted to IAM Role AssumeRole / Workload Identity; raw long-lived static credentials rejected.
- **Role Strategy**: **PRIMARY**. Cloud posture auditing.

### 20. Kube-Bench (CIS Kubernetes Benchmark Checker)
- **Security Domain**: Kubernetes Security
- **Purpose**: Verifies whether Kubernetes clusters are deployed according to CIS Kubernetes Benchmark recommendations.
- **Enterprise Maturity**: Production-Mature.
- **Upstream Project**: Aqua Security (https://github.com/aquasecurity/kube-bench).
- **Role Strategy**: **SPECIALIZED**. Dedicated Kubernetes control plane and node compliance.

### 21. Dockle (Container Image Linter for CIS & Security Best Practices)
- **Security Domain**: Container Security
- **Purpose**: Inspects container images for CIS Docker Benchmark compliance, root user execution, sensitive file exposure, and unnecessary privileges.
- **Enterprise Maturity**: Production-Mature.
- **Upstream Project**: GoodWithTech (https://github.com/goodwithtech/dockle).
- **Role Strategy**: **SPECIALIZED**. Dedicated Dockerfile and container image hardening.

---

## 3. Tool Overlap & Value Synergy Analysis

| Overlap Group | Integrated Tools | Value Synergy & False-Positive Reduction Strategy |
|---|---|---|
| **Secret Detection** | Gitleaks + TruffleHog | Gitleaks provides ultra-fast git commit history traversal; TruffleHog provides active canary verification to filter out dummy/dead credentials without exposing secrets. |
| **SCA Vulnerabilities**| Trivy + Grype + OSV-Scanner | Trivy scans containers and filesystems; Grype provides multi-distro vulnerability correlation; OSV-Scanner provides exact commit/version boundary precision from Google OSV. |
| **Subdomain & EASM** | Subfinder + crt.sh + httpx | Subfinder enumerates passive OSINT; crt.sh queries Certificate Transparency; httpx verifies live HTTP endpoints and TLS SAN properties. |
| **Code SAST** | Semgrep + Bandit + Native AST | Semgrep audits polyglot codebases; Bandit performs deep Python AST flow analysis; Native AST provides specialized zero-dependency taint tracking. |
| **IaC & Containers** | Checkov + Dockle + Kube-bench | Checkov verifies Terraform & K8s manifests; Dockle audits image layer best practices; Kube-bench verifies live CIS benchmark controls. |

---

## 4. Assessment Methodology Lifecycle (10 Stages)

```text
[1. Authorization & Scope Validation]
        ↓
[2. Target Normalization & SSRF Pre-Resolution Gateway (ValidatedTarget)]
        ↓
[3. Multi-Engine Parallel & Staged Orchestration]
        ↓
[4. External Tool Execution via Sandboxed ProcessSupervisor]
        ↓
[5. Structured Output Parsing & Zero Cascade Error Handling]
        ↓
[6. Canonical Finding Deduplication & SLA Clock Preservation]
        ↓
[7. Contextual Risk Scoring (CVSS v3.1 + Criticality + Exposure)]
        ↓
[8. Cryptographic Tamper-Evident Chained Audit Logging]
        ↓
[9. Export Pipeline (SARIF v2.1.0, CycloneDX 1.5 SBOM, Offline HTML)]
        ↓
[10. Remediation Lifecycle & Retest Verification]
```
