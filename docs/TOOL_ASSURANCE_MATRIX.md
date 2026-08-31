# CyberAssess v13 — Enterprise Tool Assurance Program & Methodology Matrix

## Document Purpose & Authority
This authoritative specification details the **Enterprise Tool Assurance Review** for all 21 external security tools integrated into the CyberAssess platform. In strict accordance with CyberAssess v13 Methodology, popularity alone does not qualify a tool as enterprise-grade. Each tool and CyberAssess's implementation of that tool are evaluated across safety controls, execution governance, supply chain provenance, finding normalization, failure semantics, and overlap strategy.

---

## 1. Tool Taxonomy & Role Classification Strategy

| Security Domain | Tool Name | Tool Role | Primary / Fallback Purpose | Upstream Artifact Type |
|---|---|---|---|---|
| **Network / EASM** | Nmap | PRIMARY | Network Port Probing & Service Fingerprinting | Compiled System Executable / WinGet |
| **Network / TLS** | SSLyze | PRIMARY | Comprehensive TLS Protocol & Cipher Suite Analysis | Pure Python Package (pip) |
| **Perimeter / EASM** | Subfinder | PRIMARY | Passive Multi-Source Subdomain Enumeration | Standalone Go Binary (GitHub Release) |
| **HTTP Probing** | httpx | VALIDATION | High-Speed HTTP Endpoint Verification & Technology Detection | Standalone Go Binary (GitHub Release) |
| **Web DAST** | Nuclei | PRIMARY | Template-Driven CVE & Misconfiguration Scanning | Standalone Go Binary (GitHub Release) |
| **Web Fuzzing** | FFuF | SPECIALIZED | Active Parameter, Directory & Header Fuzzing | Standalone Go Binary (GitHub Release) |
| **Web Crawling** | Katana | PRIMARY | Next-Gen Headless & Standard DOM Crawling | Standalone Go Binary (GitHub Release) |
| **API Contract DAST** | Schemathesis | SPECIALIZED | Property-Based OpenAPI / GraphQL Contract Fuzzing | Pure Python Package (pip) |
| **Code SAST** | Semgrep | PRIMARY | AST Pattern Matching & Polyglot Code Auditing | Standalone Binary / Python CLI |
| **Code SAST (Python)**| Bandit | SPECIALIZED | Deep Python AST Vulnerability & Crypto Linting | Pure Python Package (pip) |
| **Secret Scanning** | Gitleaks | PRIMARY | Git Commit History & Filesystem Secret Scanner | Standalone Go Binary (GitHub Release) |
| **Secret Verification**| TruffleHog | VALIDATION | Live Real-Time Credential Validation Engine | Standalone Go Binary (GitHub Release) |
| **Client-Side JS** | Retire.js | SPECIALIZED | Vulnerable JavaScript Library Auditor | Standalone Node/Go Binary |
| **Container / SCA** | Trivy | PRIMARY | Multi-Domain Container, FS & Dependency Scanner | Standalone Go Binary (GitHub Release) |
| **SCA Vulnerability** | Grype | VALIDATION | Fast Dependency Vulnerability Identification | Standalone Go Binary (GitHub Release) |
| **SBOM Generation** | Syft | PRIMARY | CycloneDX & SPDX Software Bill of Materials Engine | Standalone Go Binary (GitHub Release) |
| **OSV Intelligence** | OSV-Scanner | SPECIALIZED | Google Open Source Vulnerabilities (OSV) Lookup | Standalone Go Binary (GitHub Release) |
| **Infrastructure IaC**| Checkov | PRIMARY | Terraform, Kubernetes, CloudFormation & Dockerfile SAST | Pure Python Package (pip) |
| **Cloud Posture** | Prowler | PRIMARY | AWS, Azure, GCP & K8s CIS Benchmark Auditing | Pure Python Package (pip) |
| **Kubernetes CIS** | Kube-Bench | SPECIALIZED | In-Cluster / Manifest CIS Kubernetes Benchmark Checker | Standalone Go Binary (GitHub Release) |
| **Container Linter** | Dockle | SPECIALIZED | Container Image Best Practice & CIS Docker Linter | Standalone Go Binary (GitHub Release) |

---

## 2. Individual Tool Assurance Reviews

### 1. Nmap (Network Port & Service Discovery)
- **Security Domain**: Network / EASM
- **Purpose**: Network port discovery, service version detection, OS fingerprinting.
- **Enterprise Maturity**: Production-Mature (Industry Standard).
- **Upstream Project**: https://nmap.org (Insecure.Org).
- **Execution Method**: Sandboxed subprocess via `ProcessSupervisor` with process-group isolation and 60s bounded timeout.
- **Target Types**: `IP`, `DOMAIN`. Raw user arguments prohibited; strictly generated from safe profiles.
- **Safety Controls**: Rate-limited, pre-resolved DNS verification, single-gateway target validation, zero raw CLI argument injection.
- **Output Format & Parser**: XML output (`-oX -`) parsed via Python `xml.etree.ElementTree` with defused entity expansion.
- **Finding Normalization**: Check IDs `NET-PORT-001`/`002`, `NET-SVC-001`, CVSS 7.5/5.3, CWE-200.
- **Failure Handling**: Zero cascade failure; falls back seamlessly to native port checker & banner grabber on failure.
- **Role Strategy**: **PRIMARY**. Retain native port checker as non-blocking fallback.

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
- **Enterprise Maturity**: Production-Mature.
- **Upstream Project**: ProjectDiscovery (https://github.com/projectdiscovery/subfinder).
- **Version Pinning & Integrity**: Pinned in `PINNED_TOOL_MANIFEST` with exact SHA-256 binary digests.
- **Safety Controls**: Passive queries only; zero direct network connection to target hosts; root domain pre-authorized.
- **Output Format & Parser**: Line-by-line JSON output (`-json -silent`).
- **Finding Normalization**: Emits `DiscoveredSubdomain` records and `NET-OSINT-001` findings.
- **Role Strategy**: **PRIMARY**. Complemented by native `crt.sh` client.

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
