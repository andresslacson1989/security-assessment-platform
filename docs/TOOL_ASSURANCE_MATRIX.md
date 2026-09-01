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
- **Runtime Evidence**: The host Nmap executable reports `7.991`, not the approved `7.95`; approved managed Nmap runtime verification is `UNAVAILABLE`.

### 2. SSLyze (TLS/SSL Cipher Suite & Protocol Analyzer)
- **Security Domain**: Network / TLS
- **Purpose**: Evaluates SSLv2/SSLv3/TLSv1.0/1.1/1.2/1.3 protocol support, weak ciphers (RC4, 3DES, EXPORT, NULL), certificate chains, and expiration.
- **Enterprise Maturity**: Production-Mature.
- **Upstream Project**: https://github.com/nabla-c0d3/sslyze (Python library & CLI).
- **Execution Method**: Async Python API invocation / `ProcessSupervisor` subprocess.
- **Safety Controls**: Universal target gateway, pre-resolved hostname verification.
- **Finding Normalization**: Check IDs `NET-TLS-001` (Insecure TLS 1.0/1.1), `NET-TLS-002` (Weak Ciphers), `NET-TLS-003` (Expiring/Expired Certs), CWE-326, CWE-327.
- **Role Strategy**: **PRIMARY**. Complemented by native TLS auditor.
- **Runtime Evidence**: The host SSLyze package reports `6.3.1`, not the approved `5.2.0`; approved managed SSLyze runtime verification is `UNAVAILABLE`.

### 3. Subfinder (Passive Subdomain Enumeration)
- **Security Domain**: Perimeter / EASM
- **Purpose**: Discovers valid subdomains passively through the governed public `crtsh` provider baseline without active probing. Additional credentialed providers remain disabled.
- **Enterprise Maturity**: Repository controls and managed-runtime evidence verified for the approved Subfinder path; provider egress governance and explicit inventory admission remain broader pending capabilities.
- **Upstream Project**: ProjectDiscovery (https://github.com/projectdiscovery/subfinder).
- **Version Pinning & Integrity**: Pinned in `PINNED_TOOL_MANIFEST` with exact SHA-256 binary digests.
- **Safety Controls**: Structured allowlisted command, exact-version gate, JSONL-only parsing, deterministic hostname validation, authorized-root scope classification, public `crtsh` provider allowlist, no credential injection, and no automatic DNS probing or inventory admission. Broader provider egress policy/credential injection remains unimplemented.
- **Output Format & Parser**: Line-by-line JSON output (`-json -silent`).
- **Finding Normalization**: Emits discovery observations and `NET-OSINT-001` informational findings; out-of-scope and malformed records are rejected with warnings and are not emitted as candidates.
- **Role Strategy**: **PRIMARY**. Complemented by an independent native `crt.sh` enrichment path. Discovery is not authorization and does not itself create an active scan target.
- **Runtime Evidence**: On 2026-09-01, the production adapter executed the approved managed `backend/bin/subfinder.exe`, verified its managed trust record and SHA-256 binding, confirmed `subfinder v2.6.5`, and completed a governed `example.com` run with normalized state `COMPLETED_NO_FINDINGS`.
- **Architectural Limitation**: Explicit inventory admission and active-target authorization are broader product capabilities and are not implemented by this adapter.

### 4. httpx (High-Speed Multi-Purpose HTTP Prober)
- **Security Domain**: HTTP Probing & Discovery
- **Purpose**: Probes discovered subdomains/IPs for live HTTP/HTTPS services, status codes, title, technology stack, and TLS SANs.
- **Enterprise Maturity**: Repository controls verified; approved managed-runtime evidence remains unavailable in this environment.
- **Upstream Project**: ProjectDiscovery (https://github.com/projectdiscovery/httpx).
- **Safety Controls**: Engine-level validated-target handoff, selected-destination binding with Host/SNI preservation, exact-version gate, managed-binary preflight, bounded execution, and SSRF blocklist enforcement.
- **Output Format & Parser**: JSON Lines parsed safely line by line.
- **Role Strategy**: **VALIDATION**. Enriches discovered attack surface before DAST execution.
- **Runtime Evidence**: Approved managed httpx `v1.6.0` executable was unavailable in this verification environment; real managed-runtime execution is `UNAVAILABLE`.

### 5. Nuclei (Template-Based DAST & Vulnerability Scanner)
- **Security Domain**: Web DAST
- **Purpose**: Fast, template-based vulnerability assessment covering CVEs, default credentials, security misconfigurations, and exposed panels.
- **Enterprise Maturity**: Production-Mature.
- **Approved Release Version**: `v3.2.0`; exact runtime version enforcement is fail-closed.
- **Upstream Project**: ProjectDiscovery (https://github.com/projectdiscovery/nuclei).
- **Template Trust Policy**: Uses official curated `nuclei-templates` release; arbitrary user-provided template execution is restricted to authorized admin tenants.
- **Safety Controls**: Managed-process preflight, validated-destination pinning with Host preservation, concurrency/rate bounds, curated fixed template tags, and sanitized reproduction evidence. Arbitrary template execution is not enabled.
- **Credential Handling**: Tenant credentials are not placed in CLI arguments; authenticated coverage is handled by the governed native HTTP session until secret-safe subprocess injection is implemented.
- **Finding Normalization**: Maps `template-id` to canonical check catalog, extracts `reproduction_curl`, CVSS score, CWE mapping.
- **Role Strategy**: **PRIMARY**. Complements native DAST engine.
- **Runtime Evidence**: Approved managed Nuclei runtime was unavailable in this verification environment; repository execution-path and adversarial controls are verified, real managed-runtime execution is `UNAVAILABLE`.

### 6. FFuF (Fast Web Parameter & Endpoint Fuzzer)
- **Security Domain**: Web Fuzzing
- **Purpose**: Active fuzzing of hidden GET/POST parameters, endpoints, and authentication headers.
- **Enterprise Maturity**: Production-Mature.
- **Approved Release Version**: `v2.1.0`; exact runtime version enforcement is fail-closed.
- **Upstream Project**: https://github.com/ffuf/ffuf.
- **Safety Controls**: Managed-process preflight, validated-destination pinning with Host preservation, bounded rate/concurrency, fixed server-generated wordlist, and destructive-path exclusions. DELETE/PUT fuzzing is not supported.
- **Credential Handling**: Tenant cookies/authentication headers are not placed in FFuF CLI arguments; authenticated coverage remains in the governed native session.
- **Output Format & Parser**: JSON output (`-o out.json -of json`).
- **Finding Normalization**: Check IDs `DAST-INJ-001` (SQLi), `DAST-XSS-001` (Reflected XSS), `DAST-PARAM-001` (Hidden Parameter Exposure).
- **Role Strategy**: **SPECIALIZED**. Runs under active fuzzing profile.
- **Runtime Evidence**: Approved managed FFuF runtime was unavailable in this verification environment; repository execution-path and adversarial controls are verified, real managed-runtime execution is `UNAVAILABLE`.

### 7. Katana (Next-Gen Headless & DOM Web Crawler)
- **Security Domain**: Web Crawling & Discovery
- **Purpose**: Crawls modern JavaScript Single-Page Applications (SPAs) and traditional HTML sites to map attack surface.
- **Enterprise Maturity**: Production-Mature.
- **Approved Release Version**: `v1.0.5`; exact runtime version enforcement is fail-closed.
- **Upstream Project**: ProjectDiscovery (https://github.com/projectdiscovery/katana).
- **Safety Controls**: Managed-process preflight, validated-destination pinning with Host preservation, maximum crawl depth/page bounds, explicit same-origin redirect handling, and automatic logout/destructive-path exclusions.
- **Credential Handling**: Tenant credentials are not placed in Katana CLI arguments; authenticated coverage remains in the governed native session.
- **Output Format & Parser**: JSON stream parsed into `DiscoveredEndpoint` objects.
- **Role Strategy**: **PRIMARY**. Feeds endpoints to DAST and fuzzing engines.
- **Runtime Evidence**: Approved managed Katana runtime was unavailable in this verification environment; repository execution-path and adversarial controls are verified, real managed-runtime execution is `UNAVAILABLE`.

### 8. Schemathesis (Property-Based API Contract Security)
- **Security Domain**: API Security
- **Purpose**: Property-based contract testing against OpenAPI (Swagger) 2.0/3.0 and GraphQL schemas to detect server crashes, 500 errors, and schema violations.
- **Enterprise Maturity**: Production-Mature.
- **Approved Release Version**: `3.20.0`; exact runtime version enforcement is fail-closed.
- **Upstream Project**: https://github.com/schemathesis/schemathesis.
- **Safety Controls**: Managed-process preflight, validated-destination binding with Host preservation, bounded examples/timeouts, and state-changing operation support limited to an API profile plus an explicit internal tenant authorization grant; otherwise execution is blocked.
- **Credential Handling**: Tenant bearer tokens are not placed in Schemathesis CLI arguments; authenticated state-changing external execution remains fail-closed until secret-safe subprocess injection exists.
- **Finding Normalization**: Check IDs `API-SPEC-001` (Schema Violation), `API-FLAW-001` (Unhandled 500 Server Error).
- **Role Strategy**: **SPECIALIZED**. Executed during API-focused assessment profiles.
- **Runtime Evidence**: Approved managed Schemathesis runtime was unavailable in this verification environment; repository execution-path and adversarial controls are verified, real managed-runtime execution is `UNAVAILABLE`.

### E12 Section Evidence Status
- **Repository status**: `REPOSITORY_VERIFIED` for the implemented execution states, API visibility, exact-version fail-closed gates, destination binding, redirect confinement, and focused adversarial tests.
- **Managed runtime status**: `UNAVAILABLE` for all four approved managed E12 runtimes in the current environment; no unmanaged executable was substituted.
- **Acceptance evidence**: Full repository regression completed with `280 passed, 1 skipped`; runtime execution remains separately reported as `UNAVAILABLE` for all four approved managed E12 runtimes.

### 9. Semgrep (Polyglot AST Static Analysis Engine)
- **Security Domain**: Code SAST
- **Purpose**: Fast syntax-aware and semantic code analysis across 30+ programming languages.
- **Enterprise Maturity**: Enterprise-Grade.
- **Upstream Project**: Semgrep (https://github.com/semgrep/semgrep).
- **Rule Governance**: Pinned official Semgrep rulesets (`auto`, `security`, `p/owasp-top-ten`).
- **Safety Controls**: Engine/API workspace authorization, canonical path and symlink confinement, exact `1.65.0` package gate, pre-launch verification, fixed `auto` ruleset, and bounded supervised execution.
- **Output Format & Parser**: JSON output (`--json`) parsed into `Finding` records with AST line numbers and code snippets.
- **Finding Normalization**: Maps Semgrep check IDs to `SAST-INJ-xxx`, `SAST-SEC-xxx`, `SAST-CRYPTO-xxx`.
- **Role Strategy**: **PRIMARY**. Complemented by native Python AST taint analyzer.

### 10. Bandit (Python AST Security Linter)
- **Security Domain**: Code SAST (Python)
- **Purpose**: In-depth Python AST inspection for dangerous function calls (e.g. `eval`, `pickle.loads`, `os.system`, weak pseudo-random generators).
- **Enterprise Maturity**: Production-Mature.
- **Upstream Project**: PyCQA (https://github.com/PyCQA/bandit).
- **Safety Controls**: Engine/API workspace authorization, canonical path and symlink confinement, exact `1.7.8` package gate, pre-launch verification, and bounded supervised execution.
- **Output Format & Parser**: JSON output (`-f json`).
- **Finding Normalization**: Check IDs `SAST-PY-001` (Dangerous Eval/Exec), `SAST-CRYPTO-001` (Insecure Hash/Cipher), CWE-94, CWE-327.
- **Role Strategy**: **SPECIALIZED**. Deep inspection for Python repositories.

### 11. Gitleaks (High-Speed Git Commit & Filesystem Secret Scanner)
- **Security Domain**: Secret Detection
- **Purpose**: High-speed regex and entropy scanning across git commit history and working tree files.
- **Enterprise Maturity**: Enterprise-Grade.
- **Upstream Project**: https://github.com/gitleaks/gitleaks.
- **Safety Controls**: Authorized workspace confinement, Git history invocation through `ProcessSupervisor`, exact `v8.18.2` gate, managed executable verification, bounded output, and mandatory secret masking.
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
- **Safety Controls**: Authorized workspace confinement, exact `v3.63.0` gate, managed executable verification, `--no-update`, explicit tenant authorization for live verification, and masked evidence.

### 13. Retire.js (JavaScript Dependency Vulnerability Scanner)
- **Security Domain**: Client-Side SCA
- **Purpose**: Identifies vulnerable and outdated JavaScript libraries (jQuery, AngularJS, Bootstrap, Lodash, React) in source code and web endpoints.
- **Enterprise Maturity**: Production-Mature.
- **Upstream Project**: https://github.com/RetireJS/retire.js.
- **Finding Normalization**: Check ID `SAST-DEP-002` (Vulnerable Client-Side Library), CWE-1395.
- **Role Strategy**: **SPECIALIZED**. Web client-side supply chain analysis.
- **Safety Controls**: Authorized workspace confinement, exact `4.4.3` gate, managed package verification, offline `--nodownload` execution, bounded supervised process, and normalized parser failure state.

### E13 Section Evidence Status
- **Repository status**: `REWORK IN PROGRESS` after independent review identified and corrected shared process-supervision, fallback-provenance, attribution, evidence-sanitization, and authoritative-persistence defects. Focused controls are covered by adversarial tests; final acceptance awaits the post-correction full regression.
- **Managed runtime status**: `UNAVAILABLE` for all approved E13 runtimes in the current environment. Semgrep reports `1.175.0` (approved `1.65.0`), Bandit reports `1.9.4` (approved `1.7.8`), and Trivy reports `0.74.0` (approved `0.50.0`); Gitleaks is present but does not yield an approved managed runtime/trust record; TruffleHog, Retire.js, Grype, Syft, and OSV-Scanner are unavailable. No unmanaged runtime is treated as evidence.
- **Regression evidence**: Post-correction focused assurance/orchestration tests completed with `85 passed, 2 skipped`; full repository regression completed with `287 passed, 3 skipped, 4 warnings`.
- **Coverage limitation**: Native fallbacks are explicitly limited compared with the external tools; failed, blocked, timed-out, cancelled, or parser-degraded tools must remain visible as degraded coverage.

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
