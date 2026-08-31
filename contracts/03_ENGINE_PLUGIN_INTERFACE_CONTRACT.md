# Contract 03: Engine Plugin Interface & Module Implementation Contract

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 8.0.0 (Enterprise ASPM & EASM Suite, 22-Tool Parity, Software Supply Chain & CIS Benchmarks Architecture Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Assessment Engine Plugins, Submodules, Tool Adapters, In-App Installers & Execution Lifecycle  

---

## 1. Abstract Engine Interface (`BaseAssessmentEngine`)

Every assessment engine MUST subclass `BaseAssessmentEngine` defined in `backend/app/engines/base.py` and implement all abstract properties and methods.

```python
from abc import ABC, abstractmethod
from typing import List, Callable, Awaitable, Optional, Tuple
from app.core.models import Target, Finding, ScanConfig, LogLevel, DiscoveredEndpoint, DiscoveredSubdomain

# Asynchronous callback signatures for real-time telemetry streaming
LogCallback = Callable[[LogLevel, str], Awaitable[None]]
ProgressCallback = Callable[[int, str], Awaitable[None]]
FindingCallback = Callable[[Finding], Awaitable[None]]
AuthStatusCallback = Callable[[dict], Awaitable[None]]
EndpointDiscoveredCallback = Callable[[DiscoveredEndpoint], Awaitable[None]]
SubdomainDiscoveredCallback = Callable[[DiscoveredSubdomain], Awaitable[None]]

class BaseAssessmentEngine(ABC):
    """
    Authoritative abstract interface for all assessment engine plugins.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique machine identifier (e.g., 'network', 'web_dast', 'code_sast', 'infra_iac', 'cicd_audit')."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable display name for dashboard UI."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Detailed description of the security domain assessed by this engine."""
        pass

    @abstractmethod
    def is_applicable(self, target: Target) -> bool:
        """
        Determines whether this engine can execute against the provided target type.
        - network: URL, DOMAIN, IP
        - web_dast: URL, DOMAIN
        - code_sast: LOCAL_PATH
        - infra_iac: DOCKERFILE, IAC_MANIFEST, LOCAL_PATH
        - cicd_audit: LOCAL_PATH
        """
        pass

    @abstractmethod
    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        emit_finding: FindingCallback,
        **kwargs,
    ) -> List[Finding]:
        """
        Executes the engine's assessment checks asynchronously.
        Follows the 3-Stage Pipeline:
        1. Primary Adapters First (if available and enabled)
        2. Proprietary Native Enrichment (AST Taint, CT OSINT, Active Fuzzing, DNS)
        3. Resilient Native Fallback (if external tools are missing)
        """
        pass
```

---

## 2. Resilience, Error Isolation & Lifecycle Guarantees

1. **Zero Cascade Failure Guarantee:**
   - Any unhandled exception (e.g., `socket.timeout`, `httpx.ConnectError`, `dns.resolver.NXDOMAIN`, `yaml.YAMLError`, or tool subprocess failure) MUST be caught inside the engine/adapter boundary.
   - The engine logs the event via `emit_log(LogLevel.WARNING, ...)` and continues remaining checks.
2. **Cancellation Responsiveness:**
   - Async loops and subprocess execution MUST check for cancellation (`asyncio.CancelledError`). When cancelled, active sockets, HTTP connections, and child subprocesses MUST be terminated gracefully within 500ms.
3. **Strict Timeout Bounds:**
   - All network connections and socket operations MUST be bounded by explicit timeouts (HTTP $\le$ 10s, Socket $\le$ 2s, DNS $\le$ 3s, crt.sh $\le$ 10s, Tool Adapters $\le$ 60s).

---

## 3. Detailed Specifications for Core Engines & Submodules

### 3.1 Engine 1: Network, EASM, TLS, DNS & OSINT Auditor (`network`)
- Integrates `NmapAdapter`, `SslyzeAdapter`, `SubfinderAdapter`, `HttpxAdapter`.
- Native fallback & enrichment: `port_checker`, `banner_grabber`, `tls_auditor`, `dns_hygiene`, `subdomain_recon` (Certificate Transparency).

### 3.2 Engine 2: Web DAST, Headless SPA Crawler & API Contract Fuzzer (`web_dast`)
- Integrates `NucleiAdapter`, `FfufAdapter`, `KatanaAdapter`, `SchemathesisAdapter`.
- Native fallback & enrichment: `headers_cookies`, `cors_analyzer`, `api_inspector`, `browser_posture`, `crawler`, `auth_session`, `parameter_fuzzer`.

### 3.3 Engine 3: Code SAST, Taint Analysis & Verified Secrets (`code_sast`)
- Integrates `SemgrepAdapter`, `BanditAdapter`, `GitleaksAdapter`, `TruffleHogAdapter`, `RetireJSAdapter`.
- Native fallback & enrichment: `ast_taint_analyzer`, `secret_scanner`, `crypto_lint`, `injection_lint`, `git_history_scanner`.

### 3.4 Engine 4: Software Supply Chain Security & SBOM (`supply_chain` / `code_sast`)
- Integrates `TrivyAdapter`, `SyftAdapter`, `GrypeAdapter`, `OSVScannerAdapter`.
- Native fallback & enrichment: `dependency_auditor`, `lockfile_parser`, `cve_lookup`.

### 3.5 Engine 5: Infrastructure-as-Code, Container & Cloud CIS Benchmarks (`infra_iac`)
- Integrates `CheckovAdapter`, `ProwlerAdapter`, `KubeBenchAdapter`, `DockleAdapter`.
- Native fallback & enrichment: `dockerfile_auditor`, `compose_auditor`, `k8s_manifest_auditor`, `terraform_auditor`.

---

## 4. Pluggable Hybrid Tool Adapters Layer (`backend/app/adapters/`)

### 4.1 Abstract Tool Adapter Interface (`BaseToolAdapter`)
```python
class BaseToolAdapter(ABC):
    @property
    @abstractmethod
    def tool_name(self) -> str:
        pass

    def resolve_binary_path(self, custom_path: Optional[str] = None) -> Optional[str]:
        return UnifiedBinaryResolver.resolve(self.tool_name, custom_path)

    async def is_available(self, custom_path: Optional[str] = None) -> bool:
        path = self.resolve_binary_path(custom_path)
        if not path:
            return False
        return os.path.isfile(path) or os.path.exists(path)

    @abstractmethod
    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        pass

    @abstractmethod
    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
        **kwargs,
    ) -> List[Finding]:
        pass

    async def execute_command(
        self,
        cmd: List[str],
        timeout: float = 60.0,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
        emit_log: Optional[Callable[[LogLevel, str], Awaitable[None]]] = None,
    ) -> Tuple[int, str, str]:
        return await safe_execute_subprocess(cmd=cmd, timeout=timeout, cwd=cwd, env=env)
```

### 4.2 Complete 21-Tool Enterprise Adapter Matrix

| # | Tool Adapter | Binary | Execution Command | Output Format | Domain & Execution Role | Resilient Native Fallback | Finding Normalization |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **`NmapAdapter`** | `nmap` | `nmap -sV -sC --version-light -T4 -oX - <target>` | XML (`-oX -`) | **Network** Port & Service Scanner | `port_checker` + `banner_grabber` | Maps open ports and daemon versions to `NET-PORT-xxx`, `NET-SVC-001`. `source_tool="nmap"`. |
| 2 | **`SslyzeAdapter`** | `sslyze` | `sslyze --json_out=- <host>:<port>` | JSON (`--json_out=-`) | **Network** Deep TLS/SSL Auditor | `tls_auditor` | Maps deprecated TLS protocols and ciphers to `NET-TLS-xxx`. `source_tool="sslyze"`. |
| 3 | **`SubfinderAdapter`** | `subfinder` | `subfinder -d <domain> -silent -oJ` | JSON Lines | **EASM** Multi-Source Subdomain Recon | `subdomain_recon` (crt.sh) | Emits `DiscoveredSubdomain` records and `EASM-SUB-001`. `source_tool="subfinder"`. |
| 4 | **`HttpxAdapter`** | `httpx` | `httpx -u <target> -json -silent -title -tech-detect -status-code` | JSON Lines | **EASM** Web Port & Technology Probe | `api_inspector` | Emits `DiscoveredEndpoint` models and `EASM-EXPOSURE-001`. `source_tool="httpx"`. |
| 5 | **`NucleiAdapter`** | `nuclei` | `nuclei -u <target> -j -silent -tags cve,misconfig` | JSON Lines (`-j`) | **DAST** CVE Template Vulnerability Engine | `parameter_fuzzer` + `headers_cookies` | Maps Nuclei template IDs to canonical CWEs and `DAST-xxx`. `source_tool="nuclei"`. |
| 6 | **`FfufAdapter`** | `ffuf` | `ffuf -u <target>/FUZZ -w <wordlist> -mc 200,204,301,302,307,401,403 -o - -of json -t 5 -rate 10` | JSON (`-of json`) | **DAST** High-Speed Content Discovery | `crawler` | Discovers hidden routes and backup files, emitting `DAST-EXP-xxx`. `source_tool="ffuf"`. |
| 7 | **`KatanaAdapter`** | `katana` | `katana -u <target> -jsonl -silent -headless -d 3 -jc` | JSON Lines | **DAST** Headless SPA JavaScript Crawler | `crawler` (static HTML) | Discovers dynamic JS/React/Vue routes, emitting `DiscoveredEndpoint` and feeding DAST. `source_tool="katana"`. |
| 8 | **`SchemathesisAdapter`** | `schemathesis` | `schemathesis run <schema_url> --report-format json` | JSON | **API** Property-Based Contract Fuzzer | `api_inspector` | Tests OpenAPI/GraphQL schemas against BOLA/BFLA/500s, emitting `API-SCHEMA-001`. `source_tool="schemathesis"`. |
| 9 | **`SemgrepAdapter`** | `semgrep` | `semgrep scan --config auto --json <dir>` | JSON (`--json`) | **SAST** Multi-Language AST SAST | `injection_lint` + `crypto_lint` | Normalizes Semgrep rules into `SAST-xxx` with line numbers and diffs. `source_tool="semgrep"`. |
| 10 | **`BanditAdapter`** | `bandit` | `bandit -r <dir> -f json` | JSON (`-f json`) | **SAST** Python AST Security Linter | `crypto_lint` + `injection_lint` | Maps high/medium AST flaws to `SAST-CRY-xxx` and `SAST-INJ-xxx`. `source_tool="bandit"`. |
| 11 | **`GitleaksAdapter`** | `gitleaks` | `gitleaks detect --source <dir> --report-format json --report-path -` | JSON (`--report-format json`) | **SAST** Dedicated Git Secret Scanner | `secret_scanner` | Extracts hardcoded tokens and API keys with mandatory masking to `SAST-SEC-xxx`. `source_tool="gitleaks"`. |
| 12 | **`TruffleHogAdapter`** | `trufflehog` | `trufflehog filesystem <dir> --json --no-verification=false` | JSON Lines | **SAST** Verified Live Secret Scanner | `secret_scanner` | Identifies active verified API credentials with live verification probes, emitting `SEC-VERIFIED-001`. `source_tool="trufflehog"`. |
| 13 | **`RetireJSAdapter`** | `retire` | `retire --path <dir> --outputformat json` | JSON | **SAST** Client-Side JS Vulnerability Scanner | `dependency_auditor` | Audits front-end JavaScript libraries for known CVEs, emitting `SCA-JS-001`. `source_tool="retirejs"`. |
| 14 | **`TrivyAdapter`** | `trivy` | `trivy fs --format json <dir>` | JSON (`--format json`) | **SCA** Dependency & Container Scanner | `dependency_auditor` | Maps package and container vulnerabilities to `SAST-DEP-001` and `IAC-DOCK-xxx`. `source_tool="trivy"`. |
| 15 | **`SyftAdapter`** | `syft` | `syft <dir> -o cyclonedx-json` | CycloneDX JSON | **SCA** Software Bill of Materials (SBOM) Generator | `dependency_auditor` | Generates standardized CycloneDX/SPDX SBOMs and component inventories. `source_tool="syft"`. |
| 16 | **`GrypeAdapter`** | `grype` | `grype <dir> -o json` | JSON | **SCA** SBOM & Filesystem Vulnerability Matcher | `dependency_auditor` | Matches SBOM packages against vulnerability feeds, emitting `SCA-SBOM-001`. `source_tool="grype"`. |
| 17 | **`OSVScannerAdapter`** | `osv-scanner` | `osv-scanner scan --format json -r <dir>` | JSON | **SCA** Google OSV Lockfile Vulnerability Engine | `dependency_auditor` | Queries osv.dev for commit-hash accurate CVE matching, emitting `SCA-OSV-001`. `source_tool="osv_scanner"`. |
| 18 | **`CheckovAdapter`** | `checkov` | `checkov -d <dir> -o json --compact` | JSON (`-o json`) | **IaC** Infrastructure Policy Engine | `terraform_auditor` + `k8s_manifest_auditor` | Maps failed Terraform, K8s, Compose checks to `IAC-TF-xxx`, `IAC-K8S-xxx`. `source_tool="checkov"`. |
| 19 | **`DockleAdapter`** | `dockle` | `dockle -f json <image>` | JSON | **IaC** CIS Docker Container Hardening Linter | `dockerfile_auditor` | Checks image security (non-root, suid bits, CIS benchmark), emitting `DOCKER-CIS-001`. `source_tool="dockle"`. |
| 20 | **`KubeBenchAdapter`** | `kube-bench` | `kube-bench run --json` | JSON | **IaC / Cloud** CIS Kubernetes Benchmark Auditor | `k8s_manifest_auditor` | Audits master/node configs against CIS Kubernetes Benchmark, emitting `K8S-CIS-001`. `source_tool="kube_bench"`. |
| 21 | **`ProwlerAdapter`** | `prowler` | `prowler <provider> -M json` | JSON | **Cloud** Multi-Cloud CIS & Posture Auditor | `terraform_auditor` | Audits AWS/Azure/GCP against CIS Foundations Benchmarks, emitting `CLOUD-CIS-001`. `source_tool="prowler"`. |

---

## 5. In-App Tool Installers Engine (`backend/app/installers/`)

### 5.1 Abstract Tool Installer Interface (`BaseToolInstaller`)
```python
class BaseToolInstaller(ABC):
    @property
    @abstractmethod
    def tool_name(self) -> str:
        pass

    @property
    @abstractmethod
    def install_method(self) -> ToolInstallMethod:
        pass

    @abstractmethod
    async def get_info(self) -> ToolInstallationInfo:
        pass

    @abstractmethod
    async def install(
        self,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        force: bool = False,
    ) -> bool:
        pass
```

### 5.2 Installer Implementations by Tool Category

1. **`PipToolInstaller` (`sslyze`, `bandit`, `semgrep`, `checkov`, `prowler`, `schemathesis`):**
   - Invokes: `sys.executable -m pip install --upgrade <package_name>`
   - Bounded execution with thread-safe pipe streaming. Zero administrative elevation required.

2. **`GithubReleaseInstaller` (`nuclei`, `ffuf`, `gitleaks`, `trivy`, `subfinder`, `httpx`, `katana`, `syft`, `grype`, `osv_scanner`, `trufflehog`, `dockle`, `kube_bench`):**
   - Detects OS (`Windows`, `Linux`, `Darwin`) and CPU architecture (`amd64`, `arm64`).
   - Downloads official release zip/tarball from GitHub Releases API / CDN.
   - Extracts binary into `backend/bin/` with ZipSlip path traversal protection. Sets permissions `0o755`.

3. **`SystemToolHelper` (`nmap`, `retire`):**
   - Performs 5-tier binary discovery including Windows Registry uninstall scanning, multi-drive Program Files checks, and npm globals.
   - Integrates with `#tool-instructions-modal` presenting verified parameter breakdowns for `winget`, npm, apt, and brew.

**Applicable Target Types:** `URL`, `DOMAIN`, `IP`  
#### Submodules:
- `tls_auditor.py` (`NET-TLS-001` to `007`)
- `dns_hygiene.py` (`NET-DNS-001` to `008`)
- `port_checker.py` (`NET-PORT-001` to `003`)
- `banner_grabber.py` (`NET-SVC-001`)
- `subdomain_recon.py` (`NET-OSINT-001` to `002`)

### 3.2 Engine 2: Web Application, API DAST & Parameter Fuzzer (`web_dast`)
**Identifier:** `web_dast`  
**Display Name:** Web Application, API DAST & Parameter Fuzzer  
**Applicable Target Types:** `URL`, `DOMAIN`  
#### Submodules:
- `headers_cookies.py` (`DAST-HDR-001` to `005`, `DAST-AUTH-002`, `DAST-AUTH-004`)
- `cors_analyzer.py` (`DAST-CORS-001`)
- `api_inspector.py` (`DAST-EXP-001` to `005`)
- `browser_posture.py` (`DAST-CLNT-001` to `003`)
- `crawler.py` (Scoped BFS Crawler + Anti-CSRF Token Extraction)
- `auth_session.py` (Authenticated DAST Session + Form/Header/Cookie Auth)
- `parameter_fuzzer.py` (`DAST-INJ-001`, `DAST-XSS-001`, `DAST-LFI-001`, `DAST-SSTI-001`, `DAST-REDIR-001`)

### 3.3 Engine 3: Static Code Analysis, Secrets, AST Taint & SCA (`code_sast`)
**Identifier:** `code_sast`  
**Display Name:** Static Code Analysis, Secrets & Dependency SCA  
**Applicable Target Types:** `LOCAL_PATH`  
#### Submodules:
- `secret_scanner.py` (`SAST-SEC-001` to `003` with Shannon Entropy $\ge 4.5$)
- `crypto_lint.py` (`SAST-CRY-001` to `003`)
- `injection_lint.py` (`SAST-INJ-001` to `003`)
- `dependency_auditor.py` (`SAST-DEP-001` to `002`)
- `ast_taint_analyzer.py` (`SAST-TAINT-001` to `002` AST Dataflow Tracer)
- `git_history_scanner.py` (`SAST-SEC-004` Git Commit History Scanner)

### 3.4 Engine 4: Infrastructure-as-Code & Container Posture (`infra_iac`)
**Identifier:** `infra_iac`  
**Display Name:** Infrastructure-as-Code & Container Security  
**Applicable Target Types:** `DOCKERFILE`, `IAC_MANIFEST`, `LOCAL_PATH`  
#### Submodules:
- `dockerfile_auditor.py` (`IAC-DOCK-001` to `006`)
- `compose_auditor.py` (`IAC-CMP-001` to `003`)
- `k8s_manifest_auditor.py` (`IAC-K8S-001` to `004`)
- `terraform_auditor.py` (`IAC-TF-001` to `004`)

### 3.5 Engine 5: CI/CD Pipeline & Build Security (`cicd_audit`)
**Identifier:** `cicd_audit`  
**Display Name:** CI/CD Pipeline & Workflow Security  
**Applicable Target Types:** `LOCAL_PATH`  
#### Submodules:
- `github_actions_auditor.py` (`CICD-GHA-001` to `004`)

---

## 4. Adapters First-in-Line Plugin Architecture (`backend/app/adapters/`)

To combine enterprise-grade penetration testing power with zero-dependency portability, the platform defines the `BaseToolAdapter` interface powered by the central `resolve_tool_binary` discovery engine.

### 4.1 Abstract Tool Adapter Interface & Deterministic 5-Tier Binary Resolution
```python
from abc import ABC, abstractmethod
import os
from typing import Optional, List, Callable, Awaitable, Tuple
from app.core.models import Target, Finding, ScanConfig, LogLevel
from app.core.binary_resolver import resolve_tool_binary, safe_execute_subprocess

class BaseToolAdapter(ABC):
    """
    Abstract contract for external tool adapters across 21 modern enterprise tools:
    - Network / TLS: Nmap, SSLyze, Subfinder, Httpx
    - Web DAST: Nuclei, FFuF, Katana, Schemathesis
    - SAST / Secrets: Semgrep, Gitleaks, Bandit, TruffleHog, RetireJS
    - SCA / Supply Chain: Trivy, Syft, Grype, OSV-Scanner
    - Cloud / IaC / CIS: Checkov, Prowler, Kube-bench, Dockle
    """

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name of executable: 'nmap', 'sslyze', 'nuclei', 'ffuf', 'semgrep', 'gitleaks', 'bandit', 'trivy', 'checkov'."""
        pass

    def resolve_binary_path(self, custom_path: Optional[str] = None) -> Optional[str]:
        """
        Deterministic 5-Tier Binary Resolution Order:
        Tier 1: Explicit custom configured path (if file exists or resolves via PATH)
        Tier 2: In-App Managed Binaries directory ('backend/bin/<tool_name>[.exe|.bat|.cmd|.pl]')
        Tier 3: Active Python environment Scripts / bin directory (for pip-installed tools)
        Tier 4: System PATH discovery via shutil.which(tool_name)
        Tier 5: Platform-Specific Auto-Discovery:
                - Windows Registry: HKLM & HKCU Uninstall keys (detects Insecure.Nmap, MSI installers)
                - Windows Drive Scan: Program Files / Program Files (x86) / tools across all active drives (C:, D:, E:)
                - Windows Package Managers: Chocolatey, Scoop shims/apps, LocalAppData Programs
                - Unix / Linux / macOS: /usr/local/bin, /opt/homebrew/bin, /usr/bin, /snap/bin, ~/.local/bin
        """
        local_bin_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "bin"))
        return resolve_tool_binary(
            tool_name=self.tool_name,
            custom_path=custom_path,
            local_bin_dir=local_bin_dir,
        )

    async def is_available(self, custom_path: Optional[str] = None) -> bool:
        """Checks if tool executable is present and executable on host."""
        path = self.resolve_binary_path(custom_path)
        if not path:
            return False
        return os.path.isfile(path) or os.path.exists(path)

    @abstractmethod
    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        """Retrieves CLI tool version string (e.g. 'Nmap 7.94', 'nuclei v3.2.0')."""
        pass

    @abstractmethod
    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
    ) -> List[Finding]:
        """
        Executes CLI command asynchronously as primary first-in-line stage,
        parses stdout/JSON/XML, and normalizes findings into canonical Finding models.
        """
        pass

    async def execute_command(
        self,
        cmd: List[str],
        timeout: float = 60.0,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
        emit_log: Optional[Callable[[LogLevel, str], Awaitable[None]]] = None,
    ) -> Tuple[int, str, str]:
        """
        Safe loop-agnostic subprocess execution helper.
        Uses thread-isolated execution to eliminate NotImplementedError on Windows SelectorEventLoop,
        enforce strict 60s timeouts, and guarantee zero unhandled exception leakage.
        """
        return await safe_execute_subprocess(cmd=cmd, timeout=timeout, cwd=cwd, env=env)
```

### 4.2 Adapter Specifications, Priority & Fallback Mapping

| Tool Adapter | Binary | Execution Command | Output Format | Priority & Execution Role | Resilient Native Fallback | Finding Normalization |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`NmapAdapter`** | `nmap` | `nmap -sV -sC --version-light -T4 -oX - <target>` | XML (`-oX -`) | **Primary** Network & Port Scanner | `port_checker.py` + `banner_grabber.py` | Maps open ports, daemon versions, and NSE script output into `NET-PORT-xxx` and `NET-SVC-001`. `source_tool="nmap"`. |
| **`SslyzeAdapter`** | `sslyze` | `sslyze --json_out=- <host>:<port>` | JSON (`--json_out=-`) | **Primary** Deep TLS/SSL Auditor | `tls_auditor.py` | Maps deprecated TLS protocols, weak ciphers, and cert issues to `NET-TLS-xxx`. `source_tool="sslyze"`. |
| **`NucleiAdapter`** | `nuclei` | `nuclei -u <target> -j -silent -tags cve,misconfig` | JSON Lines (`-j`) | **Primary** DAST Vulnerability Engine | `parameter_fuzzer.py` + `headers_cookies.py` | Maps Nuclei template IDs and severity to canonical CWEs and `DAST-xxx`. `source_tool="nuclei"`. |
| **`FfufAdapter`** | `ffuf` | `ffuf -u <target>/FUZZ -w <wordlist> -mc 200,204,301,302,307,401,403 -o - -of json -t 5 -rate 10` | JSON (`-of json`) | **Primary** Endpoint & Content Discovery | `crawler.py` | Discovers hidden routes, backup files, and endpoints, emitting `DAST-EXP-xxx` findings and `DiscoveredEndpoint` models. `source_tool="ffuf"`. |
| **`SemgrepAdapter`** | `semgrep` | `semgrep scan --config auto --json <dir>` | JSON (`--json`) | **Primary** Multi-Language AST SAST | `injection_lint.py` + `crypto_lint.py` | Normalizes Semgrep rules into `SAST-xxx` with line numbers and evidence diffs. `source_tool="semgrep"`. |
| **`GitleaksAdapter`** | `gitleaks` | `gitleaks detect --source <dir> --report-format json --report-path -` | JSON (`--report-format json`) | **Primary** Dedicated Git Secret Scanner | `secret_scanner.py` + `git_history_scanner.py` | Extracts hardcoded tokens, private keys, and API secrets with mandatory masking to `SAST-SEC-xxx`. `source_tool="gitleaks"`. |
| **`BanditAdapter`** | `bandit` | `bandit -r <dir> -f json` | JSON (`-f json`) | **Primary** Python AST Security Linter | `crypto_lint.py` + `injection_lint.py` | Maps high/medium confidence AST flaws to `SAST-CRY-xxx` and `SAST-INJ-xxx`. `source_tool="bandit"`. |
| **`TrivyAdapter`** | `trivy` | `trivy fs --format json <dir>` | JSON (`--format json`) | **Primary** SCA & Container Vulnerability Engine | `dependency_auditor.py` + `dockerfile_auditor.py` | Maps package and container vulnerabilities to `SAST-DEP-001` and `IAC-DOCK-xxx`. `source_tool="trivy"`. |
| **`CheckovAdapter`** | `checkov` | `checkov -d <dir> -o json --compact` | JSON (`-o json`) | **Primary** Infrastructure-as-Code Policy Engine | `compose_auditor.py` + `k8s_manifest_auditor.py` + `terraform_auditor.py` | Maps failed IaC checks (Terraform, K8s, Compose) to `IAC-TF-xxx`, `IAC-K8S-xxx`, `IAC-CMP-xxx`. `source_tool="checkov"`. |

---

## 5. In-App Tool Installers Engine (`backend/app/installers/`)

The platform includes a dedicated, pluggable tool installer architecture for 1-click in-app installation.

### 5.1 Abstract Tool Installer Interface (`BaseToolInstaller`)
```python
from abc import ABC, abstractmethod
from typing import Callable, Awaitable, Optional
from app.core.models import ToolInstallMethod, ToolInstallationInfo, ToolInstallStatus

LogCallback = Callable[[str], Awaitable[None]]
ProgressCallback = Callable[[int, str], Awaitable[None]]

class BaseToolInstaller(ABC):
    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name identifier of the tool."""
        pass

    @property
    @abstractmethod
    def install_method(self) -> ToolInstallMethod:
        """Installation method (PIP, STANDALONE_BINARY, SYSTEM_PACKAGE_MANAGER)."""
        pass

    @abstractmethod
    async def get_info(self) -> ToolInstallationInfo:
        """Returns comprehensive installation status, version, and instructions."""
        pass

    @abstractmethod
    async def install(
        self,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        force: bool = False,
    ) -> bool:
        """Asynchronously executes installation with real-time log and progress callbacks."""
        pass
```

### 5.2 Installer Implementations by Tool Category

1. **`PipToolInstaller` (`sslyze`, `bandit`, `semgrep`, `checkov`):**
   - Invokes: `sys.executable -m pip install --upgrade <package_name>`
   - Bounded execution with real-time pipe streaming.
   - Zero administrative elevation required.

2. **`GithubReleaseInstaller` (`nuclei`, `ffuf`, `gitleaks`, `trivy`):**
   - Automatically detects OS (`Windows`, `Linux`, `Darwin`) and CPU architecture (`amd64`, `arm64`).
   - Downloads official release zip/tarball from GitHub API / CDN.
   - Extracts binary into `backend/bin/` with ZipSlip path traversal protection.
   - Sets executable permissions (`0o755`).
   - Zero administrative elevation required.

3. **`SystemToolHelper` (`nmap`, `retire`):**
   - Detects OS platform and performs 5-tier binary discovery including Windows Registry uninstall scanning and multi-drive Program Files checks.
   - **System Tool Health & Version Verification Gate:** Requires execution of the tool's version command returning exit code `0` and non-error output.
   - **In-App Interactive Setup Guidance:** Integrates with `#tool-instructions-modal` in the frontend HUD to present prioritized, copyable CLI snippets with parameter breakdowns for `winget`, official installer, npm, apt, and brew.

