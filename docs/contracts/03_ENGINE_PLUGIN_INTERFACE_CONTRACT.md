# Contract 03: Engine Plugin Interface & Module Implementation Contract

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 6.0.0 (In-App Tool Installation & Capabilities Lifecycle Management Architecture Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Assessment Engine Plugins, Submodules, Tool Adapters, In-App Installers & Execution Lifecycle  

---

## 1. Abstract Engine Interface (`BaseAssessmentEngine`)

Every assessment engine MUST subclass `BaseAssessmentEngine` defined in `backend/app/engines/base.py` and implement all abstract properties and methods.

```python
from abc import ABC, abstractmethod
from typing import List, Callable, Awaitable, Optional
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

### 3.1 Engine 1: Network, TLS, DNS & OSINT Auditor (`network`)
**Identifier:** `network`  
**Display Name:** Network Perimeter, TLS/SSL & DNS Infrastructure  
**Applicable Target Types:** `URL`, `DOMAIN`, `IP`  
#### Submodules:
- `tls_auditor.py` (`NET-TLS-001` to `006`)
- `dns_hygiene.py` (`NET-DNS-001` to `005`)
- `port_checker.py` (`NET-PORT-001` to `003`)
- `banner_grabber.py` (`NET-SVC-001`)
- `subdomain_recon.py` (`NET-OSINT-001` to `002`)

### 3.2 Engine 2: Web Application DAST & Fuzzing (`web_dast`)
**Identifier:** `web_dast`  
**Display Name:** Web Application DAST & Active Fuzzer  
**Applicable Target Types:** `URL`, `DOMAIN`  
#### Submodules:
- `headers_cookies.py` (`DAST-HDR-001` to `005`, `DAST-CKI-001` to `003`)
- `cors_analyzer.py` (`DAST-CORS-001` to `002`)
- `api_inspector.py` (`DAST-API-001` to `003`)
- `browser_posture.py` (`DAST-SRI-001`, `DAST-METH-001`)
- `graphql_auditor.py` (`DAST-GQL-001` to `002`)
- `crawler.py` (Multi-page BFS link and form discovery)
- `auth_session.py` (`DAST-AUTH-001` to `004`, `DAST-FORM-001` to `002`)
- `parameter_fuzzer.py` (`DAST-INJ-001`, `DAST-XSS-001`, `DAST-LFI-001`, `DAST-SSTI-001`, `DAST-REDIR-001`)

### 3.3 Engine 3: Static Code Analysis & Secrets (`code_sast`)
**Identifier:** `code_sast`  
**Display Name:** Static Code Analysis & Secret Scanner  
**Applicable Target Types:** `LOCAL_PATH`  
#### Submodules:
- `secret_scanner.py` (`SAST-SEC-001` to `009`)
- `crypto_lint.py` (`SAST-CRY-001` to `003`)
- `injection_lint.py` (`SAST-INJ-001` to `003`)
- `dependency_auditor.py` (`SAST-DEP-001`)
- `ast_taint_analyzer.py` (`SAST-TAINT-001` to `002`)
- `git_history_scanner.py` (`SAST-GIT-001`)

### 3.4 Engine 4: Infrastructure-as-Code & Containers (`infra_iac`)
**Identifier:** `infra_iac`  
**Display Name:** Infrastructure-as-Code & Container Posture  
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

To combine enterprise-grade penetration testing power with zero-dependency portability, the platform defines the `BaseToolAdapter` interface.

### 4.1 Abstract Tool Adapter Interface & Binary Resolution Order
```python
from abc import ABC, abstractmethod
import os
import shutil
from typing import Optional, List, Callable, Awaitable
from app.core.models import Target, Finding, ScanConfig, LogLevel

class BaseToolAdapter(ABC):
    """
    Abstract contract for external tool adapters.
    Supported enterprise tools:
    - Network / TLS: Nmap, SSLyze
    - Web DAST: Nuclei, FFuF, Nikto
    - SAST / Secrets: Semgrep, Gitleaks, Bandit
    - SCA / IaC: Trivy, Checkov
    """

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name of executable: 'nmap', 'sslyze', 'nuclei', 'ffuf', 'nikto', 'semgrep', 'gitleaks', 'bandit', 'trivy', 'checkov'."""
        pass

    def resolve_binary_path(self, custom_path: Optional[str] = None) -> Optional[str]:
        """
        Deterministic 3-Tier Binary Resolution Order:
        Tier 1: Explicit custom configured path (if file exists and is executable)
        Tier 2: In-App Managed Binaries directory ('backend/bin/<tool_name>[.exe]')
        Tier 3: System PATH discovery via shutil.which(tool_name)
        """
        if custom_path and os.path.isfile(custom_path) and os.access(custom_path, os.X_OK):
            return custom_path
        
        # Check local managed backend/bin directory
        local_bin_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "bin"))
        exts = [".exe", ""] if os.name == "nt" else ["", ".exe"]
        for ext in exts:
            candidate = os.path.join(local_bin_dir, f"{self.tool_name}{ext}")
            if os.path.isfile(candidate):
                return candidate

        return shutil.which(self.tool_name)

    @abstractmethod
    async def is_available(self, custom_path: Optional[str] = None) -> bool:
        """Checks if tool executable is present and executable."""
        pass

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
```

### 4.2 Adapter Specifications, Priority & Fallback Mapping

| Tool Adapter | Binary | Execution Command | Output Format | Priority & Execution Role | Resilient Native Fallback | Finding Normalization |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`NmapAdapter`** | `nmap` | `nmap -sV -sC --version-light -T4 -oX - <target>` | XML (`-oX -`) | **Primary** Network & Port Scanner | `port_checker.py` + `banner_grabber.py` | Maps open ports, daemon versions, and NSE script output into `NET-PORT-xxx` and `NET-SVC-001`. `source_tool="nmap"`. |
| **`SslyzeAdapter`** | `sslyze` | `sslyze --json_out=- <host>:<port>` | JSON (`--json_out=-`) | **Primary** Deep TLS/SSL Auditor | `tls_auditor.py` | Maps deprecated TLS protocols, weak ciphers, and cert issues to `NET-TLS-xxx`. `source_tool="sslyze"`. |
| **`NucleiAdapter`** | `nuclei` | `nuclei -u <target> -j -silent -tags cve,misconfig` | JSON Lines (`-j`) | **Primary** DAST Vulnerability Engine | `parameter_fuzzer.py` + `headers_cookies.py` | Maps Nuclei template IDs and severity to canonical CWEs and `DAST-xxx`. `source_tool="nuclei"`. |
| **`FfufAdapter`** | `ffuf` | `ffuf -u <target>/FUZZ -w <wordlist> -mc 200,204,301,302,307,401,403 -o - -of json -t 5 -rate 10` | JSON (`-of json`) | **Primary** Endpoint & Content Discovery | `crawler.py` | Discovers hidden routes, backup files, and endpoints, emitting `DAST-EXP-xxx` findings and `DiscoveredEndpoint` models. `source_tool="ffuf"`. |
| **`NiktoAdapter`** | `nikto` | `nikto -h <target> -Format json -output - -Tuning 1,2,3,4,8,9,a,b,c` | JSON (`-Format json`) | **Primary** Server Misconfiguration Scanner | `headers_cookies.py` + `api_inspector.py` | Maps outdated server components, dangerous HTTP methods, and insecure headers to `DAST-HDR-xxx` / `DAST-EXP-xxx`. `source_tool="nikto"`. |
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

3. **`SystemToolHelper` (`nmap`, `nikto`):**
   - Detects OS platform.
   - For Windows: Generates `winget install Insecure.Nmap` or launches official installer.
   - For Linux: Generates `sudo apt-get install nmap nikto` command snippets.
   - For macOS: Generates `brew install nmap nikto` command snippets.
