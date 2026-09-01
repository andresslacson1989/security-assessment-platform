# Contract 03: Engine Plugin Interface, Execution Governance & Tool Supply Chain Contract

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 13.0.0 (Execution Plane Governance, Pinned Supply Chain, Quarantine Pipeline, ProcessSupervisor Tree Termination & Sandbox Isolation)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Engine Interfaces, Tool Adapters, Binary Supply Chain Verification, Quarantine Lifecycle & Worker Sandbox Controls  

---

## 1. Engine & Tool Adapter Abstraction

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
```

---

## 2. Tool Supply Chain Security & Verification Pipeline

All external tools downloaded by the platform MUST follow an unyielding cryptographic verification pipeline. Unpinned or unverifiable tools are strictly prohibited in production.

### 2.1 Manifest Requirements & Registry Parity
Every tool manifest entry MUST define:
- `tool_name`: Canonical identifier (e.g., `nuclei`, `trivy`, `semgrep`).
- `version`: Exact pinned semver release (e.g., `v3.2.0`).
- `release_tag`: Exact immutable GitHub release tag (`/releases/tags/{version}`).
- `platform`: `windows`, `linux`, `darwin`.
- `architecture`: `amd64`, `arm64`.
- `asset_name`: Exact archive filename.
- `sha256`: Authentic 64-character lowercase hexadecimal cryptographic SHA-256 checksum.

**Registry Parity Invariant:**
$$\text{Tool Registry} \equiv \text{Installer Registry} \equiv \text{Integrity Manifest} \equiv \text{Supported 21 Tools}$$
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
- **Approved source-build exception:** Trivy `v0.50.0` may use `SOURCE_BUILD_MODE` because its upstream source
  tag exists while its release binary assets are unavailable. The build MUST use the source archive and Go
  toolchain declared in Contract 09, `go mod download` with the committed `go.sum`, reproducible build flags,
  and a generated executable trust record. Exact runtime version and pre-launch integrity verification remain
  mandatory; release-binary provenance is not claimed.
- **Atomic Replacement:** Production executables are never overwritten in-place during download; promotion occurs only after 100% verification passes.

---

## 3. Worker Execution Sandboxing & Central Process Supervisor

External tool subprocesses must be executed and governed exclusively through the central `ProcessSupervisor`:

1. **`ProcessSupervisor` Responsibilities:**
   - Spawns child processes in isolated process groups (`creationflags=CREATE_NEW_PROCESS_GROUP` on Windows, `start_new_session=True` on POSIX).
   - Tracks active process trees (parent, children, grandchildren).
   - Enforces execution timeouts (`60.0s` default per tool).
   - Enforces maximum output buffers (10 MB) to prevent buffer exhaustion.
   - On cancellation or timeout: recursively terminates the entire process tree without leaving orphaned zombie processes.
2. **Process Tree Cancellation Protocol:**
   - On Windows: `taskkill /F /T /PID <pid>` or Win32 Job Object tree termination.
   - On POSIX: Process group termination (`os.killpg(os.getpgid(proc.pid), signal.SIGKILL)`).
3. **Workspace Confinement:** All tool file operations must execute strictly within the server-derived workspace directory.
```
