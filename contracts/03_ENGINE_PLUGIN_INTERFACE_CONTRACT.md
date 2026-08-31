# Contract 03: Engine Plugin Interface, Execution Governance & Tool Supply Chain Contract

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 10.0.0 (Execution Plane Governance, Pinned Supply Chain, Quarantine Pipeline, Process Tree Termination & Sandbox Isolation)  
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

### 2.1 Manifest Requirements
Every tool manifest entry MUST define:
- `tool_name`: Canonical identifier (e.g., `nuclei`, `trivy`, `semgrep`).
- `version`: Exact pinned semver release (e.g., `v3.2.0`).
- `release_tag`: Exact immutable GitHub release tag.
- `platform`: `windows`, `linux`, `darwin`.
- `architecture`: `amd64`, `arm64`.
- `asset_name`: Exact archive filename.
- `sha256`: Authentic 64-character lowercase hexadecimal cryptographic SHA-256 checksum.

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
- **Atomic Replacement:** Production executables are never overwritten in-place during download; promotion occurs only after 100% verification passes.

---

## 3. Worker Execution Sandboxing & Process Governance

1. **Subprocess Confinement:** Tool subprocesses execute with lowest feasible privileges, non-interactive streams, and sandboxed temporary directories.
2. **Process Tree Cancellation:** Cancellation or timeout triggers forceful process tree termination:
   - On Windows: `taskkill /F /T /PID <pid>` or `TerminateProcess`.
   - On POSIX: Process group termination (`os.killpg(os.getpgid(proc.pid), signal.SIGKILL)`).
3. **Execution Timeouts:** Every external adapter execution has an enforced non-blocking timeout (`60.0s` default).
4. **Output Quotas:** Subprocess standard output and error streams are capped to prevent memory exhaustion (maximum 10 MB buffer per execution).
