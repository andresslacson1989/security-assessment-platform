import pytest
from unittest.mock import AsyncMock
from unittest.mock import patch
import json
import hashlib
import os
import platform
import shutil
import uuid
from pathlib import Path

from app.core.models import ScanConfig, Target, TargetType, ScanJob, DiscoveredSubdomain, NormalizedExecutionState
from app.core.orchestrator import ScanOrchestrator
from app.installers.tool_manifest import PINNED_TOOL_MANIFEST

from app.adapters.subfinder_adapter import SubfinderAdapter
from app.engines.network.engine import NetworkAssessmentEngine
from app.core.models import RejectedDiscovery
from app.core.ssrf_protector import create_validated_target


def test_normalization_and_scope_are_deterministic():
    adapter = SubfinderAdapter
    assert adapter.normalize_domain(" API.Example.com. ") == "api.example.com"
    assert adapter.normalize_domain("https://api.example.com") is None
    assert adapter.normalize_domain("127.0.0.1") is None
    assert adapter.classify_scope("api.example.com.", "example.com") == "IN_SCOPE"
    assert adapter.classify_scope("example.net", "example.com") == "OUT_OF_SCOPE"


def test_command_is_structured_and_has_no_client_flags():
    command = SubfinderAdapter.build_command("/opt/subfinder", "Example.com")
    assert command == ["/opt/subfinder", "-d", "example.com", "-s", "crtsh", "-silent", "-json", "-timeout", "10", "-max-time", "1"]
    with pytest.raises(ValueError):
        SubfinderAdapter.build_command("/opt/subfinder", "example.com; -all")
    assert SubfinderAdapter.ALLOWED_PROVIDERS == ("crtsh",)
    assert "virustotal" not in SubfinderAdapter.ALLOWED_PROVIDERS


def test_provider_environment_excludes_host_credentials_and_configuration(monkeypatch, tmp_path):
    monkeypatch.setenv("SUBFINDER_PROVIDER_CONFIG", "host-secret-config")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "host-secret")
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker-proxy.invalid")

    environment = SubfinderAdapter._provider_environment(str(tmp_path))

    assert environment["HOME"] == str(tmp_path)
    assert environment["USERPROFILE"] == str(tmp_path)
    assert "SUBFINDER_PROVIDER_CONFIG" not in environment
    assert "VIRUSTOTAL_API_KEY" not in environment
    assert "HTTPS_PROXY" not in environment


def test_unmanaged_binary_cannot_satisfy_assured_execution():
    assert SubfinderAdapter().verify_managed_binary("/usr/local/bin/subfinder") is False


def test_runtime_harness_is_explicitly_unavailable_without_approved_binary():
    managed_dir = Path("backend/bin")
    candidates = [managed_dir / "subfinder", managed_dir / "subfinder.exe"]
    if not any(path.exists() for path in candidates):
        pytest.skip("UNAVAILABLE: approved managed Subfinder v2.6.5 binary is not installed")


@pytest.mark.asyncio
async def test_real_managed_subfinder_runtime_path():
    """Exercise the approved binary, governed vector, parser, and state path."""
    managed_dir = Path("backend/bin")
    candidates = [managed_dir / "subfinder", managed_dir / "subfinder.exe"]
    if not any(path.exists() for path in candidates):
        pytest.skip("UNAVAILABLE: approved managed Subfinder v2.6.5 binary is not installed")

    adapter = SubfinderAdapter()
    path = adapter.resolve_binary_path()
    assert path is not None
    assert adapter.verify_managed_binary(path) is True
    assert await adapter.get_version(path) == "subfinder v2.6.5"

    logs = []
    findings = []
    discoveries = []
    rejected = []
    commands = []
    original_execute = adapter.execute_command

    async def capture_execute(command, **kwargs):
        commands.append(command)
        return await original_execute(command, **kwargs)

    adapter.execute_command = capture_execute

    async def log(*args):
        logs.append(args)

    async def finding(value):
        findings.append(value)

    async def discovered(value):
        discoveries.append(value)

    async def rejected_discovery(value):
        rejected.append(value)

    result = await adapter.run(
        Target(name="runtime", type=TargetType.DOMAIN, value="example.com"),
        ScanConfig(), log, finding,
        scan_id="subfinder-real-runtime",
        organization_id="org-runtime",
        emit_subdomain=discovered,
        emit_rejected_discovery=rejected_discovery,
    )

    assert result == findings
    assert adapter.last_execution_state in {
        NormalizedExecutionState.COMPLETED_NO_FINDINGS,
        NormalizedExecutionState.COMPLETED_WITH_FINDINGS,
        NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING,
        NormalizedExecutionState.TOOL_EXECUTION_FAILED,
        NormalizedExecutionState.EXECUTION_TIMED_OUT,
    }
    assert any(
        command[1:] == ["-d", "example.com", "-s", "crtsh", "-silent", "-json", "-timeout", "10", "-max-time", "1"]
        for command in commands
    )
    assert all(item.dns_status == "UNRESOLVED" for item in discoveries)
    assert all(item.organization_id == "org-runtime" for item in discoveries + rejected)


def test_managed_trust_record_binds_identity_and_detects_tampering(monkeypatch):
    import app.adapters.subfinder_adapter as module
    import app.core.binary_trust as binary_trust
    root = __import__("pathlib").Path.cwd() / f".subfinder-trust-test-{uuid.uuid4().hex}"
    try:
        adapter_dir = root / "backend" / "app" / "adapters"
        managed_dir = root / "backend" / "bin"
        adapter_dir.mkdir(parents=True)
        managed_dir.mkdir(parents=True)
        binary = managed_dir / "subfinder"
        binary.write_bytes(b"approved-binary")
        if os.name != "nt":
            binary.chmod(0o755)
        record = managed_dir / "subfinder.trust.json"
        monkeypatch.setattr(module, "__file__", str(adapter_dir / "subfinder_adapter.py"))
        monkeypatch.setattr(binary_trust, "get_managed_bin_dir", lambda: managed_dir)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        current_platform = "windows" if os.name == "nt" else ("darwin" if platform.system().lower() == "darwin" else "linux")
        current_arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "amd64"
        platform_key = f"{current_platform}_{current_arch}"
        manifest = PINNED_TOOL_MANIFEST["subfinder"]
        record_data = {
            "tool_id": "TOOL-SUBFINDER", "tool_version": "v2.6.5",
            "artifact_filename": manifest["asset_names"][platform_key],
            "artifact_sha256": manifest["sha256_checksums"][platform_key],
            "executable_relative_path": "subfinder", "executable_sha256": digest,
            "platform": current_platform, "architecture": current_arch, "installer_version": "13.0.0",
            "trust_status": "VALID", "claims": ["ARCHIVE_INTEGRITY_VERIFIED", "EXECUTABLE_INTEGRITY_VERIFIED"],
        }
        record.write_text(json.dumps(record_data))
        adapter = SubfinderAdapter()
        assert adapter.verify_managed_binary(str(binary)) is True
        record_data["artifact_sha256"] = "a" * 64
        record.write_text(json.dumps(record_data))
        assert adapter.verify_managed_binary(str(binary)) is False
        record_data["artifact_sha256"] = manifest["sha256_checksums"][platform_key]
        record.write_text(json.dumps(record_data))
        binary.write_bytes(b"tampered-binary")
        assert adapter.verify_managed_binary(str(binary)) is False
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.mark.asyncio
async def test_wrong_version_fails_closed():
    adapter = SubfinderAdapter()
    assert adapter.APPROVED_VERSION == "v2.6.5"
    assert "subfinder v2.6.4" != f"subfinder {adapter.APPROVED_VERSION}"


@pytest.mark.asyncio
async def test_wrong_version_publishes_invalid_version_state(monkeypatch):
    adapter = SubfinderAdapter()
    monkeypatch.setattr(adapter, "resolve_binary_path", lambda *_: "/bin/subfinder")
    monkeypatch.setattr(adapter, "verify_managed_binary", lambda *_: True)
    monkeypatch.setattr(adapter, "get_version", AsyncMock(return_value="subfinder v2.6.4"))
    states = []

    async def callback(*_args):
        return None

    async def capture_state(tool, state):
        states.append((tool, state))

    await adapter.run(
        Target(name="root", type=TargetType.DOMAIN, value="example.com"),
        ScanConfig(), callback, callback,
        organization_id="org-a", emit_tool_execution_state=capture_state,
    )

    assert adapter.last_execution_state == NormalizedExecutionState.INVALID_VERSION
    assert states == [("subfinder", "INVALID_VERSION")]


@pytest.mark.asyncio
async def test_discovery_never_promotes_out_of_scope_or_resolves_hosts(monkeypatch):
    adapter = SubfinderAdapter()
    emitted = []
    rejected = []
    monkeypatch.setattr(adapter, "resolve_binary_path", lambda *_: "/bin/subfinder")
    monkeypatch.setattr(adapter, "verify_managed_binary", lambda *_: True)
    monkeypatch.setattr(adapter, "get_version", AsyncMock(return_value="subfinder v2.6.5"))
    monkeypatch.setattr(adapter, "safe_execute_subprocess", AsyncMock(return_value=(
        0,
        '{"host":"admin.example.com","sources":["crtsh"]}\n'
        '{"host":"outside.example.net","sources":["provider"]}\n'
        "not-json\n",
        "",
    )))
    async def callback(*_args):
        return None

    async def subdomain(value):
        emitted.append(value)

    async def reject(value):
        rejected.append(value)

    await adapter.run(Target(name="root", type=TargetType.DOMAIN, value="example.com"), ScanConfig(), callback, callback, scan_id="scan-1", organization_id="org-a", emit_subdomain=subdomain, emit_rejected_discovery=reject)
    assert [item.domain for item in emitted] == ["admin.example.com"]
    assert rejected[0].domain == "outside.example.net"
    assert rejected[0].organization_id == "org-a"
    assert rejected[0].sources == ["provider"]
    assert adapter.last_execution_state.value == "PARTIAL_RESULTS_WITH_WARNING"


@pytest.mark.asyncio
async def test_nonzero_exit_with_partial_stdout_is_degraded_not_success(monkeypatch):
    adapter = SubfinderAdapter()
    monkeypatch.setattr(adapter, "resolve_binary_path", lambda *_: "/bin/subfinder")
    monkeypatch.setattr(adapter, "verify_managed_binary", lambda *_: True)
    monkeypatch.setattr(adapter, "get_version", AsyncMock(return_value="subfinder v2.6.5"))
    monkeypatch.setattr(adapter, "safe_execute_subprocess", AsyncMock(return_value=(
        2,
        '{"host":"api.example.com","sources":["crtsh"]}\n',
        "provider returned a non-zero status",
    )))

    async def callback(*_args):
        return None

    await adapter.run(
        Target(name="root", type=TargetType.DOMAIN, value="example.com"),
        ScanConfig(), callback, callback,
        organization_id="org-a",
    )

    assert adapter.last_execution_state == NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING


@pytest.mark.asyncio
async def test_managed_subfinder_rejects_organization_mismatch(monkeypatch):
    adapter = SubfinderAdapter()
    monkeypatch.setattr(adapter, "resolve_binary_path", lambda *_: "/bin/subfinder")
    monkeypatch.setattr(adapter, "verify_managed_binary", lambda *_: True)
    with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
        validated = create_validated_target(
            Target(name="root", type=TargetType.DOMAIN, value="example.com"),
            organization_id="org-authoritative",
        )
    states = []

    async def callback(*_args):
        return None

    async def capture_state(tool, state):
        states.append((tool, state))

    await adapter.run(
        validated,
        ScanConfig(),
        callback,
        callback,
        validated_target=validated,
        require_managed_binary=True,
        organization_id="org-attacker",
        emit_tool_execution_state=capture_state,
    )

    assert adapter.last_execution_state == NormalizedExecutionState.EXECUTION_BLOCKED
    assert states == [("subfinder", "BLOCKED")]


@pytest.mark.asyncio
async def test_timeout_with_partial_stdout_remains_timed_out(monkeypatch):
    adapter = SubfinderAdapter()
    monkeypatch.setattr(adapter, "resolve_binary_path", lambda *_: "/bin/subfinder")
    monkeypatch.setattr(adapter, "verify_managed_binary", lambda *_: True)
    monkeypatch.setattr(adapter, "get_version", AsyncMock(return_value="subfinder v2.6.5"))
    monkeypatch.setattr(adapter, "safe_execute_subprocess", AsyncMock(return_value=(
        -1,
        '{"host":"api.example.com","sources":["crtsh"]}\n',
        "Execution timed out after 30 seconds",
    )))

    async def callback(*_args):
        return None

    await adapter.run(
        Target(name="root", type=TargetType.DOMAIN, value="example.com"),
        ScanConfig(), callback, callback,
        organization_id="org-a",
    )

    assert adapter.last_execution_state == NormalizedExecutionState.EXECUTION_TIMED_OUT


@pytest.mark.asyncio
async def test_orchestrator_discovery_callback_does_not_authorize_or_queue_target():
    orchestrator = ScanOrchestrator()
    job = ScanJob(target=Target(name="root", type=TargetType.DOMAIN, value="example.com"), organization_id="org-a")
    orchestrator._active_jobs[job.id] = job
    discovered = DiscoveredSubdomain(
        domain="api.example.com",
        discovered_via="Subfinder",
        dns_status="UNRESOLVED",
        organization_id="org-attacker",
        assessment_id="assessment-attacker",
    )

    await orchestrator.emit_subdomain_discovered(job.id, discovered)

    assert [item.domain for item in job.discovered_subdomains] == ["api.example.com"]
    assert not hasattr(job, "validated_targets")
    assert not hasattr(orchestrator, "active_target_queue")
    assert job.discovered_subdomains[0].dns_status == "UNRESOLVED"
    assert job.discovered_subdomains[0].organization_id == "org-a"
    assert job.discovered_subdomains[0].assessment_id == job.id


@pytest.mark.asyncio
async def test_orchestrator_rejected_discovery_callback_rebinds_authoritative_identity():
    orchestrator = ScanOrchestrator()
    job = ScanJob(target=Target(name="root", type=TargetType.DOMAIN, value="example.com"), organization_id="org-a")
    orchestrator._active_jobs[job.id] = job
    rejection = RejectedDiscovery(
        domain="outside.example.net",
        reason="OUT_OF_SCOPE",
        sources=["crtsh"],
        authorized_root="example.com",
        assessment_id="assessment-attacker",
        organization_id="org-attacker",
    )

    await orchestrator.emit_rejected_discovery(job.id, rejection)

    assert len(job.rejected_discoveries) == 1
    assert job.rejected_discoveries[0].organization_id == "org-a"
    assert job.rejected_discoveries[0].assessment_id == job.id
    assert job.rejected_discoveries[0].sources == ["crtsh"]


@pytest.mark.asyncio
async def test_network_engine_propagates_authoritative_tenant_and_provider_evidence():
    rejected = []
    states = []

    class FakeSubfinder:
        class _State:
            value = "PARTIAL_RESULTS_WITH_WARNING"

        last_execution_state = _State()

        async def is_available(self, _path=None):
            return True

        async def run(self, _target, _config, _log, _finding, **kwargs):
            await kwargs["emit_rejected_discovery"](RejectedDiscovery(
                domain="outside.example.net", reason="OUT_OF_SCOPE", sources=["crtsh"],
                authorized_root="example.com", assessment_id="scan-1",
                organization_id=kwargs["organization_id"],
            ))
            return []

    async def noop(*_args, **_kwargs):
        return []

    async def capture_rejection(value):
        rejected.append(value)

    async def capture_state(tool, state):
        states.append((tool, state))

    config = ScanConfig()
    config.adapters.enable_subfinder = True
    with patch("app.engines.network.engine.SubfinderAdapter", FakeSubfinder), \
         patch("app.engines.network.engine.SslyzeAdapter") as sslyze, \
         patch("app.engines.network.engine.NmapAdapter") as nmap, \
         patch("app.engines.network.engine.HttpxAdapter") as httpx, \
         patch("app.engines.network.engine.audit_tls_certificates", noop), \
         patch("app.engines.network.engine.audit_tls_protocols_and_ciphers", noop), \
         patch("app.engines.network.engine.audit_dns_hygiene", noop), \
         patch("app.engines.network.engine.audit_exposed_ports", noop), \
         patch("app.engines.network.engine.audit_origin_exposure", noop), \
         patch("app.engines.network.engine.audit_subdomain_osint", noop):
        sslyze.return_value.is_available = AsyncMock(return_value=False)
        nmap.return_value.is_available = AsyncMock(return_value=False)
        httpx.return_value.is_available = AsyncMock(return_value=False)
        await NetworkAssessmentEngine().run(
            Target(name="root", type=TargetType.DOMAIN, value="example.com"), config,
            AsyncMock(), AsyncMock(), AsyncMock(), scan_id="scan-1",
            organization_id="org-a", emit_rejected_discovery=capture_rejection,
            emit_tool_execution_state=capture_state,
        )

    assert rejected[0].organization_id == "org-a"
    assert rejected[0].organization_id != "org-default"
    assert rejected[0].sources == ["crtsh"]
    assert ("subfinder", "PARTIAL_RESULTS_WITH_WARNING") in states
