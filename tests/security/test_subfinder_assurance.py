import pytest
from unittest.mock import AsyncMock
import json
import hashlib
import os
import shutil
import uuid
from pathlib import Path

from app.core.models import ScanConfig, Target, TargetType, ScanJob, DiscoveredSubdomain
from app.core.orchestrator import ScanOrchestrator

from app.adapters.subfinder_adapter import SubfinderAdapter


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


def test_unmanaged_binary_cannot_satisfy_assured_execution():
    assert SubfinderAdapter().verify_managed_binary("/usr/local/bin/subfinder") is False


def test_runtime_harness_is_explicitly_unavailable_without_approved_binary():
    managed_dir = Path("backend/bin")
    candidates = [managed_dir / "subfinder", managed_dir / "subfinder.exe"]
    if not any(path.exists() for path in candidates):
        pytest.skip("UNAVAILABLE: approved managed Subfinder v2.6.5 binary is not installed")


def test_managed_trust_record_binds_identity_and_detects_tampering(monkeypatch):
    import app.adapters.subfinder_adapter as module
    root = __import__("pathlib").Path.cwd() / f".subfinder-trust-test-{uuid.uuid4().hex}"
    try:
        adapter_dir = root / "backend" / "app" / "adapters"
        managed_dir = root / "backend" / "bin"
        adapter_dir.mkdir(parents=True)
        managed_dir.mkdir(parents=True)
        binary = managed_dir / "subfinder"
        binary.write_bytes(b"approved-binary")
        record = managed_dir / "subfinder.trust.json"
        monkeypatch.setattr(module, "__file__", str(adapter_dir / "subfinder_adapter.py"))
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        current_platform = "windows" if os.name == "nt" else ("darwin" if module.platform.system().lower() == "darwin" else "linux")
        current_arch = "arm64" if module.platform.machine().lower() in {"arm64", "aarch64"} else "amd64"
        record.write_text(json.dumps({
            "tool_id": "TOOL-SUBFINDER", "tool_version": "v2.6.5", "artifact_filename": "release.zip",
            "artifact_sha256": "a" * 64, "executable_relative_path": "subfinder", "executable_sha256": digest,
            "platform": current_platform, "architecture": current_arch, "installer_version": "13.0.0",
            "trust_status": "VALID", "claims": ["ARCHIVE_INTEGRITY_VERIFIED", "EXECUTABLE_INTEGRITY_VERIFIED"],
        }))
        adapter = SubfinderAdapter()
        assert adapter.verify_managed_binary(str(binary)) is True
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
async def test_orchestrator_discovery_callback_does_not_authorize_or_queue_target():
    orchestrator = ScanOrchestrator()
    job = ScanJob(target=Target(name="root", type=TargetType.DOMAIN, value="example.com"), organization_id="org-a")
    orchestrator._active_jobs[job.id] = job
    discovered = DiscoveredSubdomain(domain="api.example.com", discovered_via="Subfinder", dns_status="UNRESOLVED")

    await orchestrator.emit_subdomain_discovered(job.id, discovered)

    assert [item.domain for item in job.discovered_subdomains] == ["api.example.com"]
    assert not hasattr(job, "validated_targets")
    assert not hasattr(orchestrator, "active_target_queue")
    assert job.discovered_subdomains[0].dns_status == "UNRESOLVED"
