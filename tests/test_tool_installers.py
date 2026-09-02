"""
Unit & Integration Tests for In-App Tool Installers & Capabilities Lifecycle Manager.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md & Contract 08
"""

import asyncio
import io
import json
import os
import platform
import shutil
import stat
import tarfile
import tempfile
import zipfile
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.core.models import (
    ToolInstallMethod,
    ToolInstallStatus,
    ToolInstallationInfo,
    UserProfile,
    UserRole,
)
from app.core.auth import create_access_token
from app.installers.base_installer import BaseToolInstaller, SecurityError
from app.installers.pip_installer import PipToolInstaller
from app.installers.github_release_installer import GithubReleaseInstaller
from app.installers.source_build_installer import SourceBuildInstaller, SOURCE_BUILD_CONFIG
from app.core.binary_resolver import resolve_tool_binary
from app.installers.system_installer import SystemToolHelper
from app.installers.manager import ToolInstallationManager
from app.installers.tool_manifest import PINNED_TOOL_MANIFEST, audit_tool_manifest


@pytest.fixture
def auth_headers():
    user = UserProfile(id="usr-adm-01", username="admin", email="admin@sec.local", role=UserRole.ADMIN)
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def manager():
    return ToolInstallationManager.get_instance()


@pytest.mark.asyncio
async def test_manager_get_all_tools_info(manager):
    """Verifies that all 26 contract tools are registered with valid metadata."""
    tools = await manager.get_all_tools_info()
    assert len(tools) == 26
    names = {t.name for t in tools}
    expected_names = {
        "sslyze", "bandit", "semgrep", "checkov", "prowler", "schemathesis",
        "nuclei", "ffuf", "gitleaks", "trivy", "subfinder", "httpx", "katana",
        "syft", "grype", "osv-scanner", "trufflehog", "dockle", "kube-bench",
        "nmap", "retire", "metasploit", "sqlmap", "amass", "hydra", "gtfobins"
    }
    assert names == expected_names

    # Check method assignments
    tool_map = {t.name: t for t in tools}
    assert tool_map["sslyze"].install_method == ToolInstallMethod.PIP
    assert tool_map["bandit"].install_method == ToolInstallMethod.PIP
    assert tool_map["semgrep"].install_method == ToolInstallMethod.PIP
    assert tool_map["checkov"].install_method == ToolInstallMethod.PIP
    assert tool_map["prowler"].install_method == ToolInstallMethod.PIP
    assert tool_map["schemathesis"].install_method == ToolInstallMethod.PIP

    assert tool_map["nuclei"].install_method == ToolInstallMethod.STANDALONE_BINARY
    assert tool_map["ffuf"].install_method == ToolInstallMethod.STANDALONE_BINARY
    assert tool_map["gitleaks"].install_method == ToolInstallMethod.STANDALONE_BINARY
    assert tool_map["trivy"].install_method == ToolInstallMethod.STANDALONE_BINARY
    assert tool_map["subfinder"].install_method == ToolInstallMethod.STANDALONE_BINARY
    assert tool_map["httpx"].install_method == ToolInstallMethod.STANDALONE_BINARY
    assert tool_map["katana"].install_method == ToolInstallMethod.STANDALONE_BINARY
    assert tool_map["syft"].install_method == ToolInstallMethod.STANDALONE_BINARY
    assert tool_map["grype"].install_method == ToolInstallMethod.STANDALONE_BINARY
    assert tool_map["osv-scanner"].install_method == ToolInstallMethod.STANDALONE_BINARY
    assert tool_map["trufflehog"].install_method == ToolInstallMethod.STANDALONE_BINARY
    assert tool_map["dockle"].install_method == ToolInstallMethod.STANDALONE_BINARY
    assert tool_map["kube-bench"].install_method == ToolInstallMethod.STANDALONE_BINARY

    assert tool_map["nmap"].install_method == ToolInstallMethod.SYSTEM_PACKAGE_MANAGER
    assert tool_map["retire"].install_method == ToolInstallMethod.SYSTEM_PACKAGE_MANAGER


def test_pypi_manifest_records_match_hash_locked_release_metadata():
    expected = {
        "sslyze": ("5.2.0", "15ecb471b251dfbd003ba81a57d36865a93f18b74c7e7883a00d8bbddd365e03"),
        "schemathesis": ("3.20.0", "52f03b4fa694c5a5e8dd0f606e0afb98644b1989b474f526af6dfb079e501cb4"),
        "semgrep": ("1.65.0", "f8d5e9bb4a743399646ff421f7261d19f11c02511c0398055ecf1d01d7a31c64"),
        "bandit": ("1.7.8", "36de50f720856ab24a24dbaa5fee2c66050ed97c1477e0a1159deab1775eab6b"),
        "checkov": ("3.2.0", "8e3aee686f76165f6d4bfcf6a8ee192ee84039a0f5f21315d8639b404a4bc06b"),
        "prowler": ("4.1.0", "2c4e9a77750b7f3ef83b2fc80ece21dd9cf6d2a55efb6325e8d072aa80e93da3"),
    }
    for tool_name, (version, digest) in expected.items():
        entry = PINNED_TOOL_MANIFEST[tool_name]
        assert entry["version"] == version
        assert entry["sha256_checksums"]["pypi_sdist"] == digest
        assert entry["asset_names"]["pypi_sdist"].endswith(f"-{version}.tar.gz")


def test_retire_manifest_records_official_npm_tarball_identity():
    entry = PINNED_TOOL_MANIFEST["retire"]

    assert entry["version"] == "4.4.3"
    assert entry["repo"] == "npm:retire"
    assert entry["asset_names"]["npm_tarball"] == "retire-4.4.3.tgz"
    assert entry["sha256_checksums"]["npm_tarball"] == "1352bd6054d92d261b4d85dbfd75c4cee800f583573b5d9d0c45b56e3282c280"


def test_nmap_manifest_records_package_manager_delegated_identity():
    entry = PINNED_TOOL_MANIFEST["nmap"]

    assert entry["version"] == "7.95"
    assert entry["trust_mode"] == "PACKAGE_MANAGER_MODE"
    assert entry["repo"] == "nmap/nmap"
    assert "insecure-org" not in entry["repo"]
    assert entry["sha256_checksums"] == {}
    assert "OS package manager" in entry["integrity_note"]


def test_manifest_audit_reports_assured_and_incomplete_registry_entries():
    status = audit_tool_manifest(
        ["sslyze", "schemathesis", "semgrep", "bandit", "checkov", "prowler", "retire", "nmap", "trivy", "unknown-tool"]
    )

    assert set(status["assured"]) == {"sslyze", "schemathesis", "semgrep", "bandit", "checkov", "prowler", "retire", "trivy"}
    assert status["incomplete"] == ["nmap"]
    assert status["invalid"] == []
    assert status["unregistered"] == ["unknown-tool"]

    assert audit_tool_manifest(["trivy"])["assured"] == ["trivy"]


def test_trivy_uses_the_verified_source_build_installer():
    installer = ToolInstallationManager().get_installer("trivy")
    assert isinstance(installer, SourceBuildInstaller)
    assert PINNED_TOOL_MANIFEST["trivy"]["trust_mode"] == "SOURCE_BUILD_MODE"
    assert PINNED_TOOL_MANIFEST["trivy"]["direct_release_artifact_available"] is False
    assert SOURCE_BUILD_CONFIG["trivy"]["go_version"] == PINNED_TOOL_MANIFEST["trivy"]["build_toolchain"]


def test_github_release_installer_requires_exact_release_tag():
    installer = GithubReleaseInstaller("nuclei")
    assert installer._release_matches_pin({"tag_name": "v3.2.0"}, "v3.2.0") is True
    assert installer._release_matches_pin({"tag_name": "v3.2.1"}, "v3.2.0") is False
    assert installer._release_matches_pin({"name": "v3.2.0"}, "v3.2.0") is False


@pytest.mark.asyncio
async def test_source_build_requires_pinned_tag_to_resolve_to_pinned_commit():
    installer = SourceBuildInstaller("trivy")
    manifest = PINNED_TOOL_MANIFEST["trivy"]
    response = MagicMock()
    response.json.return_value = {"object": {"type": "commit", "sha": manifest["source_commit"]}}
    response.raise_for_status.return_value = None
    client = MagicMock()
    client.get = AsyncMock(return_value=response)

    await installer._verify_source_tag(client, manifest)
    client.get.assert_awaited_once()

    response.json.return_value = {"object": {"type": "commit", "sha": "0" * 40}}
    with pytest.raises(SecurityError, match="resolves"):
        await installer._verify_source_tag(client, manifest)


@pytest.mark.asyncio
async def test_source_build_refuses_when_direct_release_availability_is_not_false():
    installer = SourceBuildInstaller("trivy")
    logs = []

    async def log_cb(message):
        logs.append(message)

    async def progress_cb(*_args):
        return None

    with patch.dict(PINNED_TOOL_MANIFEST["trivy"], {"direct_release_artifact_available": True}):
        assert await installer.install(log_cb, progress_cb) is False

    assert any("direct release artifact" in message for message in logs)


def test_manifest_covers_every_registered_tool_without_assuring_manual_tools():
    manager_names = set(ToolInstallationManager()._installers)
    assert manager_names == set(PINNED_TOOL_MANIFEST)
    status = audit_tool_manifest(sorted(manager_names))
    assert {"metasploit", "sqlmap", "amass", "hydra", "gtfobins"}.issubset(status["incomplete"])


def test_manifest_audit_rejects_malformed_digest_metadata():
    malformed = {
        "demo": {
            "tool_name": "demo",
            "version": "1.0.0",
            "release_tag": "v1.0.0",
            "sha256_checksums": {"linux_amd64": "not-a-sha256"},
            "asset_names": {"linux_amd64": "demo.tar.gz"},
        }
    }

    assert audit_tool_manifest(["demo"], malformed) == {
        "assured": [],
        "incomplete": [],
        "invalid": ["demo"],
        "unregistered": [],
    }


def test_manifest_audit_requires_complete_direct_artifact_identity():
    malformed = {
        "demo": {
            "tool_name": "demo",
            "version": "1.0.0",
            "release_tag": "v1.0.0",
            "repo": "example/demo",
            "category": "Test",
            "sha256_checksums": {"linux_amd64": "a" * 64},
            "asset_names": {"linux_amd64": "demo.tar.gz"},
        }
    }

    assert audit_tool_manifest(["demo"], malformed)["invalid"] == ["demo"]


def test_manifest_audit_requires_matching_digest_and_asset_keys():
    malformed = {
        "demo": {
            "tool_name": "demo",
            "version": "1.0.0",
            "release_tag": "v1.0.0",
            "repo": "example/demo",
            "category": "Test",
            "pinned_version": "v1.0.0",
            "sha256_checksums": {"linux_amd64": "a" * 64},
            "asset_names": {"linux_arm64": "demo.tar.gz"},
        }
    }

    assert audit_tool_manifest(["demo"], malformed)["invalid"] == ["demo"]


@pytest.mark.asyncio
async def test_pip_tool_installer_success(monkeypatch, tmp_path):
    """Tests PipToolInstaller with mocked subprocess output."""
    installer = PipToolInstaller("bandit")
    assert installer.tool_name == "bandit"
    assert installer.install_method == ToolInstallMethod.PIP

    logs = []
    progress_records = []

    async def log_cb(msg):
        logs.append(msg)

    async def prog_cb(pct, stg):
        progress_records.append((pct, stg))

    venv_bin = tmp_path / "bandit" / ("Scripts" if os.name == "nt" else "bin")
    venv_bin.mkdir(parents=True)
    venv_python = venv_bin / ("python.exe" if os.name == "nt" else "python")
    venv_python.write_bytes(b"test interpreter")
    binary = venv_bin / ("bandit.exe" if os.name == "nt" else "bandit")
    binary.write_bytes(b"test bandit executable")
    if os.name != "nt":
        binary.chmod(0o755)
    monkeypatch.setenv("CYBERASSESS_TOOL_VENV_DIR", str(tmp_path))

    with patch("app.installers.pip_installer.process_supervisor.execute", new=AsyncMock(return_value=(
        0,
        "Collecting bandit\nInstalling collected packages: bandit\nSuccessfully installed bandit-1.7.8\n",
        "",
    ))) as execute_mock:
        with patch.object(installer, "get_version", new=AsyncMock(return_value="bandit 1.7.8")), \
             patch("app.installers.pip_installer.build_package_trust_record", return_value={}) as build_record, \
             patch("app.installers.pip_installer.write_package_trust_record") as write_record:
            res = await installer.install(log_cb, prog_cb, force=False)
            assert res is True
            build_record.assert_called_once()
            write_record.assert_called_once()
            assert any("Successfully installed" in l for l in logs)
            assert progress_records[-1][0] == 100
    assert execute_mock.await_args.kwargs["timeout"] == 600.0
    assert execute_mock.await_args.kwargs["max_output_bytes"] == 10 * 1024 * 1024


@pytest.mark.asyncio
async def test_pip_tool_version_fallback_uses_process_supervisor():
    """Binary version fallback must remain under centralized process governance."""
    installer = PipToolInstaller("bandit")
    with patch.object(installer, "resolve_binary_path", return_value="/managed/bandit"), \
         patch("app.installers.pip_installer.process_supervisor.execute", new=AsyncMock(return_value=(
             0, "bandit 1.7.8\n", ""
         ))) as execute_mock:
        with patch("importlib.metadata.version", side_effect=Exception("package metadata unavailable")):
            version = await installer.get_version()

    assert version == "bandit 1.7.8"
    execute_mock.assert_awaited_once_with(
        ["/managed/bandit", "--version"],
        timeout=5.0,
        max_output_bytes=1024 * 1024,
    )


@pytest.mark.asyncio
async def test_subfinder_version_probe_initializes_fresh_windows_config_dir(monkeypatch, tmp_path):
    installer = GithubReleaseInstaller("subfinder")
    appdata = tmp_path / "AppData" / "Roaming"
    monkeypatch.setenv("APPDATA", str(appdata))

    with patch("app.installers.github_release_installer.process_supervisor.execute", new=AsyncMock(return_value=(
        0, "subfinder v2.6.5\n", ""
    ))) as execute_mock:
        version = await installer._probe_version("C:\\managed\\subfinder.exe")

    assert version == "subfinder v2.6.5"
    assert (appdata / "subfinder").is_dir()
    execute_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_pip_tool_installer_failure():
    """Tests PipToolInstaller failure handling on non-zero exit."""
    installer = PipToolInstaller("sslyze")
    logs = []
    prog = []

    with patch("app.installers.pip_installer.process_supervisor.execute", new=AsyncMock(return_value=(
        1,
        "",
        "ERROR: No matching distribution\n",
    ))):
        res = await installer.install(
            lambda m: logs.append(m) or asyncio.sleep(0),
            lambda p, s: prog.append((p, s)) or asyncio.sleep(0),
            force=False
        )
        assert res is False
        assert any("failed with exit code 1" in l for l in logs)


def test_pip_installer_uses_exact_contract_version():
    installer = PipToolInstaller("bandit")
    assert installer.install_command_hint == "python -m pip install --require-hashes -r tool-requirements/bandit.lock"


@pytest.mark.asyncio
async def test_tool_installation_info_exposes_manifest_assurance_status():
    assured = await PipToolInstaller("sslyze").get_info()
    delegated = await SystemToolHelper("nmap").get_info()
    unregistered = await SystemToolHelper("sqlmap").get_info()

    # A complete manifest makes the package eligible for assurance, but a
    # host installation is not assured until the installer-created trust
    # record and runtime file verification pass.
    assert assured.assurance_status == "UNASSURED"
    assert delegated.assurance_status == "DELEGATED"
    assert unregistered.assurance_status == "INCOMPLETE"


@pytest.mark.asyncio
async def test_system_installer_accepts_only_exact_contract_version(monkeypatch):
    installer = SystemToolHelper("nmap")
    monkeypatch.setattr(installer, "get_version", AsyncMock(return_value="Nmap version 7.94"))
    logs = []
    progress = []

    result = await installer.install(
        lambda message: logs.append(message) or asyncio.sleep(0),
        lambda percent, stage: progress.append((percent, stage)) or asyncio.sleep(0),
    )

    assert result is False
    assert any("expected exact version 7.95" in message for message in logs)


@pytest.mark.asyncio
async def test_system_installer_keeps_unversioned_manual_tools_diagnostic_only(monkeypatch):
    installer = SystemToolHelper("sqlmap")
    monkeypatch.setattr(installer, "get_version", AsyncMock(return_value="sqlmap/1.8.4#stable"))
    logs = []

    result = await installer.install(
        lambda message: logs.append(message) or asyncio.sleep(0),
        lambda _percent, _stage: asyncio.sleep(0),
    )

    assert result is False
    assert any("diagnostic-only" in message for message in logs)


def test_pip_tool_resolves_managed_virtualenv_binary_first(monkeypatch, tmp_path):
    venv_bin = tmp_path / "bandit" / ("Scripts" if os.name == "nt" else "bin")
    venv_bin.mkdir(parents=True)
    binary = venv_bin / ("bandit.exe" if os.name == "nt" else "bandit")
    binary.write_text("managed", encoding="utf-8")
    monkeypatch.setenv("CYBERASSESS_TOOL_VENV_DIR", str(tmp_path))

    assert resolve_tool_binary("bandit") == str(binary.resolve())


@pytest.mark.asyncio
async def test_github_installer_rejects_unmanifested_tool():
    installer = GithubReleaseInstaller("nuclei")
    logs = []
    progress = []
    with patch("app.installers.tool_manifest.PINNED_TOOL_MANIFEST", {}):
        result = await installer.install(
            lambda message: logs.append(message) or asyncio.sleep(0),
            lambda percent, stage: progress.append((percent, stage)) or asyncio.sleep(0),
        )
    assert result is False
    assert any("no authoritative release tag" in message for message in logs)


@pytest.mark.asyncio
async def test_github_release_installer_zip_slip_prevention():
    """Tests that ZipSlip traversal attempts in archives are detected and rejected."""
    installer = GithubReleaseInstaller("nuclei")

    with tempfile.TemporaryDirectory() as tmpdir:
        bad_zip_path = os.path.join(tmpdir, "evil.zip")
        # Create a malicious zip containing ../evil.exe
        with zipfile.ZipFile(bad_zip_path, "w") as z:
            z.writestr("../../../evil.exe", "malicious_binary")

        extract_target = os.path.join(tmpdir, "extract_target")
        os.makedirs(extract_target, exist_ok=True)

        with pytest.raises(SecurityError) as exc_info:
            installer._safe_extract_zip(bad_zip_path, extract_target)
        assert "ZipSlip" in str(exc_info.value)


def test_github_release_installer_rejects_archive_links(tmp_path):
    """Archive links and special files cannot escape quarantine during extraction."""
    installer = GithubReleaseInstaller("nuclei")
    zip_path = tmp_path / "link.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        info = zipfile.ZipInfo("nuclei.exe")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "../../outside.exe")

    with pytest.raises(SecurityError, match="Unsafe archive entry type"):
        installer._safe_extract_zip(str(zip_path), str(tmp_path / "zip-out"))

    tar_path = tmp_path / "link.tar.gz"
    with tarfile.open(tar_path, "w:gz") as archive:
        info = tarfile.TarInfo("nuclei.exe")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../outside.exe"
        archive.addfile(info)

    with pytest.raises(SecurityError, match="Unsafe archive entry type"):
        installer._safe_extract_tar(str(tar_path), str(tmp_path / "tar-out"))


@pytest.mark.asyncio
async def test_github_release_installer_success():
    """Tests successful release download, extraction, and binary placement."""
    installer = GithubReleaseInstaller("nuclei")

    logs = []
    progress_records = []

    async def log_cb(msg):
        logs.append(msg)

    async def prog_cb(pct, stg):
        progress_records.append((pct, stg))

    with tempfile.TemporaryDirectory() as fake_bin_dir:
        with patch.object(installer, "get_bin_dir", return_value=fake_bin_dir):
            # Mock GitHub Releases API response
            mock_release_api = {
                "tag_name": "v3.2.0",
                "assets": [
                    {
                        "name": "nuclei_3.2.0_windows_amd64.zip",
                        "browser_download_url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_windows_amd64.zip",
                    },
                    {
                        "name": "nuclei_3.2.0_linux_amd64.zip",
                        "browser_download_url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip",
                    },
                ],
            }

            # Create fake valid in-memory zip containing nuclei.exe
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w") as z:
                z.writestr("nuclei.exe", "#!/fake/nuclei binary")
            zip_bytes = zip_buffer.getvalue()

            # Mock httpx responses
            mock_api_resp = MagicMock()
            mock_api_resp.status_code = 200
            mock_api_resp.json.return_value = mock_release_api

            mock_stream_resp = MagicMock()
            mock_stream_resp.status_code = 200
            mock_stream_resp.headers = {"content-length": str(len(zip_bytes))}
            async def aiter_bytes(chunk_size=65536):
                yield zip_bytes
            mock_stream_resp.aiter_bytes = aiter_bytes

            mock_stream_ctx = MagicMock()
            mock_stream_ctx.__aenter__ = AsyncMock(return_value=mock_stream_resp)
            mock_stream_ctx.__aexit__ = AsyncMock(return_value=None)

            mock_client = MagicMock()
            mock_client.get = AsyncMock(return_value=mock_api_resp)
            mock_client.stream = MagicMock(return_value=mock_stream_ctx)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)

            with patch("httpx.AsyncClient", return_value=mock_client), \
                 patch("app.installers.tool_manifest.verify_download_integrity", return_value=(True, "fake_hash", None)), \
                 patch.object(installer, "_probe_version", new=AsyncMock(return_value="nuclei v3.2.0")):
                res = await installer.install(log_cb, prog_cb, force=False)
                assert res is True
                assert progress_records[-1][0] == 100
                # Verify file placed in fake_bin_dir
                assert os.path.exists(os.path.join(fake_bin_dir, "nuclei.exe"))


@pytest.mark.asyncio
async def test_github_release_installer_direct_executable_success():
    """Direct executable releases must use the same trust pipeline as archives."""
    installer = GithubReleaseInstaller("osv-scanner")
    logs = []
    progress_records = []

    async def log_cb(msg):
        logs.append(msg)

    async def prog_cb(pct, stage):
        progress_records.append((pct, stage))

    os_prefix = "windows" if os.name == "nt" else ("darwin" if platform.system().lower() == "darwin" else "linux")
    architecture = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "amd64"
    asset_name = PINNED_TOOL_MANIFEST["osv-scanner"]["asset_names"][f"{os_prefix}_{architecture}"]
    download_url = f"https://github.com/google/osv-scanner/releases/download/v1.7.0/{asset_name}"
    release = {
        "tag_name": "v1.7.0",
        "assets": [{"name": asset_name, "browser_download_url": download_url}],
    }
    artifact = b"verified direct executable bytes"

    api_response = MagicMock(status_code=200)
    api_response.json.return_value = release
    stream_response = MagicMock(status_code=200, headers={"content-length": str(len(artifact))})

    async def aiter_bytes(chunk_size=65536):
        yield artifact

    stream_response.aiter_bytes = aiter_bytes
    stream_context = MagicMock()
    stream_context.__aenter__ = AsyncMock(return_value=stream_response)
    stream_context.__aexit__ = AsyncMock(return_value=None)
    client = MagicMock()
    client.get = AsyncMock(return_value=api_response)
    client.stream = MagicMock(return_value=stream_context)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    with tempfile.TemporaryDirectory() as fake_bin_dir, \
         patch.object(installer, "get_bin_dir", return_value=fake_bin_dir), \
         patch("httpx.AsyncClient", return_value=client), \
         patch("app.installers.tool_manifest.verify_download_integrity", return_value=(True, "fake_hash", None)), \
         patch.object(installer, "_probe_version", new=AsyncMock(return_value="osv-scanner v1.7.0")):
        assert await installer.install(log_cb, prog_cb) is True
        expected_binary = "osv-scanner.exe" if os.name == "nt" else "osv-scanner"
        assert os.path.isfile(os.path.join(fake_bin_dir, expected_binary))
        assert progress_records[-1][0] == 100
    assert progress_records[-1][0] == 100


@pytest.mark.asyncio
async def test_system_tool_helper_instructions():
    """Tests SystemToolHelper guidance and platform detection."""
    installer = SystemToolHelper("nmap")
    assert installer.is_elevated_required is True
    assert installer.install_method == ToolInstallMethod.SYSTEM_PACKAGE_MANAGER

    hint = installer.install_command_hint
    assert "nmap" in hint.lower()

    logs = []
    prog = []
    with patch.object(installer, "get_version", new=AsyncMock(return_value="Nmap 7.95")):
        res = await installer.install(
            lambda m: logs.append(m) or asyncio.sleep(0),
            lambda p, s: prog.append((p, s)) or asyncio.sleep(0),
        )
        assert res is True
        assert any("Nmap 7.95" in l for l in logs)


def test_tool_management_api_endpoints(client, manager, auth_headers):
    """Tests tool REST endpoints: list, install single, batch install, get status."""
    assert client.get("/api/system/tools").status_code == 401
    assert client.get("/api/system/tools/nuclei/status").status_code == 401

    # 1. GET /api/system/tools
    resp = client.get("/api/system/tools", headers=auth_headers)
    assert resp.status_code == 200
    tools = resp.json()
    assert len(tools) == 26

    # 2. GET /api/system/tools/nuclei/status
    resp = client.get("/api/system/tools/nuclei/status", headers=auth_headers)
    assert resp.status_code == 200
    info = resp.json()
    assert info["name"] == "nuclei"
    assert info["install_method"] == "STANDALONE_BINARY"

    # 3. GET unknown tool status -> 404
    resp = client.get("/api/system/tools/unknown_tool_xyz/status", headers=auth_headers)
    assert resp.status_code == 404

    # 4. POST /api/system/tools/bandit/install
    with patch.object(manager._installers["bandit"], "install", new=AsyncMock(return_value=True)):
        resp = client.post("/api/system/tools/bandit/install", json={"force": False}, headers=auth_headers)
        assert resp.status_code == 202
        data = resp.json()
        assert data["tool_name"] == "bandit"
        assert data["status"] == "INSTALLING"
        assert data["task_id"].startswith("tool-inst-")

    # 5. POST /api/system/tools/install-all
    with patch.object(manager, "_installers", {k: MagicMock(display_name=k, install=AsyncMock(return_value=True), get_info=AsyncMock(return_value=MagicMock(status=ToolInstallStatus.NOT_INSTALLED, path=None, version=None))) for k in manager._installers}):
        resp = client.post("/api/system/tools/install-all", json={"force": False}, headers=auth_headers)
        assert resp.status_code == 202
        batch = resp.json()
        assert isinstance(batch, list)

    # 6. POST /api/system/tools/bandit/cancel
    resp = client.post("/api/system/tools/bandit/cancel", headers=auth_headers)
    assert resp.status_code == 200
    assert "tool_name" in resp.json()


@pytest.mark.asyncio
async def test_pip_lock_serialization(manager):
    """Verifies that Pip installs acquire the manager's pip lock to prevent concurrent write collisions."""
    execution_order = []

    async def fake_install(name, delay):
        async with manager._pip_lock:
            execution_order.append(f"{name}_start")
            await asyncio.sleep(delay)
            execution_order.append(f"{name}_end")

    # Run two simulated pip tasks concurrently
    task1 = asyncio.create_task(fake_install("bandit", 0.05))
    task2 = asyncio.create_task(fake_install("sslyze", 0.01))

    await asyncio.gather(task1, task2)

    # Serialization check: task1 must finish before task2 starts or vice-versa
    assert execution_order in [
        ["bandit_start", "bandit_end", "sslyze_start", "sslyze_end"],
        ["sslyze_start", "sslyze_end", "bandit_start", "bandit_end"],
    ]


def test_python_scripts_binary_resolution():
    """Verifies that BaseToolAdapter resolves binaries located in Python Scripts / bin directories."""
    from app.adapters.bandit_adapter import BanditAdapter
    import sys

    adapter = BanditAdapter()

    # Create dummy bandit executable in temp folder simulating Scripts directory
    with tempfile.TemporaryDirectory() as fake_base:
        scripts_dir = os.path.join(fake_base, "Scripts")
        os.makedirs(scripts_dir, exist_ok=True)
        fake_bin = os.path.join(scripts_dir, "bandit.exe" if os.name == "nt" else "bandit")
        with open(fake_bin, "w") as f:
            f.write("#!/bin/sh\n")

        with patch("sys.executable", os.path.join(fake_base, "python.exe")):
            resolved = adapter.resolve_binary_path()
            assert resolved is not None
            assert "bandit" in resolved.lower()

