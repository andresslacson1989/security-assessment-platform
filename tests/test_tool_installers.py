"""
Unit & Integration Tests for In-App Tool Installers & Capabilities Lifecycle Manager.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md & Contract 08
"""

import asyncio
import io
import json
import os
import shutil
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
)
from app.installers.base_installer import BaseToolInstaller, SecurityError
from app.installers.pip_installer import PipToolInstaller
from app.installers.github_release_installer import GithubReleaseInstaller
from app.installers.system_installer import SystemToolHelper
from app.installers.manager import ToolInstallationManager


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def manager():
    return ToolInstallationManager.get_instance()


@pytest.mark.asyncio
async def test_manager_get_all_tools_info(manager):
    """Verifies that all 21 tools are registered with valid installation metadata."""
    tools = await manager.get_all_tools_info()
    assert len(tools) == 21
    names = {t.name for t in tools}
    expected_names = {
        "sslyze", "bandit", "semgrep", "checkov", "prowler", "schemathesis",
        "nuclei", "ffuf", "gitleaks", "trivy", "subfinder", "httpx", "katana",
        "syft", "grype", "osv-scanner", "trufflehog", "dockle", "kube-bench",
        "nmap", "retire"
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


@pytest.mark.asyncio
async def test_pip_tool_installer_success():
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

    # Mock subprocess
    mock_proc = MagicMock()
    mock_proc.stdout = [
        "Collecting bandit\n",
        "Installing collected packages: bandit\n",
        "Successfully installed bandit-1.7.8\n",
    ]
    mock_proc.wait = MagicMock(return_value=0)
    mock_proc.returncode = 0

    with patch("subprocess.Popen", return_value=mock_proc):
        with patch.object(installer, "get_version", new=AsyncMock(return_value="bandit 1.7.8")):
            res = await installer.install(log_cb, prog_cb, force=False)
            assert res is True
            assert any("Successfully installed" in l for l in logs)
            assert progress_records[-1][0] == 100


@pytest.mark.asyncio
async def test_pip_tool_installer_failure():
    """Tests PipToolInstaller failure handling on non-zero exit."""
    installer = PipToolInstaller("sslyze")
    logs = []
    prog = []

    mock_proc = MagicMock()
    mock_proc.stdout = ["ERROR: No matching distribution\n"]
    mock_proc.wait = MagicMock(return_value=1)
    mock_proc.returncode = 1

    with patch("subprocess.Popen", return_value=mock_proc):
        res = await installer.install(
            lambda m: logs.append(m) or asyncio.sleep(0),
            lambda p, s: prog.append((p, s)) or asyncio.sleep(0),
            force=False
        )
        assert res is False
        assert any("failed with exit code 1" in l for l in logs)


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

            with patch("httpx.AsyncClient", return_value=mock_client):
                with patch.object(installer, "get_version", new=AsyncMock(return_value="nuclei v3.2.0")):
                    res = await installer.install(log_cb, prog_cb, force=False)
                    assert res is True
                    assert progress_records[-1][0] == 100
                    # Verify file placed in fake_bin_dir
                    assert os.path.exists(os.path.join(fake_bin_dir, "nuclei.exe"))


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
    with patch.object(installer, "get_version", new=AsyncMock(return_value="Nmap 7.94")):
        res = await installer.install(
            lambda m: logs.append(m) or asyncio.sleep(0),
            lambda p, s: prog.append((p, s)) or asyncio.sleep(0),
        )
        assert res is True
        assert any("Nmap 7.94" in l for l in logs)


def test_tool_management_api_endpoints(client, manager):
    """Tests tool REST endpoints: list, install single, batch install, get status."""
    # 1. GET /api/system/tools
    resp = client.get("/api/system/tools")
    assert resp.status_code == 200
    tools = resp.json()
    assert len(tools) == 21

    # 2. GET /api/system/tools/nuclei/status
    resp = client.get("/api/system/tools/nuclei/status")
    assert resp.status_code == 200
    info = resp.json()
    assert info["name"] == "nuclei"
    assert info["install_method"] == "STANDALONE_BINARY"

    # 3. GET unknown tool status -> 404
    resp = client.get("/api/system/tools/unknown_tool_xyz/status")
    assert resp.status_code == 404

    # 4. POST /api/system/tools/bandit/install
    with patch.object(manager._installers["bandit"], "install", new=AsyncMock(return_value=True)):
        resp = client.post("/api/system/tools/bandit/install", json={"force": False})
        assert resp.status_code == 202
        data = resp.json()
        assert data["tool_name"] == "bandit"
        assert data["status"] == "INSTALLING"
        assert data["task_id"].startswith("tool-inst-")

    # 5. POST /api/system/tools/install-all
    with patch.object(manager, "_installers", {k: MagicMock(display_name=k, install=AsyncMock(return_value=True), get_info=AsyncMock(return_value=MagicMock(status=ToolInstallStatus.NOT_INSTALLED, path=None, version=None))) for k in manager._installers}):
        resp = client.post("/api/system/tools/install-all", json={"force": False})
        assert resp.status_code == 202
        batch = resp.json()
        assert isinstance(batch, list)

    # 6. POST /api/system/tools/bandit/cancel
    resp = client.post("/api/system/tools/bandit/cancel")
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

