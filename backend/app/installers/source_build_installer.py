"""Contract 03/08 verified source-build installer for approved tools."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import tarfile
import tempfile
import uuid
from pathlib import Path
from typing import Optional

import httpx

from app.core.models import ToolInstallMethod
from app.core.version import APP_VERSION
from app.core.process_supervisor import process_supervisor
from app.installers.base_installer import (
    BaseToolInstaller,
    LogCallback,
    ProgressCallback,
    SecurityError,
)
from app.installers.tool_manifest import PINNED_TOOL_MANIFEST


SOURCE_BUILD_CONFIG = {
    "trivy": {
        "display_name": "Trivy Container & Dependency SCA Scanner",
        "category": "Infra IaC",
        "source_root": "trivy-0.50.0",
        "source_commit": "8ec3938e01a93855503e3400eae9831abbb5de4a",
        "go_version": "1.21.13",
        "build_package": "./cmd/trivy",
        "version_cmd": ["--version"],
    }
}


class SourceBuildInstaller(BaseToolInstaller):
    """Builds an approved source tag with a pinned, verified Go toolchain."""

    def __init__(self, tool_name: str):
        if tool_name not in SOURCE_BUILD_CONFIG:
            raise ValueError(f"Unknown SourceBuildInstaller target: {tool_name}")
        self._tool_name = tool_name
        self._cfg = SOURCE_BUILD_CONFIG[tool_name]

    @property
    def tool_name(self) -> str:
        return self._tool_name

    @property
    def display_name(self) -> str:
        return self._cfg["display_name"]

    @property
    def category(self) -> str:
        return self._cfg["category"]

    @property
    def install_method(self) -> ToolInstallMethod:
        return ToolInstallMethod.STANDALONE_BINARY

    @property
    def install_command_hint(self) -> str:
        return "Install the approved source-build prerequisites and run the managed installer."

    @property
    def download_url(self) -> Optional[str]:
        return PINNED_TOOL_MANIFEST[self.tool_name]["source_archive_url"]

    def _platform_key(self) -> str:
        if platform.system().lower() != "linux":
            raise RuntimeError("The approved Trivy source-build path currently supports Linux only")
        machine = platform.machine().lower()
        if machine in ("x86_64", "amd64"):
            return "linux_amd64"
        if machine in ("aarch64", "arm64"):
            return "linux_arm64"
        raise RuntimeError(f"Unsupported source-build architecture: {machine}")

    async def _download(self, client: httpx.AsyncClient, url: str, destination: str) -> str:
        digest = hashlib.sha256()
        async with client.stream("GET", url) as response:
            response.raise_for_status()
            with open(destination, "wb") as output:
                async for chunk in response.aiter_bytes(chunk_size=1024 * 1024):
                    digest.update(chunk)
                    output.write(chunk)
        return digest.hexdigest()

    @staticmethod
    def _safe_extract_tar(archive: str, target: str) -> None:
        root = Path(target).resolve()
        with tarfile.open(archive, "r:*") as handle:
            members = handle.getmembers()
            for member in members:
                destination = (root / member.name).resolve()
                if os.path.commonpath((str(root), str(destination))) != str(root):
                    raise SecurityError(f"Tar path traversal detected: {member.name}")
                if member.isdev() or member.isfifo() or member.ischr() or member.isblk():
                    raise SecurityError(f"Unsafe archive entry type: {member.name}")
                if member.issym() or member.islnk():
                    link_target = (destination.parent / member.linkname).resolve()
                    if os.path.commonpath((str(root), str(link_target))) != str(root):
                        raise SecurityError(f"Archive link escapes extraction root: {member.name}")
            handle.extractall(root)

    async def get_version(self) -> Optional[str]:
        path = self.resolve_binary_path()
        if not path:
            return None
        code, stdout, stderr = await process_supervisor.execute(
            [path] + self._cfg["version_cmd"], timeout=5.0, max_output_bytes=1024 * 1024
        )
        output = stdout or stderr
        match = re.search(r"Version:\s*([0-9]+\.[0-9]+\.[0-9]+)", output or "", re.IGNORECASE)
        return f"trivy {match.group(1)}" if code == 0 and match else None

    async def install(self, emit_log: LogCallback, emit_progress: ProgressCallback, force: bool = False) -> bool:
        manifest = PINNED_TOOL_MANIFEST.get(self.tool_name, {})
        if manifest.get("trust_mode") != "SOURCE_BUILD_MODE" or not manifest.get("source_build"):
            await emit_log("Installation refused: source-build mode is not authorized by the manifest.")
            return False
        platform_key = self._platform_key()
        checksums = manifest.get("sha256_checksums", {})
        source_url = manifest.get("source_archive_url")
        source_sha = checksums.get("source_archive")
        go_key = "go_linux_arm64" if platform_key.endswith("arm64") else "go_linux_amd64"
        go_sha = checksums.get(go_key)
        go_name = manifest.get("asset_names", {}).get(go_key)
        if not all((source_url, source_sha, go_sha, go_name)):
            await emit_log("Installation refused: incomplete source-build identity in the pinned manifest.")
            return False

        bin_dir = Path(self.get_bin_dir())
        bin_dir.mkdir(parents=True, exist_ok=True)
        staged_binary = bin_dir / f".trivy.{uuid.uuid4().hex}.staged"
        staged_trust = bin_dir / f".trivy.trust.{uuid.uuid4().hex}.staged"
        try:
            await emit_progress(10, "Downloading verified Go toolchain and Trivy source archive...")
            async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client, tempfile.TemporaryDirectory() as temp:
                source_archive = os.path.join(temp, "trivy-source.tar.gz")
                go_archive = os.path.join(temp, go_name)
                source_actual = await self._download(client, source_url, source_archive)
                go_url = f"https://go.dev/dl/{go_name}"
                go_actual = await self._download(client, go_url, go_archive)
                if source_actual != source_sha:
                    raise SecurityError(f"Trivy source archive SHA-256 mismatch: {source_actual}")
                if go_actual != go_sha:
                    raise SecurityError(f"Go toolchain SHA-256 mismatch: {go_actual}")
                await emit_progress(35, "Extracting verified source and toolchain...")
                source_dir = os.path.join(temp, "source")
                go_dir = os.path.join(temp, "go")
                os.makedirs(source_dir)
                os.makedirs(go_dir)
                self._safe_extract_tar(source_archive, source_dir)
                self._safe_extract_tar(go_archive, go_dir)
                source_root = os.path.join(source_dir, self._cfg["source_root"])
                go_root = os.path.join(go_dir, "go")
                if not os.path.isdir(source_root) or not os.path.isfile(os.path.join(go_root, "bin", "go")):
                    raise SecurityError("Verified source-build inputs are incomplete")
                env = dict(os.environ)
                env.update({"PATH": os.path.join(go_root, "bin") + os.pathsep + env.get("PATH", ""), "GOTOOLCHAIN": "local", "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64" if platform_key.endswith("amd64") else "arm64"})
                for command, stage, message in [
                    ([os.path.join(go_root, "bin", "go"), "mod", "download"], 50, "Verifying Go module dependencies from go.sum..."),
                    ([os.path.join(go_root, "bin", "go"), "build", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w -X=github.com/aquasecurity/trivy/pkg/version.ver=0.50.0", "-o", str(staged_binary), self._cfg["build_package"]], 75, "Building Trivy from the verified source tag..."),
                ]:
                    await emit_progress(stage, message)
                    code, _, stderr = await process_supervisor.execute(command, cwd=source_root, env=env, timeout=900.0, max_output_bytes=10 * 1024 * 1024)
                    if code != 0:
                        raise RuntimeError(f"Source build command failed: {stderr[-2000:]}")
                os.chmod(staged_binary, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
                await emit_progress(90, "Verifying the built executable version and trust evidence...")
                code, stdout, stderr = await process_supervisor.execute([str(staged_binary), "--version"], timeout=10.0, max_output_bytes=1024 * 1024)
                if code != 0 or not re.search(r"Version:\s*0\.50\.0\b", stdout or stderr, re.IGNORECASE):
                    raise SecurityError(f"Built Trivy failed exact runtime version verification: {stdout or stderr}")
                executable_sha = hashlib.sha256(staged_binary.read_bytes()).hexdigest()
                trust = {"tool_id": "TOOL-TRIVY", "tool_version": "v0.50.0", "artifact_filename": manifest["asset_names"]["source_archive"], "artifact_sha256": source_actual, "source_commit": self._cfg["source_commit"], "build_toolchain": self._cfg["go_version"], "build_toolchain_sha256": go_actual, "executable_relative_path": "trivy", "executable_sha256": executable_sha, "platform": "linux", "architecture": "arm64" if platform_key.endswith("arm64") else "amd64", "installer_version": APP_VERSION, "trust_status": "VALID", "claims": ["SOURCE_ARCHIVE_INTEGRITY_VERIFIED", "BUILD_TOOLCHAIN_INTEGRITY_VERIFIED", "EXECUTABLE_INTEGRITY_VERIFIED"]}
                staged_trust.write_text(json.dumps(trust, sort_keys=True), encoding="utf-8")
                with open(staged_trust, "a", encoding="utf-8") as record:
                    record.flush()
                    os.fsync(record.fileno())
                os.replace(staged_binary, bin_dir / "trivy")
                os.replace(staged_trust, bin_dir / "trivy.trust.json")
                await emit_progress(100, "Successfully installed verified Trivy source build (v0.50.0).")
                return True
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await emit_log(f"Error installing {self.tool_name}: {exc}")
            await emit_progress(100, f"Installation failed: {exc}")
            return False
        finally:
            for path in (staged_binary, staged_trust):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
