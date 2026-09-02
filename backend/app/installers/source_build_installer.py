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
    MAX_INSTALLER_REDIRECTS,
    resolve_allowed_https_redirect,
)
from app.installers.tool_manifest import PINNED_TOOL_MANIFEST


SOURCE_BUILD_CONFIG = {
    "nmap": {
        "display_name": "Nmap Network & Port Scanner",
        "category": "Network Perimeter",
        "source_root": "nmap-7.95",
        "source_revision": "svn-r39734",
        "build_package": None,
        "version_cmd": ["--version"],
        "version_regex": r"Nmap version\s+([0-9]+(?:\.[0-9]+)+)",
        "build_kind": "configure_make",
    },
    "trivy": {
        "display_name": "Trivy Container & Dependency SCA Scanner",
        "category": "Infra IaC",
        "source_root": "trivy-0.50.0",
        "source_commit": "8ec3938e01a93855503e3400eae9831abbb5de4a",
        "go_version": "go1.21.13",
        "build_package": "./cmd/trivy",
        "version_cmd": ["--version"],
        "version_regex": r"Version:\s*([0-9]+\.[0-9]+\.[0-9]+)",
        "build_kind": "go",
    }
}


class SourceBuildInstaller(BaseToolInstaller):
    """Builds an explicitly approved source artifact with verified inputs."""

    _ALLOWED_REDIRECT_HOSTS = frozenset({
        "github.com",
        "api.github.com",
        "codeload.github.com",
        "go.dev",
        "dl.google.com",
        "storage.googleapis.com",
        "nmap.org",
    })

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

    def is_assured_installation(self, path: Optional[str]) -> bool:
        if not path:
            return False
        from app.core.binary_trust import verify_managed_binary_artifact

        return verify_managed_binary_artifact(
            self.tool_name,
            path,
            expected_version=PINNED_TOOL_MANIFEST[self.tool_name].get("version"),
        )

    def _platform_key(self) -> str:
        if platform.system().lower() != "linux":
            raise RuntimeError(f"The approved {self.tool_name} source-build path currently supports Linux only")
        machine = platform.machine().lower()
        if machine in ("x86_64", "amd64"):
            return "linux_amd64"
        if machine in ("aarch64", "arm64"):
            return "linux_arm64"
        raise RuntimeError(f"Unsupported {self.tool_name} source-build architecture: {machine}")

    @staticmethod
    def _sha256_file(path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    async def _download(self, client: httpx.AsyncClient, url: str, destination: str) -> str:
        digest = hashlib.sha256()
        current_url = url
        for redirect_count in range(MAX_INSTALLER_REDIRECTS + 1):
            async with client.stream("GET", current_url) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location:
                        raise SecurityError("Installer redirect response omitted its destination.")
                    if redirect_count >= MAX_INSTALLER_REDIRECTS:
                        raise SecurityError("Installer redirect limit exceeded.")
                    current_url = resolve_allowed_https_redirect(
                        current_url, location, self._ALLOWED_REDIRECT_HOSTS
                    )
                    continue
                response.raise_for_status()
                with open(destination, "wb") as output:
                    async for chunk in response.aiter_bytes(chunk_size=1024 * 1024):
                        digest.update(chunk)
                        output.write(chunk)
                return digest.hexdigest()
        raise SecurityError("Installer download did not reach a terminal response.")

    async def _verify_source_tag(self, client: httpx.AsyncClient, manifest: dict) -> None:
        """Verify the pinned Git tag resolves to the pinned immutable commit."""
        repo = str(manifest.get("repo", "")).strip()
        tag = str(manifest.get("release_tag", "")).strip()
        expected_commit = str(manifest.get("source_commit", "")).strip().lower()
        if not repo or not tag or not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
            raise SecurityError("Incomplete source tag identity in the pinned manifest")
        ref_url = f"https://api.github.com/repos/{repo}/git/ref/tags/{tag}"
        response = await client.get(
            ref_url,
            headers={"Accept": "application/vnd.github+json", "User-Agent": f"CyberAssess/{APP_VERSION}"},
        )
        response.raise_for_status()
        ref = response.json()
        obj = ref.get("object") if isinstance(ref, dict) else None
        if not isinstance(obj, dict) or not obj.get("sha"):
            raise SecurityError("Pinned source tag did not resolve to a Git object")
        resolved_commit = str(obj["sha"]).lower()
        if obj.get("type") == "tag":
            tag_response = await client.get(
                f"https://api.github.com/repos/{repo}/git/tags/{resolved_commit}",
                headers={"Accept": "application/vnd.github+json", "User-Agent": f"CyberAssess/{APP_VERSION}"},
            )
            tag_response.raise_for_status()
            tag_data = tag_response.json()
            target = tag_data.get("object") if isinstance(tag_data, dict) else None
            resolved_commit = str(target.get("sha", "")).lower() if isinstance(target, dict) else ""
        if resolved_commit != expected_commit:
            raise SecurityError(
                f"Pinned source tag {tag} resolves to {resolved_commit or 'unknown'}, expected {expected_commit}"
            )

    async def _verify_source_identity(self, client: httpx.AsyncClient, manifest: dict) -> None:
        """Verify the immutable source identity supported by the manifest."""
        if self.tool_name == "trivy":
            await self._verify_source_tag(client, manifest)
            return
        if self.tool_name == "nmap":
            if str(manifest.get("source_revision", "")).strip() != self._cfg["source_revision"]:
                raise SecurityError("Pinned Nmap source revision is inconsistent with installer policy")
            return
        raise SecurityError(f"No source identity verifier is registered for {self.tool_name}")

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
        match = re.search(self._cfg["version_regex"], output or "", re.IGNORECASE)
        return f"{self.tool_name} {match.group(1)}" if code == 0 and match else None

    async def install(self, emit_log: LogCallback, emit_progress: ProgressCallback, force: bool = False) -> bool:
        manifest = PINNED_TOOL_MANIFEST.get(self.tool_name, {})
        if manifest.get("trust_mode") != "SOURCE_BUILD_MODE" or not manifest.get("source_build"):
            await emit_log("Installation refused: source-build mode is not authorized by the manifest.")
            return False
        if manifest.get("direct_release_artifact_available") is not False:
            await emit_log("Installation refused: source build is not permitted while a direct release artifact is available or its availability is unproven.")
            return False
        try:
            platform_key = self._platform_key()
        except (RuntimeError, OSError, ValueError) as exc:
            await emit_log(f"Installation refused for {self.tool_name}: {exc}")
            await emit_progress(100, f"Unsupported source-build platform for {self.tool_name}")
            return False
        checksums = manifest.get("sha256_checksums", {})
        source_url = manifest.get("source_archive_url")
        source_sha = checksums.get("source_archive")
        go_key = "go_linux_arm64" if platform_key.endswith("arm64") else "go_linux_amd64"
        go_sha = checksums.get(go_key)
        go_name = manifest.get("asset_names", {}).get(go_key)
        if not all((source_url, source_sha)):
            await emit_log("Installation refused: incomplete source-build identity in the pinned manifest.")
            return False

        if self.tool_name == "trivy" and not all((go_sha, go_name)):
            await emit_log("Installation refused: incomplete Go toolchain identity in the pinned manifest.")
            return False
        if self.tool_name == "nmap" and platform_key != "linux_amd64":
            await emit_log("Installation refused: the approved Nmap source build supports linux/amd64 only.")
            return False

        bin_dir = Path(self.get_bin_dir())
        bin_dir.mkdir(parents=True, exist_ok=True)
        staged_binary = bin_dir / f".{self.tool_name}.{uuid.uuid4().hex}.staged"
        staged_trust = bin_dir / f".{self.tool_name}.trust.{uuid.uuid4().hex}.staged"
        try:
            await emit_progress(10, f"Downloading verified {self.tool_name} source-build inputs...")
            async with httpx.AsyncClient(timeout=120.0, follow_redirects=False, trust_env=False) as client, tempfile.TemporaryDirectory() as temp:
                await self._verify_source_identity(client, manifest)
                source_archive = os.path.join(temp, manifest["asset_names"]["source_archive"])
                go_archive = os.path.join(temp, go_name) if go_name else None
                source_actual = await self._download(client, source_url, source_archive)
                go_actual = None
                if self.tool_name == "trivy":
                    go_url = f"https://go.dev/dl/{go_name}"
                    go_actual = await self._download(client, go_url, go_archive)
                if source_actual != source_sha:
                    raise SecurityError(f"{self.tool_name} source archive SHA-256 mismatch: {source_actual}")
                if self.tool_name == "trivy" and go_actual != go_sha:
                    raise SecurityError(f"Go toolchain SHA-256 mismatch: {go_actual}")
                await emit_progress(35, "Extracting verified source and toolchain...")
                source_dir = os.path.join(temp, "source")
                os.makedirs(source_dir)
                self._safe_extract_tar(source_archive, source_dir)
                source_root = os.path.join(source_dir, self._cfg["source_root"])
                if not os.path.isdir(source_root):
                    raise SecurityError("Verified source-build inputs are incomplete")
                if self.tool_name == "trivy":
                    go_dir = os.path.join(temp, "go")
                    os.makedirs(go_dir)
                    self._safe_extract_tar(go_archive, go_dir)
                    go_root = os.path.join(go_dir, "go")
                    if not os.path.isfile(os.path.join(go_root, "bin", "go")):
                        raise SecurityError("Verified Go toolchain is incomplete")
                    build_cache = os.path.join(temp, "go-cache")
                    module_cache = os.path.join(temp, "go-mod-cache")
                    os.makedirs(build_cache)
                    os.makedirs(module_cache)
                    env = {"PATH": os.path.join(go_root, "bin"), "GOTOOLCHAIN": "local", "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64" if platform_key.endswith("amd64") else "arm64", "GOCACHE": build_cache, "GOMODCACHE": module_cache, "HOME": temp}
                    commands = [
                        ([os.path.join(go_root, "bin", "go"), "mod", "download"], 50, "Verifying Go module dependencies from go.sum..."),
                        ([os.path.join(go_root, "bin", "go"), "build", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w -X=github.com/aquasecurity/trivy/pkg/version.ver=0.50.0", "-o", str(staged_binary), self._cfg["build_package"]], 75, "Building Trivy from the verified source tag..."),
                    ]
                else:
                    compiler = shutil.which("gcc")
                    expected_compiler_sha = manifest.get("build_toolchain_sha256", {}).get(platform_key)
                    if not compiler or not expected_compiler_sha or self._sha256_file(compiler) != expected_compiler_sha:
                        raise SecurityError("Pinned Nmap compiler/toolchain verification failed")
                    env = {"HOME": temp, "PATH": os.environ.get("PATH", "")}
                    commands = [
                        (["./configure", "--prefix=/usr/local", "--without-zenmap"], 50, "Configuring Nmap from the verified source archive..."),
                        (["make", "-j2"], 75, "Building Nmap from the verified source archive..."),
                        (["make", f"DESTDIR={temp}/nmap-root", "install"], 85, "Staging the verified Nmap executable..."),
                    ]
                for command, stage, message in commands:
                    await emit_progress(stage, message)
                    code, _, stderr = await process_supervisor.execute(command, cwd=source_root, env=env, timeout=900.0, max_output_bytes=10 * 1024 * 1024)
                    if code != 0:
                        raise RuntimeError(f"Source build command failed: {stderr[-2000:]}")
                if self.tool_name == "nmap":
                    built = Path(temp) / "nmap-root" / "usr" / "local" / "bin" / "nmap"
                    if not built.is_file():
                        raise SecurityError("Nmap source build did not produce the expected executable")
                    shutil.copy2(built, staged_binary)
                os.chmod(staged_binary, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
                await emit_progress(90, "Verifying the built executable version and trust evidence...")
                code, stdout, stderr = await process_supervisor.execute([str(staged_binary), "--version"], timeout=10.0, max_output_bytes=1024 * 1024)
                if code != 0 or not re.search(self._cfg["version_regex"] + r"\b", stdout or stderr, re.IGNORECASE):
                    raise SecurityError(f"Built {self.tool_name} failed exact runtime version verification: {stdout or stderr}")
                executable_sha = hashlib.sha256(staged_binary.read_bytes()).hexdigest()
                trust = {"tool_id": f"TOOL-{self.tool_name.upper().replace('-', '_')}", "tool_version": f"v{manifest['version']}", "artifact_filename": manifest["asset_names"]["source_archive"], "artifact_sha256": source_actual, "executable_relative_path": self.tool_name, "executable_sha256": executable_sha, "platform": "linux", "architecture": "arm64" if platform_key.endswith("arm64") else "amd64", "installer_version": APP_VERSION, "trust_status": "VALID", "claims": ["SOURCE_ARCHIVE_INTEGRITY_VERIFIED", "EXECUTABLE_INTEGRITY_VERIFIED"]}
                if self.tool_name == "trivy":
                    trust.update({"source_commit": self._cfg["source_commit"], "build_toolchain": self._cfg["go_version"], "build_toolchain_sha256": go_actual})
                    trust["claims"].append("BUILD_TOOLCHAIN_INTEGRITY_VERIFIED")
                else:
                    trust.update({"source_revision": self._cfg["source_revision"], "build_toolchain": manifest["build_toolchain"], "build_toolchain_sha256": manifest["build_toolchain_sha256"][platform_key]})
                    trust["claims"].append("BUILD_TOOLCHAIN_INTEGRITY_VERIFIED")
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
