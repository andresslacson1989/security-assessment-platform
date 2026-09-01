"""
Contract 03 & 08 Standalone Binary GitHub Release Installer (nuclei, ffuf, gitleaks, trivy).
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import asyncio
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
import uuid
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import httpx

from app.core.models import ToolInstallMethod
from app.installers.base_installer import (
    BaseToolInstaller,
    SecurityError,
    LogCallback,
    ProgressCallback,
)
from app.core.process_supervisor import process_supervisor


GITHUB_TOOL_CONFIGS: Dict[str, dict] = {
    "nuclei": {
        "display_name": "Nuclei Vulnerability & CVE Template Scanner",
        "category": "Web DAST",
        "repo": "projectdiscovery/nuclei",
        "binary_name": "nuclei",
        "command_hint": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "download_url": "https://github.com/projectdiscovery/nuclei/releases",
        "version_cmd": ["-version"],
    },
    "ffuf": {
        "display_name": "FFuF Fast Web Fuzzer & Content Discovery Engine",
        "category": "Web DAST",
        "repo": "ffuf/ffuf",
        "binary_name": "ffuf",
        "command_hint": "go install github.com/ffuf/ffuf/v2@latest",
        "download_url": "https://github.com/ffuf/ffuf/releases",
        "version_cmd": ["-V"],
    },
    "gitleaks": {
        "display_name": "Gitleaks Git History Secret Scanner",
        "category": "Code SAST",
        "repo": "gitleaks/gitleaks",
        "binary_name": "gitleaks",
        "command_hint": "go install github.com/gitleaks/gitleaks/v8@latest",
        "download_url": "https://github.com/gitleaks/gitleaks/releases",
        "version_cmd": ["version"],
    },
    "trivy": {
        "display_name": "Trivy Container & Dependency SCA Scanner",
        "category": "Infra IaC",
        "repo": "aquasecurity/trivy",
        "binary_name": "trivy",
        "command_hint": "winget install AquaSecurity.Trivy (or brew install trivy)",
        "download_url": "https://github.com/aquasecurity/trivy/releases",
        "version_cmd": ["--version"],
    },
    "subfinder": {
        "display_name": "Subfinder Passive Subdomain Recon Engine",
        "category": "Network EASM",
        "repo": "projectdiscovery/subfinder",
        "binary_name": "subfinder",
        "command_hint": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "download_url": "https://github.com/projectdiscovery/subfinder/releases",
        "version_cmd": ["-version"],
    },
    "httpx": {
        "display_name": "Httpx Fast HTTP Probe & Technology Fingerprinter",
        "category": "Network EASM",
        "repo": "projectdiscovery/httpx",
        "binary_name": "httpx",
        "command_hint": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "download_url": "https://github.com/projectdiscovery/httpx/releases",
        "version_cmd": ["-version"],
    },
    "katana": {
        "display_name": "Katana Headless Chromium SPA Crawler",
        "category": "Web DAST",
        "repo": "projectdiscovery/katana",
        "binary_name": "katana",
        "command_hint": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "download_url": "https://github.com/projectdiscovery/katana/releases",
        "version_cmd": ["-version"],
    },
    "syft": {
        "display_name": "Syft CycloneDX / SPDX SBOM Generator",
        "category": "Supply Chain",
        "repo": "anchore/syft",
        "binary_name": "syft",
        "command_hint": "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
        "download_url": "https://github.com/anchore/syft/releases",
        "version_cmd": ["--version"],
    },
    "grype": {
        "display_name": "Grype SBOM & Container Vulnerability Matcher",
        "category": "Supply Chain",
        "repo": "anchore/grype",
        "binary_name": "grype",
        "command_hint": "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
        "download_url": "https://github.com/anchore/grype/releases",
        "version_cmd": ["--version"],
    },
    "osv-scanner": {
        "display_name": "Google OSV-Scanner Open Source Vulnerability Engine",
        "category": "Supply Chain",
        "repo": "google/osv-scanner",
        "binary_name": "osv-scanner",
        "command_hint": "go install github.com/google/osv-scanner/cmd/osv-scanner@latest",
        "download_url": "https://github.com/google/osv-scanner/releases",
        "version_cmd": ["--version"],
    },
    "trufflehog": {
        "display_name": "TruffleHog Verified Live Credential Scanner",
        "category": "Code SAST",
        "repo": "trufflesecurity/trufflehog",
        "binary_name": "trufflehog",
        "command_hint": "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
        "download_url": "https://github.com/trufflesecurity/trufflehog/releases",
        "version_cmd": ["--version"],
    },
    "dockle": {
        "display_name": "Dockle CIS Docker Container Security Linter",
        "category": "Infra IaC",
        "repo": "goodwithtech/dockle",
        "binary_name": "dockle",
        "command_hint": "brew install goodwithtech/r/dockle (or scoop install dockle)",
        "download_url": "https://github.com/goodwithtech/dockle/releases",
        "version_cmd": ["--version"],
    },
    "kube-bench": {
        "display_name": "Kube-bench CIS Kubernetes Benchmark Auditor",
        "category": "Cluster Posture",
        "repo": "aquasecurity/kube-bench",
        "binary_name": "kube-bench",
        "command_hint": "kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml",
        "download_url": "https://github.com/aquasecurity/kube-bench/releases",
        "version_cmd": ["version"],
    },
}


class GithubReleaseInstaller(BaseToolInstaller):
    """
    Installer that fetches official release archives from GitHub, validates ZipSlip safety,
    extracts the binary to backend/bin/, and sets executable permissions.
    """

    def __init__(self, tool_name: str):
        if tool_name not in GITHUB_TOOL_CONFIGS:
            raise ValueError(f"Unknown GithubReleaseInstaller target: {tool_name}")
        self._tool_name = tool_name
        self._cfg = GITHUB_TOOL_CONFIGS[tool_name]

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
        return self._cfg["command_hint"]

    @property
    def download_url(self) -> Optional[str]:
        return self._cfg["download_url"]

    def _get_platform_keywords(self) -> Tuple[List[str], List[str]]:
        """Returns matching strings for OS and architecture."""
        system = platform.system().lower()
        machine = platform.machine().lower()

        os_keywords = []
        if "windows" in system or sys.platform == "win32":
            os_keywords = ["windows", "_win", "-win", "win64", "win32", "win_", "win."]
        elif "darwin" in system:
            os_keywords = ["darwin", "macos", "mac", "osx"]
        elif "linux" in system:
            os_keywords = ["linux"]

        arch_keywords = []
        if machine in ("x86_64", "amd64", "x64"):
            arch_keywords = ["amd64", "x86_64", "x64", "64bit"]
        elif machine in ("aarch64", "arm64"):
            arch_keywords = ["arm64", "aarch64"]
        elif "arm" in machine:
            arch_keywords = ["armv7", "arm"]
        elif "386" in machine or "i686" in machine:
            arch_keywords = ["386", "i386", "32bit", "x32"]

        return os_keywords, arch_keywords

    def _match_release_asset(self, assets: List[dict]) -> Optional[dict]:
        """Finds the best matching release asset for the current OS and CPU."""
        system = platform.system().lower()
        os_keys, arch_keys = self._get_platform_keywords()

        # Prefer an exact, manifest-bound filename. This is required for
        # releases whose executable assets have no archive suffix (for example
        # OSV-Scanner), and prevents a loose keyword match from selecting a
        # different platform artifact.
        from app.installers.tool_manifest import PINNED_TOOL_MANIFEST
        manifest = PINNED_TOOL_MANIFEST.get(self.tool_name, {})
        machine = platform.machine().lower()
        os_name = "windows" if ("windows" in system or sys.platform == "win32") else ("darwin" if "darwin" in system else "linux")
        arch_name = "arm64" if (machine in ("aarch64", "arm64")) else "amd64"
        platform_key = f"{os_name}_{arch_name}"
        exact_name = manifest.get("asset_names", {}).get(platform_key)
        if exact_name:
            return next((asset for asset in assets if asset.get("name") == exact_name), None)

        for asset in assets:
            name = asset.get("name", "").lower()
            if not (name.endswith(".zip") or name.endswith(".tar.gz") or name.endswith(".tgz")):
                continue

            # Prevent false positives (e.g. 'darwin' matching 'win' substring)
            if ("windows" in system or sys.platform == "win32") and ("darwin" in name or "linux" in name):
                continue
            if "darwin" in system and ("windows" in name or "linux" in name):
                continue
            if "linux" in system and ("windows" in name or "darwin" in name):
                continue

            # Check OS match
            if not any(k in name for k in os_keys):
                continue
            # Check Arch match
            if not any(k in name for k in arch_keys):
                continue
            # Avoid checksums or deb/rpm/apk packages
            if any(bad in name for bad in ("checksum", "sha256", ".deb", ".rpm", ".apk")):
                continue
            return asset

        # Fallback loose match
        for asset in assets:
            name = asset.get("name", "").lower()
            if ("windows" in system or sys.platform == "win32") and ("darwin" in name or "linux" in name):
                continue
            if any(k in name for k in os_keys) and (name.endswith(".zip") or name.endswith(".tar.gz") or name.endswith(".tgz")):
                return asset

        return None

    async def get_version(self) -> Optional[str]:
        path = self.resolve_binary_path()
        if not path:
            return None
        return await self._probe_version(path)

    async def _probe_version(self, path: str) -> Optional[str]:
        """Probe a specific executable through the central process supervisor."""
        # Subfinder initializes its provider configuration during a version
        # probe. Create the managed user-config directory first so a fresh
        # Windows installation is not rejected as an apparent version failure.
        if self.tool_name == "subfinder":
            appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
            Path(appdata, "subfinder").mkdir(parents=True, exist_ok=True)
        code, stdout, stderr = await process_supervisor.execute(
            [path] + self._cfg["version_cmd"],
            timeout=5.0,
            max_output_bytes=1024 * 1024,
        )
        output = stdout + (f"\n{stderr}" if stderr else "")
        lines = output.strip().splitlines()
        return lines[0] if code == 0 and lines else None

    def _safe_extract_zip(self, zip_path: str, target_dir: str) -> None:
        """Extracts zip archive with ZipSlip path traversal protection."""
        target_dir = os.path.abspath(target_dir)
        with zipfile.ZipFile(zip_path, "r") as z:
            for info in z.infolist():
                member = info.filename
                dest_path = os.path.abspath(os.path.join(target_dir, member))
                if not dest_path.startswith(target_dir + os.sep) and dest_path != target_dir:
                    raise SecurityError(f"ZipSlip traversal attempt detected: {member}")
                # Unix mode bits are stored in the upper half of external_attr.
                # Reject links and special files even when their names are safe.
                mode = (info.external_attr >> 16) & 0o170000
                if mode in (stat.S_IFLNK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK):
                    raise SecurityError(f"Unsafe archive entry type detected: {member}")
            z.extractall(target_dir)

    def _safe_extract_tar(self, tar_path: str, target_dir: str) -> None:
        """Extracts tar.gz archive with path traversal protection."""
        target_dir = os.path.abspath(target_dir)
        with tarfile.open(tar_path, "r:*") as t:
            for member in t.getmembers():
                dest_path = os.path.abspath(os.path.join(target_dir, member.name))
                if not dest_path.startswith(target_dir + os.sep) and dest_path != target_dir:
                    raise SecurityError(f"TarSlip traversal attempt detected: {member.name}")
                if member.issym() or member.islnk() or member.isdev() or member.isfifo() or member.ischr() or member.isblk():
                    raise SecurityError(f"Unsafe archive entry type detected: {member.name}")
            t.extractall(target_dir)

    async def install(
        self,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        force: bool = False,
    ) -> bool:
        repo = self._cfg["repo"]
        bin_name = self._cfg["binary_name"]
        local_bin_dir = self.get_bin_dir()

        from app.installers.tool_manifest import PINNED_TOOL_MANIFEST, verify_download_integrity
        manifest_entry = PINNED_TOOL_MANIFEST.get(self.tool_name, {})
        pinned_tag = manifest_entry.get("pinned_version")
        checksums = manifest_entry.get("sha256_checksums", {})
        if not pinned_tag or not checksums:
            message = (
                f"Installation refused for '{self.tool_name}': no authoritative release tag and platform digest "
                "are registered in PINNED_TOOL_MANIFEST."
            )
            await emit_log(message)
            await emit_progress(100, message)
            return False
        
        rel_label = pinned_tag or "pinned release"
        await emit_log(f"Querying GitHub release metadata for {repo} ({rel_label})...")
        await emit_progress(10, f"Fetching release metadata for {self.display_name} ({rel_label})...")

        headers = {
            "User-Agent": "CyberAssess-Platform/13.0.0",
            "Accept": "application/vnd.github.v3+json",
        }

        download_url = None
        asset_filename = None
        rel_url = f"https://api.github.com/repos/{repo}/releases/tags/{pinned_tag}" if pinned_tag else f"https://api.github.com/repos/{repo}/releases/latest"

        staged_binary_path = None
        staged_trust_path = None
        try:
            async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
                resp = await client.get(rel_url)
                if resp.status_code == 200:
                    data = resp.json()
                    assets = data.get("assets", [])
                    matched = self._match_release_asset(assets)
                    if matched:
                        download_url = matched.get("browser_download_url")
                        asset_filename = matched.get("name")
                        await emit_log(f"Found official release asset: {asset_filename}")
                elif resp.status_code == 403:
                    await emit_log(f"Notice: GitHub API unauthenticated rate limit reached. Checking fallback release targets...")

            if not download_url:
                raise RuntimeError(
                    f"Could not automatically resolve matching release asset for {repo} on {sys.platform}. "
                    f"Please install via: {self.install_command_hint}"
                )

            await emit_progress(30, f"Downloading {asset_filename}...")
            await emit_log(f"Downloading from {download_url}...")

            with tempfile.TemporaryDirectory() as tmpdir:
                archive_path = os.path.join(tmpdir, asset_filename)
                
                async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
                    async with client.stream("GET", download_url) as stream:
                        if stream.status_code != 200:
                            raise RuntimeError(f"Download failed with HTTP {stream.status_code}")
                        
                        total_bytes = int(stream.headers.get("content-length", 0))
                        downloaded = 0
                        with open(archive_path, "wb") as f:
                            async for chunk in stream.aiter_bytes(chunk_size=65536):
                                f.write(chunk)
                                downloaded += len(chunk)
                                if total_bytes > 0:
                                    pct = 30 + int((downloaded / total_bytes) * 35)
                                    await emit_progress(pct, f"Downloading: {downloaded // 1024} KB / {total_bytes // 1024} KB")

                # Cryptographic SHA-256 Checksum Verification
                await emit_progress(68, "Verifying cryptographic SHA-256 checksum integrity...")
                sys_plat = platform.system().lower()
                mach = platform.machine().lower()
                os_prefix = "windows" if "win" in sys_plat else ("darwin" if "darwin" in sys_plat else "linux")
                arch_suffix = "arm64" if ("arm64" in mach or "aarch64" in mach) else "amd64"
                platform_key = f"{os_prefix}_{arch_suffix}"

                with open(archive_path, "rb") as f:
                    archive_bytes = f.read()
                is_valid, computed_hash, hash_err = verify_download_integrity(
                    self.tool_name, archive_bytes, platform_key=platform_key
                )
                if not is_valid:
                    raise SecurityError(f"SHA-256 integrity check failed: {hash_err}")
                await emit_log(f"Verified archive SHA-256: {computed_hash[:16]}...")

                await emit_progress(75, "Extracting binary to isolated quarantine and validating safety...")
                await emit_log(f"Extracting {asset_filename} to managed bin directory...")

                extract_dir = os.path.join(tmpdir, "extracted")
                os.makedirs(extract_dir, exist_ok=True)

                if archive_path.endswith(".zip"):
                    self._safe_extract_zip(archive_path, extract_dir)
                elif archive_path.endswith((".tar.gz", ".tgz")):
                    self._safe_extract_tar(archive_path, extract_dir)
                else:
                    # Some official releases (notably OSV-Scanner) publish
                    # the platform executable directly without an archive.
                    raw_name = f"{bin_name}.exe" if os_name == "windows" else bin_name
                    shutil.copy2(archive_path, os.path.join(extract_dir, raw_name))

                # Locate the binary executable inside extracted files (including nested subdirectories)
                found_bin = None
                target_names = [f"{bin_name}.exe", bin_name]
                for root, _, files in os.walk(extract_dir):
                    for f in files:
                        if f.lower() in [tn.lower() for tn in target_names]:
                            found_bin = os.path.join(root, f)
                            break
                    if found_bin:
                        break

                if not found_bin:
                    raise FileNotFoundError(f"Could not find executable '{bin_name}' inside downloaded archive")

                # Validate the quarantined executable before it can enter the
                # managed directory. The production resolver must never be
                # used to validate an artifact that has not been promoted.
                dest_filename = os.path.basename(found_bin)
                dest_path = os.path.join(local_bin_dir, dest_filename)
                # On POSIX, ensure the staged executable is runnable.
                staged_binary_path = os.path.join(local_bin_dir, f".{dest_filename}.{uuid.uuid4().hex}.staged")
                staged_trust_path = os.path.join(local_bin_dir, f".{dest_filename}.trust.{uuid.uuid4().hex}.staged")
                shutil.copy2(found_bin, staged_binary_path)
                if os.name != "nt":
                    os.chmod(staged_binary_path, 0o755)

                await emit_progress(90, "Verifying binary execution...")
                ver = await self._probe_version(staged_binary_path)
                expected_version = str(pinned_tag or "").lstrip("v")
                version_match = re.search(r"(?<![0-9A-Za-z.-])v?(\d+\.\d+\.\d+)(?![0-9A-Za-z.-])", ver or "")
                if not version_match or version_match.group(1) != expected_version:
                    raise SecurityError(
                        f"Runtime version verification failed for {self.tool_name}: expected {pinned_tag}, found {ver or 'unavailable'}."
                    )
                with open(staged_binary_path, "rb") as binary_file:
                    executable_hash = hashlib.sha256(binary_file.read()).hexdigest()
                trust_record = {
                    "tool_id": f"TOOL-{self.tool_name.upper().replace('-', '_')}",
                    "tool_version": pinned_tag,
                    "artifact_filename": asset_filename,
                    "artifact_sha256": computed_hash,
                    "executable_relative_path": dest_filename,
                    "executable_sha256": executable_hash,
                    "platform": os_prefix,
                    "architecture": arch_suffix,
                    "installer_version": "13.0.0",
                    "trust_status": "VALID",
                    "claims": ["ARCHIVE_INTEGRITY_VERIFIED", "EXECUTABLE_INTEGRITY_VERIFIED"],
                }
                with open(staged_trust_path, "w", encoding="utf-8") as trust_file:
                    json.dump(trust_record, trust_file, sort_keys=True)
                    trust_file.flush()
                    os.fsync(trust_file.fileno())

                # Promotion is atomic. If the process stops between these two
                # replacements, the executable/sidecar mismatch fails trust
                # verification rather than authorizing an ambiguous binary.
                os.replace(staged_binary_path, dest_path)
                staged_binary_path = None
                os.replace(staged_trust_path, os.path.join(local_bin_dir, f"{dest_filename}.trust.json"))
                staged_trust_path = None
                await emit_log(f"Binary installed at: {dest_path} (version: {ver or 'unknown'})")
                await emit_progress(100, f"Successfully installed {self.display_name} ({ver or 'ready'})")
                return True

        except asyncio.CancelledError:
            await emit_log(f"Download/installation of {self.tool_name} was cancelled by user.")
            raise
        except Exception as e:
            await emit_log(f"Error installing {self.tool_name}: {e}")
            await emit_progress(100, f"Installation failed: {e}")
            return False
        finally:
            for staged_path in (staged_binary_path, staged_trust_path):
                if staged_path:
                    try:
                        os.unlink(staged_path)
                    except FileNotFoundError:
                        pass
