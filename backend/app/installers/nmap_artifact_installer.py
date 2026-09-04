"""
Direct Artifact Installer for Nmap Network & Port Scanner (Contract 03 & Contract 09).
Downloads official Insecure.Org release package, verifies SHA-256 integrity,
extracts binary and supporting data files, and creates a cryptographic hash-bound
managed trust record (not cryptographically signed — no private key is used).
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
import struct
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import httpx
try:
    import zstandard
except ImportError:
    zstandard = None  # type: ignore

from app.core.models import ToolInstallMethod
from app.core.version import APP_VERSION
from app.core.binary_trust import (
    write_direct_artifact_trust_record,
    verify_managed_binary_artifact,
    build_resource_manifest,
)
from app.installers.base_installer import (
    BaseToolInstaller,
    SecurityError,
    LogCallback,
    ProgressCallback,
    MAX_INSTALLER_REDIRECTS,
    resolve_allowed_https_redirect,
)
from app.core.process_supervisor import process_supervisor
from app.installers.tool_manifest import PINNED_TOOL_MANIFEST, calculate_sha256


class NmapArtifactInstaller(BaseToolInstaller):
    """
    Installs verified pre-compiled Nmap binary and supporting NSE/signature assets
    directly from official Insecure.Org release packages into user-space backend/bin.
    """

    _ALLOWED_REDIRECT_HOSTS = frozenset({
        "nmap.org",
        "www.nmap.org",
        "insecure.org",
        "www.insecure.org",
    })

    def __init__(self, tool_name: str = "nmap"):
        self._tool_name = "nmap"

    @property
    def tool_name(self) -> str:
        return self._tool_name

    @property
    def display_name(self) -> str:
        return "Nmap Network & Port Scanner (NSE)"

    @property
    def category(self) -> str:
        return "Network Perimeter"

    @property
    def install_method(self) -> ToolInstallMethod:
        return ToolInstallMethod.STANDALONE_BINARY

    @property
    def is_elevated_required(self) -> bool:
        return False

    @property
    def install_command_hint(self) -> str:
        return "Click 'Install' to download and verify the official Insecure.Org release package."

    @property
    def download_url(self) -> Optional[str]:
        manifest = PINNED_TOOL_MANIFEST.get(self.tool_name, {})
        return manifest.get("download_urls", {}).get(self._platform_key())

    def _platform_key(self) -> str:
        system = platform.system().lower()
        machine = platform.machine().lower()
        if system == "linux" and machine in ("x86_64", "amd64"):
            return "linux_amd64"
        elif system == "darwin":
            return "darwin_amd64" if machine in ("x86_64", "amd64") else "darwin_arm64"
        elif system == "windows":
            return "windows_amd64"
        return f"{system}_{machine}"

    def is_assured_installation(self, path: Optional[str] = None) -> bool:
        target = path or self.resolve_binary_path()
        if not target:
            return False
        return verify_managed_binary_artifact("nmap", target, expected_version="7.95")

    async def get_version(self) -> Optional[str]:
        path = self.resolve_binary_path()
        if not path:
            return None
        env = {}
        resources = os.path.abspath(os.path.join(os.path.dirname(path), "resources", "nmap"))
        if os.path.isdir(resources):
            env["NMAPDIR"] = resources
        code, stdout, stderr = await process_supervisor.execute(
            [path, "--version"],
            env=env,
            timeout=5.0,
            max_output_bytes=1024 * 1024,
        )
        output = stdout or stderr
        match = re.search(r"Nmap version\s+([0-9\.]+[a-zA-Z0-9]*)", output or "", re.IGNORECASE)
        return f"Nmap {match.group(1)}" if code == 0 and match else None

    # Maximum permitted CPIO entry name length (prevents excessive memory allocation)
    _CPIO_MAX_NAMESIZE = 4096
    # Maximum permitted single extracted file size (100 MiB)
    _CPIO_MAX_FILESIZE = 100 * 1024 * 1024
    # Maximum number of CPIO entries to process (prevents infinite-loop bombs)
    _CPIO_MAX_ENTRIES = 8192

    @staticmethod
    def _extract_rpm_payload(rpm_path: str, target_bin: str, target_resources: str) -> None:
        """
        Parses RPM package header, decompresses the zstd-compressed cpio payload,
        and extracts ./usr/bin/nmap and ./usr/share/nmap/* into target destinations.

        Hardened against adversarial packages:
        - Rejects absolute paths and path-traversal sequences
        - Rejects symlink and hardlink CPIO entries
        - Rejects non-regular, non-directory file types
        - Rejects over-size namesize/filesize values
        - Rejects duplicate destination paths (first-write wins; second raises)
        - Caps total decompressed size at 150 MiB
        - Caps total entry count at _CPIO_MAX_ENTRIES
        """
        with open(rpm_path, "rb") as f:
            lead = f.read(96)
            if lead[:4] != b"\xed\xab\xee\xdb":
                raise SecurityError("Invalid RPM lead magic")
            # Signature header
            sig_magic = f.read(4)
            if sig_magic != b"\x8e\xad\xe8\x01":
                raise SecurityError("Invalid RPM signature header magic")
            f.seek(4, 1)  # skip version + reserved
            il, dl = struct.unpack("!2I", f.read(8))
            f.seek(il * 16 + dl, 1)
            # 8-byte align
            rem = f.tell() % 8
            if rem:
                f.seek(8 - rem, 1)
            # General header
            gen_magic = f.read(4)
            if gen_magic != b"\x8e\xad\xe8\x01":
                raise SecurityError("Invalid RPM general header magic")
            f.seek(4, 1)
            il, dl = struct.unpack("!2I", f.read(8))
            f.seek(il * 16 + dl, 1)
            payload_data = f.read()

        if zstandard is None:
            raise SecurityError("RPM extraction failed: 'zstandard' Python package is required")

        dctx = zstandard.ZstdDecompressor()
        decompressed = dctx.decompress(payload_data, max_output_size=150 * 1024 * 1024)

        os.makedirs(os.path.dirname(target_bin), exist_ok=True)
        os.makedirs(target_resources, exist_ok=True)

        abs_target_bin = os.path.abspath(target_bin)
        abs_target_res = os.path.abspath(target_resources)

        pos = 0
        bin_found = False
        written_paths: set = set()
        entry_count = 0

        while pos < len(decompressed) - 110:
            magic = decompressed[pos:pos + 6]
            if magic not in (b"070701", b"070702"):
                break

            # Parse CPIO newc header (110-byte fixed header)
            try:
                mode     = int(decompressed[pos + 14:pos + 22], 16)
                nlink    = int(decompressed[pos + 22:pos + 30], 16)
                filesize = int(decompressed[pos + 54:pos + 62], 16)
                namesize = int(decompressed[pos + 94:pos + 102], 16)
            except ValueError:
                raise SecurityError("CPIO header field is not valid hex — malformed package")

            # --- Bounds checks ---
            if namesize < 1 or namesize > NmapArtifactInstaller._CPIO_MAX_NAMESIZE:
                raise SecurityError(f"CPIO namesize out of bounds: {namesize}")
            if filesize < 0 or filesize > NmapArtifactInstaller._CPIO_MAX_FILESIZE:
                raise SecurityError(f"CPIO filesize out of bounds: {filesize}")
            if pos + 110 + namesize > len(decompressed):
                raise SecurityError("CPIO entry name extends beyond payload boundary")

            raw_name = decompressed[pos + 110:pos + 110 + namesize - 1].decode("utf-8", "replace")
            if "TRAILER!!!" in raw_name:
                break

            pos += 110 + namesize
            rem = pos % 4
            if rem:
                pos += (4 - rem)

            if pos + filesize > len(decompressed):
                raise SecurityError("CPIO entry data extends beyond payload boundary")

            file_bytes = decompressed[pos:pos + filesize]
            pos += filesize
            rem = pos % 4
            if rem:
                pos += (4 - rem)

            entry_count += 1
            if entry_count > NmapArtifactInstaller._CPIO_MAX_ENTRIES:
                raise SecurityError("CPIO entry count exceeds maximum permitted limit")

            # --- File type checks ---
            ftype = mode & 0o170000
            IS_DIR     = 0o040000
            IS_REG     = 0o100000
            IS_SYMLINK = 0o120000

            # Reject symlinks unconditionally
            if ftype == IS_SYMLINK:
                raise SecurityError(f"CPIO entry is a symlink — rejected: {raw_name}")

            # Reject hardlinks (nlink > 1 on a non-directory with filesize > 0)
            if ftype == IS_REG and nlink > 1 and filesize > 0:
                raise SecurityError(f"CPIO entry is a hardlink — rejected: {raw_name}")

            # Only process directories and regular files
            if ftype not in (IS_DIR, IS_REG):
                # Skip device files, FIFOs, sockets etc. silently
                continue

            # --- Path sanitisation ---
            # Inspect raw path components before stripping prefix: normalize \ to /
            norm_name = raw_name.replace("\\", "/")
            if norm_name.startswith("/"):
                raise SecurityError(f"CPIO absolute path rejected: {raw_name}")
            raw_parts = norm_name.split("/")
            if ".." in raw_parts:
                raise SecurityError(f"CPIO path traversal sequence rejected: {raw_name}")

            # Deliberate single ./ prefix removal
            clean_name = norm_name[2:] if norm_name.startswith("./") else norm_name
            if clean_name.startswith("/") or ".." in clean_name.split("/"):
                raise SecurityError(f"CPIO path traversal sequence rejected: {raw_name}")

            # --- Extract relevant entries ---
            if clean_name == "usr/bin/nmap" and ftype == IS_REG:
                # Guard duplicate write
                if abs_target_bin in written_paths:
                    raise SecurityError("CPIO duplicate entry for nmap binary — rejected")
                written_paths.add(abs_target_bin)
                with open(target_bin, "wb") as out:
                    out.write(file_bytes)
                os.chmod(
                    target_bin,
                    stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
                    | stat.S_IRGRP | stat.S_IXGRP
                    | stat.S_IROTH | stat.S_IXOTH,
                )
                bin_found = True

            elif clean_name.startswith("usr/share/nmap/"):
                rel_path = clean_name[len("usr/share/nmap/"):]
                if not rel_path:
                    continue
                dest = os.path.normpath(os.path.join(target_resources, rel_path))
                abs_dest = os.path.abspath(dest)

                # Path-traversal boundary — must remain inside target_resources
                if os.path.commonpath((abs_target_res, abs_dest)) != abs_target_res:
                    raise SecurityError(f"CPIO path traversal detected: {raw_name}")

                if ftype == IS_DIR:
                    os.makedirs(dest, exist_ok=True)
                elif ftype == IS_REG and filesize > 0:
                    # Guard duplicate write
                    if abs_dest in written_paths:
                        raise SecurityError(f"CPIO duplicate path rejected: {rel_path}")
                    written_paths.add(abs_dest)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with open(dest, "wb") as out:
                        out.write(file_bytes)
                    if mode & 0o111:
                        os.chmod(dest, 0o755)

        if not bin_found or not os.path.isfile(target_bin):
            raise SecurityError("RPM extraction failed: 'usr/bin/nmap' not found in package payload")

    async def install(
        self,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        force: bool = False,
    ) -> bool:
        # Idempotency pre-check
        existing_path = self.resolve_binary_path()
        if not force and existing_path and self.is_assured_installation(existing_path):
            ver = await self.get_version()
            await emit_progress(100, f"{self.display_name} is already installed and verified.")
            await emit_log(f"{self.display_name} is already installed and cryptographically assured ({ver or 'verified'}).")
            return True

        platform_key = self._platform_key()
        if platform_key != "linux_amd64":
            await emit_log(f"In-app direct artifact installer for {self.tool_name} supports linux/amd64 (found '{platform_key}').")
            await emit_progress(100, f"Unsupported direct-artifact platform for {self.tool_name}")
            return False

        manifest = PINNED_TOOL_MANIFEST.get(self.tool_name, {})
        download_url = manifest.get("download_urls", {}).get(platform_key)
        expected_sha = manifest.get("sha256_checksums", {}).get(platform_key)
        expected_asset = manifest.get("asset_names", {}).get(platform_key)

        if not all((download_url, expected_sha, expected_asset)):
            await emit_log(f"Installation refused: incomplete direct-artifact metadata in manifest for {self.tool_name}")
            return False

        bin_dir = Path(self.get_bin_dir())
        bin_dir.mkdir(parents=True, exist_ok=True)
        final_binary = bin_dir / self.tool_name
        final_resources = bin_dir / "resources" / self.tool_name
        final_resources.parent.mkdir(parents=True, exist_ok=True)

        staged_binary = bin_dir / f".{self.tool_name}.{uuid.uuid4().hex}.staged"
        staged_resources = bin_dir / "resources" / f".{self.tool_name}.{uuid.uuid4().hex}.staged"

        try:
            await emit_progress(10, f"Downloading official {self.display_name} package ({expected_asset})...")
            await emit_log(f"Fetching release artifact from {download_url}...")

            async with httpx.AsyncClient(timeout=120.0, follow_redirects=False, trust_env=False) as client:
                with tempfile.TemporaryDirectory() as temp:
                    archive_path = os.path.join(temp, expected_asset)
                    curr_url = download_url
                    redirects = 0

                    while redirects <= MAX_INSTALLER_REDIRECTS:
                        response = await client.get(curr_url)
                        if response.status_code in (301, 302, 303, 307, 308):
                            redirect_loc = response.headers.get("location")
                            curr_url = resolve_allowed_https_redirect(curr_url, redirect_loc, self._ALLOWED_REDIRECT_HOSTS)
                            redirects += 1
                            continue
                        elif response.status_code == 200:
                            with open(archive_path, "wb") as f:
                                f.write(response.content)
                            break
                        else:
                            raise SecurityError(f"HTTP {response.status_code} fetching release artifact from {curr_url}")
                    else:
                        raise SecurityError("Too many redirects downloading release artifact")

                    actual_sha = hashlib.sha256(open(archive_path, "rb").read()).hexdigest()
                    if actual_sha != expected_sha:
                        raise SecurityError(f"Release package SHA-256 mismatch! Expected {expected_sha}, got {actual_sha}")

                    await emit_progress(45, "Cryptographic integrity verified. Extracting package payload...")
                    await emit_log(f"SHA-256 digest verified ({actual_sha[:16]}...). Extracting binary and signature resources...")

                    self._extract_rpm_payload(archive_path, str(staged_binary), str(staged_resources))

            await emit_progress(80, "Verifying extracted Nmap binary version and script engine...")
            env = {"NMAPDIR": str(staged_resources)}
            code, stdout, stderr = await process_supervisor.execute(
                [str(staged_binary), "--version"],
                env=env,
                timeout=10.0,
                max_output_bytes=1024 * 1024,
            )
            output = stdout or stderr
            match = re.search(r"Nmap version\s+([0-9\.]+[a-zA-Z0-9]*)", output or "", re.IGNORECASE)
            if code != 0 or not match or match.group(1) != manifest["version"]:
                raise SecurityError(f"Extracted Nmap executable failed runtime version check: {output}")

            await emit_progress(90, "Promoting binary and writing hash-bound managed trust record...")

            # Promote binary
            os.replace(staged_binary, final_binary)

            # Promote resources
            if final_resources.exists():
                shutil.rmtree(final_resources)
            os.replace(staged_resources, final_resources)

            # Build deterministic resource manifest AFTER promotion so hashes
            # reflect exactly the files that will be used at runtime.
            await emit_log("Building cryptographic resource tree manifest (NSE scripts, signatures)...")
            res_manifest = build_resource_manifest(final_resources)
            await emit_log(f"Resource manifest bound: {len(res_manifest)} file(s) hash-locked.")

            # Write direct artifact trust record — hash-binds both binary and resource tree.
            # Installation creates trust. Execution verifies trust. Execution never repairs trust.
            write_direct_artifact_trust_record(
                tool_name=self.tool_name,
                binary=str(final_binary),
                installer_version=APP_VERSION,
                resource_manifest=res_manifest,
            )

            await emit_progress(100, f"Successfully installed and assured {self.display_name} (v{manifest['version']}).")
            await emit_log(f"Nmap v{manifest['version']} is cryptographically hash-bound and ready for scans.")
            return True

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await emit_log(f"Error installing {self.tool_name}: {exc}")
            await emit_progress(100, f"Installation failed: {exc}")
            return False
        finally:
            if staged_binary.exists():
                try:
                    staged_binary.unlink()
                except Exception:
                    pass
            if staged_resources.exists():
                try:
                    shutil.rmtree(staged_resources)
                except Exception:
                    pass
