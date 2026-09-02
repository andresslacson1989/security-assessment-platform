"""Runtime verification for managed standalone tool artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import sys
from pathlib import Path
from typing import Any, Optional


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAX_TRUST_RECORD_BYTES = 1024 * 1024


def get_managed_bin_dir() -> Path:
    """Return the server-owned managed standalone-binary directory."""
    # Keep the final directory component unresolved so callers can reject a
    # symlinked managed root instead of silently normalizing it away.
    return Path(__file__).resolve().parents[2] / "bin"


def _platform_key() -> tuple[str, str, str]:
    system = platform.system().lower()
    if os.name == "nt" or sys.platform == "win32":
        platform_name = "windows"
    elif system == "darwin":
        platform_name = "darwin"
    else:
        platform_name = "linux"
    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        architecture = "arm64"
    elif machine in {"amd64", "x86_64", "x64"}:
        architecture = "amd64"
    else:
        architecture = "unsupported"
    return platform_name, architecture, f"{platform_name}_{architecture}"


def _is_regular_non_symlink(path: Path) -> bool:
    try:
        absolute = os.path.abspath(str(path))
        return path.is_file() and os.path.normcase(os.path.realpath(str(path))) == os.path.normcase(absolute)
    except OSError:
        return False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalized_version(value: Any) -> str:
    return str(value or "").strip().lstrip("v")


def _expected_executable_path(tool_name: str, managed_dir: Path) -> tuple[Path, ...]:
    return (managed_dir / tool_name, managed_dir / f"{tool_name}.exe")


def _validate_common_record(
    record: dict[str, Any],
    *,
    tool_name: str,
    binary_path: Path,
    expected_version: str,
    platform_name: str,
    architecture: str,
) -> bool:
    required = {
        "tool_id",
        "tool_version",
        "executable_relative_path",
        "executable_sha256",
        "platform",
        "architecture",
        "installer_version",
        "trust_status",
        "claims",
    }
    if not required.issubset(record):
        return False
    if (
        record["tool_id"] != f"TOOL-{tool_name.upper()}"
        or _normalized_version(record["tool_version"]) != _normalized_version(expected_version)
        or record["executable_relative_path"] != binary_path.name
        or record["platform"] != platform_name
        or record["architecture"] != architecture
        or not isinstance(record["installer_version"], str)
        or not record["installer_version"].strip()
        or record["trust_status"] != "VALID"
        or not isinstance(record["claims"], list)
        or "EXECUTABLE_INTEGRITY_VERIFIED" not in record["claims"]
        or not _SHA256_PATTERN.fullmatch(str(record["executable_sha256"]).lower())
    ):
        return False
    return str(record["executable_sha256"]).lower() == _sha256_file(binary_path)


def verify_managed_binary_artifact(
    tool_name: str,
    binary: str,
    *,
    expected_version: Optional[str] = None,
) -> bool:
    """Verify manifest-bound artifact identity at the process boundary."""
    try:
        from app.installers.tool_manifest import PINNED_TOOL_MANIFEST

        manifest = PINNED_TOOL_MANIFEST.get(tool_name)
        if not isinstance(manifest, dict):
            return False
        expected = expected_version or manifest.get("version")
        if not expected or not isinstance(binary, str) or not binary.strip() or "\x00" in binary:
            return False

        managed_dir = get_managed_bin_dir()
        if managed_dir.is_symlink():
            return False
        path = Path(os.path.abspath(binary))
        if not _is_regular_non_symlink(path):
            return False
        if os.name != "nt" and not os.access(path, os.X_OK):
            return False
        if not any(os.path.normcase(str(path)) == os.path.normcase(str(candidate)) for candidate in _expected_executable_path(tool_name, managed_dir)):
            return False

        record_path = Path(f"{path}.trust.json")
        if not _is_regular_non_symlink(record_path) or record_path.stat().st_size > _MAX_TRUST_RECORD_BYTES:
            return False
        record = json.loads(record_path.read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            return False

        platform_name, architecture, platform_key = _platform_key()
        if not _validate_common_record(
            record,
            tool_name=tool_name,
            binary_path=path,
            expected_version=str(expected),
            platform_name=platform_name,
            architecture=architecture,
        ):
            return False

        trust_mode = str(manifest.get("trust_mode", "DIRECT_ARTIFACT_MODE"))
        claims = set(record["claims"])
        checksums = manifest.get("sha256_checksums")
        assets = manifest.get("asset_names")
        if not isinstance(checksums, dict) or not isinstance(assets, dict):
            return False

        if trust_mode == "SOURCE_BUILD_MODE":
            source_sha = checksums.get("source_archive")
            source_name = assets.get("source_archive")
            expected_toolchain_sha = (
                manifest.get("build_toolchain_sha256", {}).get(platform_key)
                if isinstance(manifest.get("build_toolchain_sha256"), dict)
                else checksums.get(f"go_{platform_key}")
            )
            if not {
                "SOURCE_ARCHIVE_INTEGRITY_VERIFIED",
                "BUILD_TOOLCHAIN_INTEGRITY_VERIFIED",
            }.issubset(claims):
                return False
            if record.get("artifact_filename") != source_name or record.get("artifact_sha256") != source_sha:
                return False
            source_identity = manifest.get("source_commit", manifest.get("source_revision"))
            record_identity = record.get("source_commit", record.get("source_revision"))
            if record_identity != source_identity:
                return False
            if record.get("build_toolchain") != manifest.get("build_toolchain"):
                return False
            if not expected_toolchain_sha or record.get("build_toolchain_sha256") != expected_toolchain_sha:
                return False
            if record.get("upstream_provenance_verified") is True:
                return False
        else:
            expected_sha = checksums.get(platform_key)
            expected_asset = assets.get(platform_key)
            if "ARCHIVE_INTEGRITY_VERIFIED" not in claims or not expected_sha or not expected_asset:
                return False
            if record.get("artifact_sha256") != expected_sha or record.get("artifact_filename") != expected_asset:
                return False
        return True
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def build_direct_artifact_trust_record(
    tool_name: str,
    binary: str,
    *,
    installer_version: str,
) -> dict[str, Any]:
    """Create a managed record after the image builder verifies the release archive.

    The Docker builder performs the archive SHA-256 check before the executable is
    copied into the managed directory. This function binds that manifest entry to
    the exact executable bytes and emits only the claims supported by that check.
    """
    from app.installers.tool_manifest import PINNED_TOOL_MANIFEST

    manifest = PINNED_TOOL_MANIFEST.get(tool_name)
    if not isinstance(manifest, dict) or manifest.get("trust_mode") == "SOURCE_BUILD_MODE":
        raise ValueError("direct-artifact trust requires a direct-release manifest entry")
    path = Path(os.path.abspath(binary))
    managed_dir = get_managed_bin_dir()
    if managed_dir.is_symlink() or not _is_regular_non_symlink(path):
        raise ValueError("managed executable must be a regular file")
    if path.parent != managed_dir or path.name not in {tool_name, f"{tool_name}.exe"}:
        raise ValueError("executable is outside the managed tool directory")
    if os.name != "nt" and not os.access(path, os.X_OK):
        raise ValueError("managed executable is not executable")

    platform_name, architecture, platform_key = _platform_key()
    checksums = manifest.get("sha256_checksums")
    assets = manifest.get("asset_names")
    expected_sha = checksums.get(platform_key) if isinstance(checksums, dict) else None
    expected_asset = assets.get(platform_key) if isinstance(assets, dict) else None
    if not expected_sha or not expected_asset:
        raise ValueError("manifest has no platform-specific direct artifact identity")

    return {
        "tool_id": f"TOOL-{tool_name.upper()}",
        "tool_version": f"v{manifest['version']}",
        "artifact_filename": expected_asset,
        "artifact_sha256": expected_sha,
        "executable_relative_path": path.name,
        "executable_sha256": _sha256_file(path),
        "platform": platform_name,
        "architecture": architecture,
        "installer_version": installer_version,
        "trust_status": "VALID",
        "claims": ["ARCHIVE_INTEGRITY_VERIFIED", "EXECUTABLE_INTEGRITY_VERIFIED"],
    }


def write_direct_artifact_trust_record(
    tool_name: str,
    binary: str,
    *,
    installer_version: str,
) -> Path:
    """Atomically persist a direct-artifact trust record beside its executable."""
    record = build_direct_artifact_trust_record(
        tool_name,
        binary,
        installer_version=installer_version,
    )
    destination = Path(f"{os.path.abspath(binary)}.trust.json")
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    os.replace(temporary, destination)
    return destination


def build_source_artifact_trust_record(
    tool_name: str,
    binary: str,
    *,
    source_identity: str,
    build_toolchain_sha256: str,
    installer_version: str,
) -> dict[str, Any]:
    """Create a managed record for an explicitly approved verified source build."""
    from app.installers.tool_manifest import PINNED_TOOL_MANIFEST

    manifest = PINNED_TOOL_MANIFEST.get(tool_name)
    if not isinstance(manifest, dict) or manifest.get("trust_mode") != "SOURCE_BUILD_MODE":
        raise ValueError("source-build trust requires an approved source-build manifest entry")
    path = Path(os.path.abspath(binary))
    managed_dir = get_managed_bin_dir()
    if managed_dir.is_symlink() or not _is_regular_non_symlink(path):
        raise ValueError("managed executable must be a regular file")
    if path.parent != managed_dir or path.name not in {tool_name, f"{tool_name}.exe"}:
        raise ValueError("executable is outside the managed tool directory")
    if os.name != "nt" and not os.access(path, os.X_OK):
        raise ValueError("managed executable is not executable")
    platform_name, architecture, platform_key = _platform_key()
    checksums = manifest.get("sha256_checksums")
    assets = manifest.get("asset_names")
    if not isinstance(checksums, dict) or not isinstance(assets, dict):
        raise ValueError("source-build manifest is missing source identity")
    expected_toolchain = manifest.get("build_toolchain_sha256", {})
    if isinstance(expected_toolchain, dict):
        expected_toolchain = expected_toolchain.get(platform_key)
    else:
        expected_toolchain = checksums.get(f"go_{platform_key}")
    if (
        source_identity != manifest.get("source_commit", manifest.get("source_revision"))
        or not checksums.get("source_archive")
        or not assets.get("source_archive")
        or build_toolchain_sha256 != expected_toolchain
    ):
        raise ValueError("source-build identity does not match the manifest")
    record = {
        "tool_id": f"TOOL-{tool_name.upper()}",
        "tool_version": f"v{manifest['version']}",
        "artifact_filename": assets["source_archive"],
        "artifact_sha256": checksums["source_archive"],
        "executable_relative_path": path.name,
        "executable_sha256": _sha256_file(path),
        "platform": platform_name,
        "architecture": architecture,
        "installer_version": installer_version,
        "trust_status": "VALID",
        "claims": [
            "SOURCE_ARCHIVE_INTEGRITY_VERIFIED",
            "BUILD_TOOLCHAIN_INTEGRITY_VERIFIED",
            "EXECUTABLE_INTEGRITY_VERIFIED",
        ],
        "build_toolchain": manifest["build_toolchain"],
        "build_toolchain_sha256": build_toolchain_sha256,
        "upstream_provenance_verified": False,
    }
    identity_field = "source_commit" if "source_commit" in manifest else "source_revision"
    record[identity_field] = source_identity
    return record


def write_source_artifact_trust_record(
    tool_name: str,
    binary: str,
    *,
    source_identity: str,
    build_toolchain_sha256: str,
    installer_version: str,
) -> Path:
    """Atomically persist a source-build trust record beside its executable."""
    record = build_source_artifact_trust_record(
        tool_name,
        binary,
        source_identity=source_identity,
        build_toolchain_sha256=build_toolchain_sha256,
        installer_version=installer_version,
    )
    destination = Path(f"{os.path.abspath(binary)}.trust.json")
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    os.replace(temporary, destination)
    return destination
