"""Trust verification for managed npm tool installations.

Retire.js is the only current tool whose contract uses npm.  This module keeps
its package-manager execution path separate from Python package trust so a
global npm installation or PATH executable cannot satisfy the assured path.
The local trust record is an installation assertion; it does not claim
upstream provenance beyond the pinned npm tarball digest.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Mapping, Optional


NPM_TRUST_SCHEMA_VERSION = 1
NPM_TRUST_RECORD_SUFFIX = ".trust.json"
NPM_TRUST_CLAIMS = frozenset(
    {
        "NPM_TARBALL_INTEGRITY_VERIFIED",
        "PACKAGE_TREE_INTEGRITY_VERIFIED",
        "EXECUTABLE_INTEGRITY_VERIFIED",
        "RUNTIME_VERSION_VERIFIED",
    }
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TOOL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


class NpmTrustError(ValueError):
    """Raised when a managed npm identity cannot be established."""


def _validate_tool_name(tool_name: str) -> str:
    if not isinstance(tool_name, str) or not _TOOL_PATTERN.fullmatch(tool_name):
        raise NpmTrustError("invalid npm tool name")
    return tool_name


def get_npm_root() -> Path:
    configured = os.environ.get("CYBERASSESS_NPM_PREFIX_DIR")
    default = Path(__file__).resolve().parents[2] / ".tool-npm"
    return (Path(configured).expanduser() if configured else default).absolute()


def get_npm_prefix_dir(tool_name: str) -> Path:
    return (get_npm_root() / _validate_tool_name(tool_name)).absolute()


def _validate_prefix(prefix: Path) -> None:
    if prefix.is_symlink() or prefix.parent.is_symlink():
        raise NpmTrustError("managed npm prefix or its root is a symlink")


def npm_binary_candidates(tool_name: str, prefix: Optional[Path] = None) -> tuple[Path, ...]:
    prefix = prefix or get_npm_prefix_dir(tool_name)
    if os.name == "nt":
        return (
            prefix / "node_modules" / ".bin" / f"{tool_name}.cmd",
            prefix / "node_modules" / ".bin" / f"{tool_name}.exe",
            prefix / f"{tool_name}.cmd",
            prefix / f"{tool_name}.exe",
            prefix / tool_name,
        )
    return (
        prefix / "node_modules" / ".bin" / tool_name,
        prefix / "bin" / tool_name,
        prefix / tool_name,
    )


def resolve_npm_binary(tool_name: str) -> Optional[str]:
    for candidate in npm_binary_candidates(tool_name):
        if candidate.is_file():
            return str(candidate)
    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest(tool_name: str) -> Mapping[str, Any]:
    from app.installers.tool_manifest import PINNED_TOOL_MANIFEST

    entry = PINNED_TOOL_MANIFEST.get(tool_name)
    if not isinstance(entry, dict) or entry.get("trust_mode") != "PACKAGE_MANAGER_MODE":
        raise NpmTrustError("tool has no package-manager trust manifest")
    if entry.get("repo") != "npm:retire":
        raise NpmTrustError("tool is not an approved npm package")
    return entry


def _expected_tarball(entry: Mapping[str, Any]) -> tuple[str, str]:
    checksums = entry.get("sha256_checksums")
    names = entry.get("asset_names")
    if not isinstance(checksums, dict) or not isinstance(names, dict):
        raise NpmTrustError("npm manifest is missing tarball identity")
    digest = checksums.get("npm_tarball")
    filename = names.get("npm_tarball")
    if not isinstance(digest, str) or not _SHA256_PATTERN.fullmatch(digest.lower()):
        raise NpmTrustError("npm manifest has an invalid tarball digest")
    if not isinstance(filename, str) or Path(filename).name != filename or not filename.endswith(".tgz"):
        raise NpmTrustError("npm manifest has an invalid tarball filename")
    return filename, digest.lower()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _file_inventory(prefix: Path, binary: Path) -> dict[str, str]:
    """Hash installed package files while excluding npm's symlink bin farm."""
    node_modules = prefix / "node_modules"
    if not node_modules.is_dir() or node_modules.is_symlink():
        raise NpmTrustError("managed npm node_modules directory is missing or is a symlink")
    inventory: dict[str, str] = {}
    trust_sidecar = Path(f"{binary}{NPM_TRUST_RECORD_SUFFIX}")
    for path in sorted(node_modules.rglob("*")):
        if path.is_dir():
            if path.is_symlink():
                raise NpmTrustError("managed npm package directory is a symlink")
            continue
        if path.is_symlink():
            # npm's .bin directory is a generated launcher farm.  The
            # selected Retire launcher is bound separately below; all other
            # links are rejected so dependency code cannot escape the prefix.
            if ".bin" in path.relative_to(node_modules).parts:
                continue
            raise NpmTrustError("managed npm package file is a symlink")
        if path == binary or path == trust_sidecar:
            continue
        relative = path.relative_to(prefix).as_posix()
        inventory[relative] = _sha256_file(path)
    if not inventory:
        raise NpmTrustError("managed npm package tree is empty")
    return inventory


def _package_identity(prefix: Path, binary: Path) -> tuple[dict[str, str], str, str]:
    package_dir = prefix / "node_modules" / "retire"
    package_json = package_dir / "package.json"
    if not package_json.is_file() or package_json.is_symlink():
        raise NpmTrustError("managed Retire package metadata is missing")
    try:
        metadata = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NpmTrustError("managed Retire package metadata is invalid") from exc
    if not isinstance(metadata, dict) or metadata.get("name") != "retire":
        raise NpmTrustError("managed npm package name is invalid")
    version = str(metadata.get("version", ""))
    if not version:
        raise NpmTrustError("managed npm package version is missing")

    lockfile = prefix / "package-lock.json"
    if not lockfile.is_file() or lockfile.is_symlink():
        raise NpmTrustError("managed npm package-lock.json is missing")
    lock_hash = _sha256_file(lockfile)
    inventory = _file_inventory(prefix, binary)
    return inventory, lock_hash, version


def _executable_identity(prefix: Path, binary: Path) -> tuple[str, Optional[str]]:
    if not binary.is_file():
        raise NpmTrustError("managed npm executable is missing")
    if not _inside(binary, prefix):
        raise NpmTrustError("managed npm executable is outside its prefix")
    if binary.is_symlink():
        target = binary.resolve()
        if not _inside(target, prefix) or target.is_symlink() or not target.is_file():
            raise NpmTrustError("managed npm launcher resolves outside its prefix")
        return _sha256_file(target), target.relative_to(prefix).as_posix()
    return _sha256_file(binary), None


def build_npm_trust_record(
    *,
    tool_name: str,
    binary: str,
    installer_version: str,
    runtime_version_verified: bool = True,
) -> dict[str, Any]:
    prefix = get_npm_prefix_dir(tool_name)
    _validate_prefix(prefix)
    binary_path = Path(binary).absolute()
    if not _inside(binary_path, prefix):
        raise NpmTrustError("managed npm executable is outside its prefix")
    entry = _manifest(tool_name)
    expected_filename, expected_tarball_sha = _expected_tarball(entry)
    inventory, lock_hash, package_version = _package_identity(prefix, binary_path)
    executable_sha, target_relative = _executable_identity(prefix, binary_path)
    if package_version != str(entry.get("version")):
        raise NpmTrustError("managed npm package version differs from manifest")
    record = {
        "schema_version": NPM_TRUST_SCHEMA_VERSION,
        "tool_id": f"TOOL-{tool_name.upper()}",
        "tool_name": tool_name,
        "trust_mode": "PACKAGE_MANAGER_MODE",
        "install_method": "NPM",
        "package_name": "retire",
        "package_version": package_version,
        "prefix_relative_path": tool_name,
        "executable_relative_path": binary_path.relative_to(prefix).as_posix(),
        "executable_target_relative_path": target_relative,
        "executable_sha256": executable_sha,
        "package_files": inventory,
        "package_lock_sha256": lock_hash,
        "npm_tarball_filename": expected_filename,
        "npm_tarball_sha256": expected_tarball_sha,
        "tool_version": str(entry["version"]),
        "installer_version": str(installer_version),
        "installed_at": datetime.now(timezone.utc).isoformat(),
        "trust_status": "VALID",
        "claims": sorted(NPM_TRUST_CLAIMS if runtime_version_verified else NPM_TRUST_CLAIMS - {"RUNTIME_VERSION_VERIFIED"}),
        "provenance_claims": {"UPSTREAM_PROVENANCE_VERIFIED": False},
    }
    return record


def trust_record_path(binary: str) -> Path:
    if not isinstance(binary, str) or not binary.strip() or "\x00" in binary:
        raise NpmTrustError("invalid executable path")
    return Path(f"{os.path.abspath(binary)}{NPM_TRUST_RECORD_SUFFIX}")


def write_npm_trust_record(record: Mapping[str, Any], binary: str) -> Path:
    path = trust_record_path(binary)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise NpmTrustError("trust record directory is missing or is a symlink")
    if path.exists() and path.is_symlink():
        raise NpmTrustError("existing npm trust record is a symlink")
    payload = json.dumps(dict(record), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(str(temporary), str(path))
        if hasattr(os, "O_DIRECTORY"):
            directory_fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except (OSError, ValueError) as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise NpmTrustError("npm trust record could not be written") from exc
    return path


def invalidate_npm_trust_record(binary: str) -> None:
    path = trust_record_path(binary)
    if path.is_symlink():
        raise NpmTrustError("existing npm trust record is a symlink")
    if path.exists():
        path.unlink()


def verify_npm_trust(*, tool_name: str, binary: str, approved_version: str) -> bool:
    try:
        prefix = get_npm_prefix_dir(tool_name)
        _validate_prefix(prefix)
        binary_path = Path(binary).absolute()
        if not _inside(binary_path, prefix):
            return False
        entry = _manifest(tool_name)
        expected_filename, expected_tarball_sha = _expected_tarball(entry)
        record_path = trust_record_path(str(binary_path))
        if not record_path.is_file() or record_path.is_symlink() or record_path.stat().st_size > 8 * 1024 * 1024:
            return False
        record = json.loads(record_path.read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            return False
        required = {
            "schema_version", "tool_id", "tool_name", "trust_mode", "install_method",
            "package_name", "package_version", "prefix_relative_path", "executable_relative_path",
            "executable_target_relative_path", "executable_sha256", "package_files", "package_lock_sha256",
            "npm_tarball_filename", "npm_tarball_sha256", "tool_version", "installer_version",
            "installed_at", "trust_status", "claims", "provenance_claims",
        }
        if not required.issubset(record):
            return False
        if (
            record["schema_version"] != NPM_TRUST_SCHEMA_VERSION
            or record["tool_id"] != f"TOOL-{tool_name.upper()}"
            or record["tool_name"] != tool_name
            or record["trust_mode"] != "PACKAGE_MANAGER_MODE"
            or record["install_method"] != "NPM"
            or record["package_name"] != "retire"
            or str(record["package_version"]) != str(approved_version).lstrip("v")
            or record["tool_version"] != str(approved_version).lstrip("v")
            or record["prefix_relative_path"] != tool_name
            or record["executable_relative_path"] != binary_path.relative_to(prefix).as_posix()
            or record["npm_tarball_filename"] != expected_filename
            or str(record["npm_tarball_sha256"]).lower() != expected_tarball_sha
            or record["trust_status"] != "VALID"
            or not NPM_TRUST_CLAIMS.issubset(set(record["claims"]))
            or record["provenance_claims"] != {"UPSTREAM_PROVENANCE_VERIFIED": False}
            or not _SHA256_PATTERN.fullmatch(str(record["executable_sha256"]).lower())
        ):
            return False
        target = binary_path.resolve() if binary_path.is_symlink() else binary_path
        recorded_target = record["executable_target_relative_path"]
        actual_target = target.relative_to(prefix).as_posix() if binary_path.is_symlink() else None
        if actual_target != recorded_target:
            return False
        if str(record["executable_sha256"]).lower() != _sha256_file(target):
            return False
        inventory, lock_hash, package_version = _package_identity(prefix, binary_path)
        if package_version != str(approved_version).lstrip("v") or lock_hash != record["package_lock_sha256"]:
            return False
        if inventory != record["package_files"]:
            return False
        return True
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, json.JSONDecodeError, NpmTrustError):
        return False
