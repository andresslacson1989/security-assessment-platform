"""Trust records and runtime verification for hash-locked Python tools.

The pip installer uses this module after a successful installation to bind the
approved lock file, the isolated virtual environment, the installed
distribution files, and the console executable into one durable identity.
Adapters use the same verifier immediately before process launch.

The record is intentionally treated as a local trust assertion, not as an
upstream provenance attestation.  Its claims are limited to what CyberAssess
can verify from the locked installation and the local filesystem.
"""

from __future__ import annotations

import base64
import binascii
import csv
from datetime import datetime, timezone
import hashlib
import importlib.metadata as metadata
import io
import json
import os
import re
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, Mapping, Optional

from packaging.markers import default_environment
from packaging.requirements import Requirement


PACKAGE_TRUST_SCHEMA_VERSION = 1
PACKAGE_TRUST_RECORD_SUFFIX = ".trust.json"
PACKAGE_TRUST_CLAIMS = frozenset(
    {
        "LOCKFILE_INTEGRITY_VERIFIED",
        "PACKAGE_DISTRIBUTION_INTEGRITY_VERIFIED",
        "EXECUTABLE_INTEGRITY_VERIFIED",
        "RUNTIME_VERSION_VERIFIED",
    }
)
_BOOTSTRAP_DISTRIBUTIONS = frozenset({"pip", "setuptools", "wheel"})
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_REQUIREMENT_PATTERN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s\\]+)")
_HASH_PATTERN = re.compile(r"^--hash=sha256:([0-9a-fA-F]{64})\s*(?:\\)?$")


class PackageTrustError(ValueError):
    """Raised when a managed package identity cannot be established."""


def canonical_package_name(name: str) -> str:
    """Return the PEP 503-normalized package name."""
    return re.sub(r"[-_.]+", "-", str(name).strip()).lower()


def get_tool_venv_root() -> Path:
    """Return the server-configured root for isolated tool environments."""
    configured = os.environ.get("CYBERASSESS_TOOL_VENV_DIR")
    default = Path(__file__).resolve().parents[2] / ".tool-venvs"
    return Path(configured).expanduser().resolve() if configured else default.resolve()


def get_tool_venv_dir(tool_name: str) -> Path:
    """Return the isolated environment directory for one canonical tool."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", str(tool_name)):
        raise PackageTrustError("invalid tool name")
    return (get_tool_venv_root() / str(tool_name)).resolve()


def get_lock_path(tool_name: str) -> Path:
    """Return the repository-controlled hash-locked requirements file."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", str(tool_name)):
        raise PackageTrustError("invalid tool name")
    return Path(__file__).resolve().parents[2] / "tool-requirements" / f"{tool_name}.lock"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_non_symlink_file(path: Path) -> bool:
    try:
        absolute = os.path.abspath(str(path))
        return path.is_file() and os.path.normcase(os.path.realpath(str(path))) == os.path.normcase(absolute)
    except OSError:
        return False


def _is_under(root: Path, candidate: Path) -> bool:
    try:
        return os.path.commonpath([os.path.normcase(str(root)), os.path.normcase(str(candidate))]) == os.path.normcase(str(root))
    except ValueError:
        return False


def _expected_binary_paths(venv_dir: Path, binary_name: str) -> tuple[Path, ...]:
    bin_dir = venv_dir / ("Scripts" if os.name == "nt" else "bin")
    # The extensionless form remains valid for POSIX and is accepted on
    # Windows only when it is the exact installer-selected path.
    return (bin_dir / f"{binary_name}.exe", bin_dir / binary_name)


def _expected_interpreter_path(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _validate_managed_binary_path(
    tool_name: str,
    binary_name: str,
    binary: str,
) -> tuple[Path, Path]:
    if not isinstance(binary, str) or not binary.strip() or "\x00" in binary:
        raise PackageTrustError("missing executable path")

    venv_dir = get_tool_venv_dir(tool_name)
    path = Path(os.path.abspath(binary))
    if not _is_non_symlink_file(path):
        raise PackageTrustError("managed executable is missing or is a symlink")
    if os.name != "nt" and not os.access(path, os.X_OK):
        raise PackageTrustError("managed executable is not executable")

    if not any(
        os.path.normcase(str(path)) == os.path.normcase(str(expected))
        for expected in _expected_binary_paths(venv_dir, binary_name)
    ):
        raise PackageTrustError("executable is outside its managed tool environment")
    if not _is_non_symlink_file(_expected_interpreter_path(venv_dir)):
        raise PackageTrustError("managed tool interpreter is missing or is a symlink")
    return venv_dir, path


def parse_locked_requirements(lock_path: Path) -> Dict[str, Dict[str, Any]]:
    """Parse a generated pip lock file into exact packages and SHA-256 pins."""
    if not _is_non_symlink_file(lock_path):
        raise PackageTrustError("hash-locked requirements file is missing or is a symlink")

    requirements: Dict[str, Dict[str, Any]] = {}
    current: Optional[Dict[str, Any]] = None
    ignored_requirement_hashes = False
    try:
        lines = lock_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise PackageTrustError("hash-locked requirements file cannot be read") from exc

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        requirement_text = line[:-1].rstrip() if line.endswith("\\") else line
        match = _REQUIREMENT_PATTERN.match(requirement_text)
        if match:
            canonical = canonical_package_name(match.group(1))
            try:
                parsed_requirement = Requirement(requirement_text)
            except (TypeError, ValueError) as exc:
                raise PackageTrustError("unsupported or malformed hash-locked requirement line") from exc
            if parsed_requirement.marker is not None and not parsed_requirement.marker.evaluate(default_environment()):
                current = None
                ignored_requirement_hashes = True
                continue
            if canonical in requirements:
                raise PackageTrustError("duplicate package in hash-locked requirements")
            current = {
                "name": match.group(1),
                "version": match.group(2),
                "hashes": [],
            }
            ignored_requirement_hashes = False
            requirements[canonical] = current
            continue
        hash_match = _HASH_PATTERN.match(line)
        if hash_match and current is not None:
            current["hashes"].append(hash_match.group(1).lower())
            continue
        if hash_match and ignored_requirement_hashes:
            continue
        raise PackageTrustError("unsupported or malformed hash-locked requirement line")

    if not requirements or any(not item["hashes"] for item in requirements.values()):
        raise PackageTrustError("every locked package must have at least one SHA-256 pin")
    return requirements


def _locked_package_snapshot(requirements: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "version": str(requirements[name]["version"]),
            "hashes": sorted({str(value).lower() for value in requirements[name]["hashes"]}),
        }
        for name in sorted(requirements)
    ]


def _distribution_search_paths(venv_dir: Path) -> list[Path]:
    candidates = [venv_dir / "Lib" / "site-packages"]
    lib_dir = venv_dir / "lib"
    if lib_dir.is_dir() and not lib_dir.is_symlink():
        try:
            candidates.extend(
                child / "site-packages"
                for child in sorted(lib_dir.iterdir(), key=lambda item: item.name)
                if child.is_dir() and not child.is_symlink() and child.name.startswith("python")
            )
        except OSError as exc:
            raise PackageTrustError("managed package environment cannot be enumerated") from exc
    candidates.append(venv_dir / "lib" / "site-packages")

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = os.path.normcase(os.path.abspath(str(candidate)))
        if key not in seen and candidate.is_dir() and not candidate.is_symlink():
            seen.add(key)
            unique.append(candidate)
    return unique


def _find_distributions(venv_dir: Path) -> Dict[str, metadata.Distribution]:
    paths = _distribution_search_paths(venv_dir)
    if not paths:
        raise PackageTrustError("managed package site-packages directory is missing")
    found: Dict[str, metadata.Distribution] = {}
    try:
        for distribution in metadata.distributions(path=[str(path) for path in paths]):
            name = distribution.metadata.get("Name")
            if not name:
                continue
            canonical = canonical_package_name(name)
            if canonical in found:
                raise PackageTrustError("duplicate managed package distribution")
            found[canonical] = distribution
    except PackageTrustError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise PackageTrustError("managed package metadata cannot be read") from exc
    return found


def _shared_record_digest_index(
    distributions: Mapping[str, metadata.Distribution],
    venv_dir: Path,
) -> Dict[str, frozenset[bytes]]:
    """Collect approved digests for files shared by multiple distributions."""
    digests: Dict[str, set[bytes]] = {}
    for distribution in distributions.values():
        record_path = _distribution_record_path(distribution)
        try:
            rows = list(csv.reader(io.StringIO(record_path.read_text(encoding="utf-8"), newline="")))
        except (OSError, UnicodeError, csv.Error) as exc:
            raise PackageTrustError("managed distribution RECORD is malformed") from exc
        for row in rows:
            if len(row) != 3 or not row[1] or not row[1].startswith("sha256="):
                continue
            relative = PurePosixPath(row[0].replace("\\", "/"))
            if relative.is_absolute() or not relative.parts:
                continue
            candidate = Path(distribution.locate_file(relative))
            resolved_candidate = Path(os.path.realpath(str(candidate)))
            if not _is_under(venv_dir, resolved_candidate) or not _is_non_symlink_file(candidate):
                continue
            digest = _decode_record_digest(row[1].split("=", 1)[1])
            key = os.path.normcase(str(Path(os.path.abspath(str(candidate)))))
            digests.setdefault(key, set()).add(digest)
    return {key: frozenset(values) for key, values in digests.items()}


def _distribution_record_path(distribution: metadata.Distribution) -> Path:
    files = distribution.files or []
    record_candidates = [
        file_entry
        for file_entry in files
        if PurePosixPath(str(file_entry).replace("\\", "/")).name == "RECORD"
    ]
    if len(record_candidates) != 1:
        raise PackageTrustError("managed distribution has no unique RECORD file")
    record_path = Path(distribution.locate_file(record_candidates[0]))
    if not _is_non_symlink_file(record_path):
        raise PackageTrustError("managed distribution RECORD is missing or is a symlink")
    return record_path


def _decode_record_digest(value: str) -> bytes:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(value + padding)
    except (binascii.Error, ValueError) as exc:
        raise PackageTrustError("managed distribution RECORD contains an invalid digest") from exc
    if len(decoded) != 32:
        raise PackageTrustError("managed distribution RECORD contains a non-SHA-256 digest")
    return decoded


def _verify_distribution_record(
    distribution: metadata.Distribution,
    venv_dir: Path,
    expected_record_sha256: Optional[str] = None,
    shared_digest_index: Optional[Mapping[str, frozenset[bytes]]] = None,
) -> str:
    """Verify every hashed file named by a distribution's RECORD."""
    record_path = _distribution_record_path(distribution)
    if not _is_under(venv_dir, Path(os.path.realpath(str(record_path)))):
        raise PackageTrustError("managed distribution RECORD escapes its virtual environment")
    try:
        record_bytes = record_path.read_bytes()
        record_text = record_bytes.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise PackageTrustError("managed distribution RECORD cannot be read") from exc

    record_sha256 = _sha256_bytes(record_bytes)
    if expected_record_sha256 and record_sha256 != expected_record_sha256.lower():
        raise PackageTrustError("managed distribution RECORD changed after installation")

    try:
        rows = list(csv.reader(io.StringIO(record_text, newline="")))
    except csv.Error as exc:
        raise PackageTrustError("managed distribution RECORD is malformed") from exc
    if not rows:
        raise PackageTrustError("managed distribution RECORD is empty")

    record_blank_digest_rows = 0
    for row in rows:
        if len(row) != 3:
            raise PackageTrustError("managed distribution RECORD has an invalid row")
        relative_text, digest_text, _size = row
        relative = PurePosixPath(relative_text.replace("\\", "/"))
        if relative.is_absolute() or not relative.parts:
            raise PackageTrustError("managed distribution RECORD contains an unsafe path")
        candidate = Path(distribution.locate_file(relative))
        absolute_candidate = Path(os.path.abspath(str(candidate)))
        resolved_candidate = Path(os.path.realpath(str(candidate)))
        if not _is_under(venv_dir, resolved_candidate) or not _is_non_symlink_file(candidate):
            raise PackageTrustError("managed distribution RECORD references an unsafe file")

        if not digest_text:
            if relative.name != "RECORD":
                if relative.suffix != ".pyc" or "__pycache__" not in relative.parts:
                    raise PackageTrustError("managed distribution RECORD omits a file digest")
            else:
                record_blank_digest_rows += 1
            continue
        if not digest_text.startswith("sha256="):
            raise PackageTrustError("managed distribution RECORD uses an unsupported digest algorithm")
        expected_digest = _decode_record_digest(digest_text.split("=", 1)[1])
        actual_digest = hashlib.sha256(absolute_candidate.read_bytes()).digest()
        accepted_shared_digests = (shared_digest_index or {}).get(
            os.path.normcase(str(absolute_candidate)),
            frozenset(),
        )
        if actual_digest != expected_digest and actual_digest not in accepted_shared_digests:
            raise PackageTrustError(
                f"managed distribution file integrity verification failed: {distribution.metadata.get('Name', 'unknown')}:{relative_text}"
            )

    if record_blank_digest_rows != 1:
        raise PackageTrustError("managed distribution RECORD must have exactly one unhashed RECORD entry")
    return record_sha256


def _manifest_package_hashes(tool_name: str) -> set[str]:
    from app.installers.tool_manifest import PINNED_TOOL_MANIFEST

    entry = PINNED_TOOL_MANIFEST.get(tool_name)
    if not isinstance(entry, dict) or entry.get("trust_mode") != "PACKAGE_MANAGER_MODE":
        raise PackageTrustError("tool has no package-manager trust manifest")
    checksums = entry.get("sha256_checksums")
    if not isinstance(checksums, dict):
        raise PackageTrustError("package-manager trust manifest has no SHA-256 pins")
    hashes = {
        str(value).lower()
        for key, value in checksums.items()
        if str(key).startswith("pypi_") and isinstance(value, str) and _SHA256_PATTERN.fullmatch(value.lower())
    }
    if not hashes:
        raise PackageTrustError("package-manager trust manifest has no valid PyPI SHA-256 pins")
    return hashes


def _validate_lock_against_manifest(tool_name: str, package_name: str, requirements: Mapping[str, Mapping[str, Any]]) -> None:
    canonical = canonical_package_name(package_name)
    package = requirements.get(canonical)
    if not package:
        raise PackageTrustError("the managed package is absent from its lock file")
    manifest_hashes = _manifest_package_hashes(tool_name)
    if not manifest_hashes.intersection(set(package["hashes"])):
        raise PackageTrustError("the managed package lock does not contain an authoritative manifest digest")
    from app.installers.tool_manifest import PINNED_TOOL_MANIFEST

    expected_version = str(PINNED_TOOL_MANIFEST[tool_name].get("version", ""))
    if str(package["version"]) != expected_version:
        raise PackageTrustError("the managed package lock version differs from the authoritative manifest")


def _distribution_inventory(
    tool_name: str,
    package_name: str,
    venv_dir: Path,
    requirements: Mapping[str, Mapping[str, Any]],
    expected_records: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> Dict[str, Dict[str, Any]]:
    distributions = _find_distributions(venv_dir)
    locked_names = set(requirements)
    managed_locked_names = locked_names - _BOOTSTRAP_DISTRIBUTIONS
    extras = set(distributions) - locked_names - _BOOTSTRAP_DISTRIBUTIONS
    if extras:
        raise PackageTrustError("managed package environment contains an unapproved distribution")

    locked_distributions = {
        canonical: distribution
        for canonical, distribution in distributions.items()
        if canonical in managed_locked_names
    }
    shared_digest_index = _shared_record_digest_index(locked_distributions, venv_dir)
    inventory: Dict[str, Dict[str, Any]] = {}
    for canonical in sorted(managed_locked_names):
        distribution = distributions.get(canonical)
        if distribution is None:
            raise PackageTrustError("a hash-locked package is not installed")
        expected_version = str(requirements[canonical]["version"])
        if str(distribution.version) != expected_version:
            raise PackageTrustError("installed package version differs from its lock file")
        expected = (expected_records or {}).get(canonical)
        expected_record_hash = expected.get("record_sha256") if expected else None
        record_sha256 = _verify_distribution_record(
            distribution,
            venv_dir,
            expected_record_hash,
            shared_digest_index,
        )
        inventory[canonical] = {
            "name": canonical,
            "version": str(distribution.version),
            "record_sha256": record_sha256,
        }
    if canonical_package_name(package_name) not in inventory:
        raise PackageTrustError("the managed executable package is not in the verified inventory")
    return inventory


def build_package_trust_record(
    *,
    tool_name: str,
    package_name: str,
    binary_name: str,
    binary: str,
    installer_version: str,
) -> dict[str, Any]:
    """Build a durable trust record after a verified pip installation."""
    venv_dir, binary_path = _validate_managed_binary_path(tool_name, binary_name, binary)
    lock_path = get_lock_path(tool_name)
    requirements = parse_locked_requirements(lock_path)
    _validate_lock_against_manifest(tool_name, package_name, requirements)
    inventory = _distribution_inventory(tool_name, package_name, venv_dir, requirements)

    from app.installers.tool_manifest import PINNED_TOOL_MANIFEST

    manifest = PINNED_TOOL_MANIFEST[tool_name]
    relative_executable = binary_path.relative_to(venv_dir).as_posix()
    record = {
        "schema_version": PACKAGE_TRUST_SCHEMA_VERSION,
        "tool_id": f"TOOL-{tool_name.upper()}",
        "tool_name": tool_name,
        "trust_mode": "PACKAGE_MANAGER_MODE",
        "install_method": "PIP",
        "package_name": package_name,
        "package_version": str(requirements[canonical_package_name(package_name)]["version"]),
        "lockfile": f"tool-requirements/{tool_name}.lock",
        "lockfile_sha256": sha256_file(lock_path),
        "locked_packages": _locked_package_snapshot(requirements),
        "distribution_records": inventory,
        "venv_relative_path": tool_name,
        "interpreter_relative_path": _expected_interpreter_path(venv_dir).relative_to(venv_dir).as_posix(),
        "executable_relative_path": relative_executable,
        "executable_sha256": sha256_file(binary_path),
        "tool_version": str(manifest["version"]),
        "installer_version": str(installer_version),
        "installed_at": datetime.now(timezone.utc).isoformat(),
        "trust_status": "VALID",
        "claims": sorted(PACKAGE_TRUST_CLAIMS),
        "provenance_claims": {"UPSTREAM_PROVENANCE_VERIFIED": False},
    }
    return record


def trust_record_path(binary: str) -> Path:
    if not isinstance(binary, str) or not binary.strip() or "\x00" in binary:
        raise PackageTrustError("invalid executable path")
    return Path(f"{os.path.abspath(binary)}{PACKAGE_TRUST_RECORD_SUFFIX}")


def write_package_trust_record(record: Mapping[str, Any], binary: str) -> Path:
    """Atomically write a validated local package trust record."""
    path = trust_record_path(binary)
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise PackageTrustError("trust record directory is missing or is a symlink")
    if path.exists() and path.is_symlink():
        raise PackageTrustError("existing trust record is a symlink")
    payload = json.dumps(dict(record), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(parent))
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
            directory_fd = os.open(str(parent), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except (OSError, ValueError) as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise PackageTrustError("package trust record could not be written") from exc
    return path


def invalidate_package_trust_record(binary: str) -> None:
    """Remove a stale local trust record before a reinstall or failed install."""
    path = trust_record_path(binary)
    if path.is_symlink():
        raise PackageTrustError("existing trust record is a symlink")
    if path.exists():
        path.unlink()


def verify_package_trust(
    *,
    tool_name: str,
    package_name: str,
    binary_name: str,
    approved_version: str,
    binary: str,
) -> bool:
    """Verify the exact package environment and executable used for launch."""
    try:
        venv_dir, binary_path = _validate_managed_binary_path(tool_name, binary_name, binary)
        lock_path = get_lock_path(tool_name)
        requirements = parse_locked_requirements(lock_path)
        _validate_lock_against_manifest(tool_name, package_name, requirements)
        trust_path = trust_record_path(str(binary_path))
        if not _is_non_symlink_file(trust_path) or trust_path.stat().st_size > 8 * 1024 * 1024:
            return False
        record = json.loads(trust_path.read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            return False

        expected_package = requirements[canonical_package_name(package_name)]
        expected_snapshot = _locked_package_snapshot(requirements)
        required_fields = {
            "schema_version",
            "tool_id",
            "tool_name",
            "trust_mode",
            "install_method",
            "package_name",
            "package_version",
            "lockfile",
            "lockfile_sha256",
            "locked_packages",
            "distribution_records",
            "venv_relative_path",
            "interpreter_relative_path",
            "executable_relative_path",
            "executable_sha256",
            "tool_version",
            "installer_version",
            "installed_at",
            "trust_status",
            "claims",
        }
        if not required_fields.issubset(record):
            return False
        if (
            record["schema_version"] != PACKAGE_TRUST_SCHEMA_VERSION
            or record["tool_id"] != f"TOOL-{tool_name.upper()}"
            or record["tool_name"] != tool_name
            or record["trust_mode"] != "PACKAGE_MANAGER_MODE"
            or record["install_method"] != "PIP"
            or canonical_package_name(record["package_name"]) != canonical_package_name(package_name)
            or str(record["package_version"]) != str(approved_version).lstrip("v")
            or record["tool_version"] != str(approved_version).lstrip("v")
            or record["lockfile"] != f"tool-requirements/{tool_name}.lock"
            or record["lockfile_sha256"] != sha256_file(lock_path)
            or record["locked_packages"] != expected_snapshot
            or record["venv_relative_path"] != tool_name
            or record["executable_relative_path"] != binary_path.relative_to(venv_dir).as_posix()
            or record["interpreter_relative_path"] != _expected_interpreter_path(venv_dir).relative_to(venv_dir).as_posix()
            or record["trust_status"] != "VALID"
            or not PACKAGE_TRUST_CLAIMS.issubset(set(record["claims"]))
            or not _SHA256_PATTERN.fullmatch(str(record["executable_sha256"]).lower())
        ):
            return False
        if str(record["executable_sha256"]).lower() != sha256_file(binary_path):
            return False

        expected_records = record["distribution_records"]
        if not isinstance(expected_records, dict):
            return False
        inventory = _distribution_inventory(
            tool_name,
            package_name,
            venv_dir,
            requirements,
            expected_records=expected_records,
        )
        if inventory != expected_records:
            return False
        return str(inventory[canonical_package_name(package_name)]["version"]) == str(expected_package["version"])
    except (
        OSError,
        UnicodeError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
        PackageTrustError,
    ):
        return False
