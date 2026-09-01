"""Assurance tests for hash-locked Python tool installation identity."""

import base64
import hashlib
import os
from pathlib import Path

from app.adapters.bandit_adapter import BanditAdapter
from app.core import package_trust
from app.core.package_trust import (
    build_package_trust_record,
    verify_package_trust,
    write_package_trust_record,
)
from app.installers.tool_manifest import PINNED_TOOL_MANIFEST


def _record_digest(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _create_fake_bandit_environment(tmp_path: Path, monkeypatch):
    venv_root = tmp_path / "tool-venvs"
    venv_dir = venv_root / "bandit"
    bin_dir = venv_dir / ("Scripts" if os.name == "nt" else "bin")
    site_packages = (
        venv_dir / "Lib" / "site-packages"
        if os.name == "nt"
        else venv_dir / "lib" / "python3.13" / "site-packages"
    )
    bin_dir.mkdir(parents=True)
    site_packages.mkdir(parents=True)
    monkeypatch.setenv("CYBERASSESS_TOOL_VENV_DIR", str(venv_root))

    interpreter = bin_dir / ("python.exe" if os.name == "nt" else "python")
    interpreter.write_bytes(b"managed interpreter")
    binary = bin_dir / ("bandit.exe" if os.name == "nt" else "bandit")
    binary.write_bytes(b"managed bandit executable")
    if os.name != "nt":
        binary.chmod(0o755)

    package_dir = site_packages / "bandit"
    package_dir.mkdir()
    package_file = package_dir / "__init__.py"
    package_file.write_bytes(b"__version__ = '1.7.8'\n")
    dist_info = site_packages / "bandit-1.7.8.dist-info"
    dist_info.mkdir()
    metadata_file = dist_info / "METADATA"
    metadata_file.write_text(
        "Metadata-Version: 2.1\nName: bandit\nVersion: 1.7.8\n",
        encoding="utf-8",
    )
    record_file = dist_info / "RECORD"
    record_file.write_text(
        "\n".join(
            [
                f"bandit/__init__.py,sha256={_record_digest(package_file)},{package_file.stat().st_size}",
                f"bandit-1.7.8.dist-info/METADATA,sha256={_record_digest(metadata_file)},{metadata_file.stat().st_size}",
                "bandit-1.7.8.dist-info/RECORD,,",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    lock_file = tmp_path / "bandit.lock"
    root_hash = PINNED_TOOL_MANIFEST["bandit"]["sha256_checksums"]["pypi_sdist"]
    lock_file.write_text(
        f"bandit==1.7.8 \\\n    --hash=sha256:{root_hash}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(package_trust, "get_lock_path", lambda _tool: lock_file)
    return binary, package_file


def test_package_trust_binds_lock_distribution_and_executable(tmp_path, monkeypatch):
    binary, package_file = _create_fake_bandit_environment(tmp_path, monkeypatch)

    record = build_package_trust_record(
        tool_name="bandit",
        package_name="bandit",
        binary_name="bandit",
        binary=str(binary),
        installer_version="14.3.0",
    )
    write_package_trust_record(record, str(binary))

    assert verify_package_trust(
        tool_name="bandit",
        package_name="bandit",
        binary_name="bandit",
        approved_version="1.7.8",
        binary=str(binary),
    ) is True

    package_file.write_bytes(b"tampered package code\n")
    assert BanditAdapter().verify_managed_binary(str(binary)) is False


def test_package_trust_rejects_missing_record_and_unapproved_path(tmp_path, monkeypatch):
    binary, _ = _create_fake_bandit_environment(tmp_path, monkeypatch)
    adapter = BanditAdapter()

    assert adapter.verify_managed_binary(str(binary)) is False
    assert adapter.verify_managed_binary(str(tmp_path / "bandit")) is False
