"""Assurance tests for the managed Retire.js npm installation boundary."""

import hashlib
import json
import os
from pathlib import Path

from app.core import npm_trust
from app.core.npm_trust import (
    build_npm_trust_record,
    verify_npm_trust,
    write_npm_trust_record,
)
from app.adapters.retirejs_adapter import RetireJSAdapter
from app.core.process_supervisor import process_supervisor
from app.installers.npm_installer import NpmToolInstaller


def _create_fake_retire_prefix(tmp_path: Path, monkeypatch):
    prefix = tmp_path / "retire"
    package_dir = prefix / "node_modules" / "retire"
    package_dir.mkdir(parents=True)
    package_json = package_dir / "package.json"
    package_json.write_text(
        json.dumps({"name": "retire", "version": "4.4.3", "bin": {"retire": "bin/retire.js"}}),
        encoding="utf-8",
    )
    (package_dir / "bin").mkdir()
    package_script = package_dir / "bin" / "retire.js"
    package_script.write_text("#!/usr/bin/env node\nconsole.log('retire');\n", encoding="utf-8")
    dependency_dir = prefix / "node_modules" / "walkdir"
    dependency_dir.mkdir()
    (dependency_dir / "package.json").write_text(
        json.dumps({"name": "walkdir", "version": "0.4.1"}), encoding="utf-8"
    )
    (dependency_dir / "index.js").write_text("module.exports = {};\n", encoding="utf-8")
    (prefix / "package-lock.json").write_text(
        json.dumps({"name": "retire", "lockfileVersion": 3, "packages": {"": {"dependencies": {}}}}),
        encoding="utf-8",
    )
    if os.name == "nt":
        binary = prefix / "retire.cmd"
        binary.write_text("@echo off\nnode node_modules\\retire\\bin\\retire.js %*\n", encoding="utf-8")
    else:
        (prefix / "bin").mkdir()
        binary = prefix / "bin" / "retire"
        binary.write_text("#!/bin/sh\nexec node node_modules/retire/bin/retire.js \"$@\"\n", encoding="utf-8")
        binary.chmod(0o755)
    monkeypatch.setattr(npm_trust, "get_npm_prefix_dir", lambda _tool: prefix)
    return prefix, binary, package_script


def test_npm_trust_binds_tarball_package_tree_and_executable(tmp_path, monkeypatch):
    prefix, binary, package_script = _create_fake_retire_prefix(tmp_path, monkeypatch)

    record = build_npm_trust_record(
        tool_name="retire",
        binary=str(binary),
        installer_version="14.3.0",
    )
    write_npm_trust_record(record, str(binary))

    assert verify_npm_trust(tool_name="retire", binary=str(binary), approved_version="4.4.3") is True
    package_script.write_text("#!/usr/bin/env node\nconsole.log('tampered');\n", encoding="utf-8")
    assert RetireJSAdapter().verify_managed_binary(str(binary)) is False


def test_npm_trust_rejects_unmanaged_path_and_tampered_lockfile(tmp_path, monkeypatch):
    prefix, binary, _ = _create_fake_retire_prefix(tmp_path, monkeypatch)
    record = build_npm_trust_record(tool_name="retire", binary=str(binary), installer_version="14.3.0")
    write_npm_trust_record(record, str(binary))

    unmanaged = tmp_path / "unmanaged-retire"
    unmanaged.write_bytes(b"retire 4.4.3")
    assert verify_npm_trust(tool_name="retire", binary=str(unmanaged), approved_version="4.4.3") is False

    lockfile = prefix / "package-lock.json"
    lockfile.write_text(lockfile.read_text(encoding="utf-8") + "tampered", encoding="utf-8")
    assert verify_npm_trust(tool_name="retire", binary=str(binary), approved_version="4.4.3") is False


def test_retire_adapter_prefers_managed_npm_binary(tmp_path, monkeypatch):
    _, binary, _ = _create_fake_retire_prefix(tmp_path, monkeypatch)
    adapter = RetireJSAdapter()
    assert Path(adapter.resolve_binary_path()) == binary


def test_npm_installer_verifies_tarball_before_managed_install(tmp_path, monkeypatch):
    npm_root = tmp_path / "npm-root"
    monkeypatch.setenv("CYBERASSESS_NPM_PREFIX_DIR", str(npm_root))
    monkeypatch.setenv("NPM_CONFIG_REGISTRY", "https://attacker.invalid/")
    monkeypatch.setenv("NODE_OPTIONS", "--require attacker.js")
    captured = []

    async def fake_execute(cmd, **kwargs):
        captured.append((cmd, kwargs))
        if cmd[1] == "pack":
            destination = Path(cmd[cmd.index("--pack-destination") + 1])
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "retire-4.4.3.tgz").write_bytes(b"verified fixture tarball")
            return 0, "retire-4.4.3.tgz", ""
        assert cmd[1] == "install"
        prefix = Path(cmd[cmd.index("--prefix") + 1])
        package_dir = prefix / "node_modules" / "retire"
        package_dir.mkdir(parents=True)
        (package_dir / "package.json").write_text(
            json.dumps({"name": "retire", "version": "4.4.3"}), encoding="utf-8"
        )
        (package_dir / "index.js").write_text("module.exports = {};\n", encoding="utf-8")
        dependency_dir = prefix / "node_modules" / "walkdir"
        dependency_dir.mkdir()
        (dependency_dir / "package.json").write_text(
            json.dumps({"name": "walkdir", "version": "0.4.1"}), encoding="utf-8"
        )
        (dependency_dir / "index.js").write_text("module.exports = {};\n", encoding="utf-8")
        (prefix / "package-lock.json").write_text(json.dumps({"name": "retire", "lockfileVersion": 3}), encoding="utf-8")
        binary = prefix / "node_modules" / ".bin" / ("retire.cmd" if os.name == "nt" else "retire")
        binary.parent.mkdir(parents=True)
        binary.write_text("managed retire launcher\n", encoding="utf-8")
        if os.name != "nt":
            binary.chmod(0o755)
        return 0, "", ""

    monkeypatch.setattr(process_supervisor, "execute", fake_execute)
    monkeypatch.setattr(
        "app.installers.npm_installer.verify_download_integrity",
        lambda *args, **kwargs: (True, "1" * 64, None),
    )
    logs = []

    async def emit_log(_message):
        logs.append(_message)
        return None

    async def emit_progress(_percent, _stage):
        return None

    import asyncio
    assert asyncio.run(NpmToolInstaller("retire").install(emit_log, emit_progress)), logs
    assert len(captured) == 2
    assert captured[0][0][0:2] == ["npm", "pack"]
    assert captured[1][0][0:2] == ["npm", "install"]
    install_env = captured[1][1]["env"]
    assert install_env["NPM_CONFIG_REGISTRY"] == "https://registry.npmjs.org/"
    assert "NODE_OPTIONS" not in install_env
    assert "NODE_PATH" not in install_env
    active = npm_root / "retire" / "node_modules" / ".bin" / ("retire.cmd" if os.name == "nt" else "retire")
    assert verify_npm_trust(tool_name="retire", binary=str(active), approved_version="4.4.3") is True
