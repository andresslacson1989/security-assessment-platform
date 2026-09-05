"""Managed npm installer for the contract-approved Retire.js package."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import shutil
import tempfile
from typing import Optional

from app.core.models import ToolInstallMethod
from app.core.npm_trust import (
    NpmTrustError,
    build_npm_trust_record,
    get_npm_prefix_dir,
    invalidate_npm_trust_record,
    npm_binary_candidates,
    resolve_npm_binary,
    verify_npm_trust,
    write_npm_trust_record,
)
from app.core.process_supervisor import process_supervisor
from app.core.execution_context import issue_non_scan_execution_context
from app.core.version import APP_VERSION
from app.installers.base_installer import BaseToolInstaller, LogCallback, ProgressCallback
from app.installers.tool_manifest import PINNED_TOOL_MANIFEST, verify_download_integrity


NPM_TOOL_CONFIGS = {
    "retire": {
        "display_name": "Retire.js Client-Side JavaScript CVE Auditor",
        "category": "Code SAST",
        "package_name": "retire",
        "binary_name": "retire",
        "pinned_version": "4.4.3",
    }
}


class NpmToolInstaller(BaseToolInstaller):
    """Install a pinned npm package into a server-managed prefix."""

    def __init__(self, tool_name: str):
        if tool_name not in NPM_TOOL_CONFIGS:
            raise ValueError(f"Unknown NpmToolInstaller target: {tool_name}")
        self._tool_name = tool_name
        self._cfg = NPM_TOOL_CONFIGS[tool_name]

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
        return ToolInstallMethod.SYSTEM_PACKAGE_MANAGER

    @property
    def is_elevated_required(self) -> bool:
        return False

    @property
    def install_command_hint(self) -> str:
        return "npm install --ignore-scripts --prefix <managed-prefix> retire@4.4.3"

    @property
    def download_url(self) -> Optional[str]:
        return "https://registry.npmjs.org/retire/-/retire-4.4.3.tgz"

    def resolve_binary_path(self) -> Optional[str]:
        return resolve_npm_binary(self.tool_name) or super().resolve_binary_path()

    def is_assured_installation(self, path: Optional[str]) -> bool:
        return bool(path and verify_npm_trust(tool_name=self.tool_name, binary=path, approved_version=self._cfg["pinned_version"]))

    async def get_version(self) -> Optional[str]:
        path = self.resolve_binary_path()
        if not path:
            return None
        try:
            code, stdout, stderr = await process_supervisor.execute(
                [path, "--version"], timeout=5.0, max_output_bytes=1024 * 1024,
                non_scan_context=issue_non_scan_execution_context(f"installer:{self.tool_name}:version"),
            )
            if code == 0:
                output = (stdout or stderr or "").strip()
                if output:
                    return output.splitlines()[0]
        except Exception:
            return None
        return None

    @staticmethod
    def _npm_environment(config_path: Path) -> dict[str, str]:
        return {
            "NPM_CONFIG_USERCONFIG": str(config_path),
            "NPM_CONFIG_REGISTRY": "https://registry.npmjs.org/",
            "NPM_CONFIG_STRICT_SSL": "true",
            "NPM_CONFIG_IGNORE_SCRIPTS": "true",
            "NPM_CONFIG_AUDIT": "false",
            "NPM_CONFIG_FUND": "false",
            "NPM_CONFIG_UPDATE_NOTIFIER": "false",
        }

    async def install(self, emit_log: LogCallback, emit_progress: ProgressCallback, force: bool = False) -> bool:
        existing_path = self.resolve_binary_path()
        if not force and existing_path and self.is_assured_installation(existing_path):
            ver = await self.get_version()
            msg = f"{self.display_name} is already installed and verified."
            await emit_progress(100, msg)
            await emit_log(f"{self.display_name} is already installed and cryptographically assured ({ver or 'verified'}).")
            return True

        manifest = PINNED_TOOL_MANIFEST[self.tool_name]
        expected_version = self._cfg["pinned_version"]
        prefix = get_npm_prefix_dir(self.tool_name)
        root = prefix.parent
        if root.is_symlink():
            await emit_log("Retire.js installation rejected: managed npm root is a symlink.")
            await emit_progress(100, "Managed npm root validation failed")
            return False
        root.mkdir(parents=True, exist_ok=True)
        old_binary = resolve_npm_binary(self.tool_name)
        if old_binary:
            try:
                invalidate_npm_trust_record(old_binary)
            except (OSError, NpmTrustError) as exc:
                await emit_log(f"Retire.js installation rejected: trust invalidation failed ({type(exc).__name__}).")
                await emit_progress(100, "Trust state invalidation failed for Retire.js")
                return False

        staging = Path(tempfile.mkdtemp(prefix=".retire-staging-", dir=str(root)))
        temp_prefix = Path(tempfile.mkdtemp(prefix=".retire-prefix-", dir=str(root)))
        config_path = staging / "npmrc"
        config_path.write_text(
            "registry=https://registry.npmjs.org/\nstrict-ssl=true\nignore-scripts=true\naudit=false\nfund=false\n",
            encoding="utf-8",
        )
        try:
            await emit_progress(10, "Downloading the pinned Retire.js npm tarball...")
            pack_code, pack_out, pack_err = await process_supervisor.execute(
                ["npm", "pack", f"retire@{expected_version}", "--pack-destination", str(staging)],
                timeout=120.0,
                max_output_bytes=10 * 1024 * 1024,
                env=self._npm_environment(config_path),
                non_scan_context=issue_non_scan_execution_context(f"installer:{self.tool_name}:package-manager"),
            )
            if pack_code != 0:
                await emit_log(f"Retire.js npm download failed with exit code {pack_code}: {pack_err}")
                return False
            tarball = staging / manifest["asset_names"]["npm_tarball"]
            if not tarball.is_file():
                await emit_log("Retire.js installation rejected: npm did not produce the pinned tarball filename.")
                return False
            valid, actual_hash, error = verify_download_integrity(
                self.tool_name, tarball.read_bytes(), platform_key="npm_tarball"
            )
            if not valid:
                await emit_log(f"Retire.js tarball integrity verification failed: {error}")
                return False
            await emit_log(f"Verified Retire.js npm tarball SHA-256: {actual_hash}")

            await emit_progress(35, "Installing Retire.js into the managed npm prefix...")
            install_code, install_out, install_err = await process_supervisor.execute(
                ["npm", "install", "--prefix", str(temp_prefix), "--ignore-scripts", "--no-audit", "--no-fund", str(tarball)],
                timeout=600.0,
                max_output_bytes=10 * 1024 * 1024,
                env=self._npm_environment(config_path),
                non_scan_context=issue_non_scan_execution_context(f"installer:{self.tool_name}:install"),
            )
            if install_code != 0:
                await emit_log(f"Retire.js npm installation failed with exit code {install_code}: {install_err}")
                return False
            candidates = npm_binary_candidates(self.tool_name, temp_prefix)
            staged_binary_path = next((candidate for candidate in candidates if candidate.is_file()), None)
            if staged_binary_path is None:
                await emit_log("Retire.js installation rejected: managed npm executable was not created.")
                return False

            # Verify the staged tree before it becomes the active prefix.
            from app.core import npm_trust
            original_prefix = npm_trust.get_npm_prefix_dir
            npm_trust.get_npm_prefix_dir = lambda _tool: temp_prefix
            try:
                record = build_npm_trust_record(
                    tool_name=self.tool_name,
                    binary=str(staged_binary_path),
                    installer_version=APP_VERSION,
                )
            finally:
                npm_trust.get_npm_prefix_dir = original_prefix

            if prefix.exists() or prefix.is_symlink():
                if prefix.is_symlink() or not prefix.is_dir():
                    await emit_log("Retire.js installation rejected: managed prefix is not a normal directory.")
                    return False
                shutil.rmtree(prefix)
            os.replace(str(temp_prefix), str(prefix))
            active_binary = resolve_npm_binary(self.tool_name)
            if not active_binary:
                await emit_log("Retire.js installation rejected: active managed executable disappeared.")
                return False
            record["executable_relative_path"] = Path(active_binary).relative_to(prefix).as_posix()
            write_npm_trust_record(record, active_binary)
            if not verify_npm_trust(tool_name=self.tool_name, binary=active_binary, approved_version=expected_version):
                invalidate_npm_trust_record(active_binary)
                await emit_log("Retire.js installation rejected: final trust verification failed.")
                return False
            await emit_progress(100, f"Successfully installed Retire.js {expected_version}")
            return True
        except asyncio.CancelledError:
            raise
        except (OSError, NpmTrustError, ValueError) as exc:
            await emit_log(f"Retire.js installation rejected: {type(exc).__name__}.")
            return False
        finally:
            shutil.rmtree(staging, ignore_errors=True)
            if temp_prefix.exists():
                shutil.rmtree(temp_prefix, ignore_errors=True)
