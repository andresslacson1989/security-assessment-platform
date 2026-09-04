"""
Contract 03 (Section 5) & Contract 08 (Section 9) Abstract In-App Tool Installer.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
from abc import ABC, abstractmethod
import os
import shutil
from typing import Callable, Awaitable, Optional, Iterable
from urllib.parse import urljoin, urlparse

from app.core.models import (
    ToolInstallMethod,
    ToolInstallStatus,
    ToolInstallationInfo,
)
from app.core.binary_resolver import resolve_tool_binary, get_default_bin_dir

LogCallback = Callable[[str], Awaitable[None]]
ProgressCallback = Callable[[int, str], Awaitable[None]]


class SecurityError(Exception):
    """Raised when an unsafe file or path traversal condition is detected."""
    pass


MAX_INSTALLER_REDIRECTS = 3


def resolve_allowed_https_redirect(
    current_url: str,
    location: str,
    allowed_hosts: Iterable[str],
) -> str:
    """Resolve one installer redirect and fail closed outside approved HTTPS hosts."""
    next_url = urljoin(current_url, location)
    parsed = urlparse(next_url)
    hosts = {str(host).lower().rstrip(".") for host in allowed_hosts}
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https" or parsed.port not in (None, 443) or hostname not in hosts:
        raise SecurityError(f"Installer redirect destination is not allowlisted: {next_url}")
    return next_url


class BaseToolInstaller(ABC):
    """
    Abstract contract for in-app tool installers.
    """

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Unique tool key: 'sslyze', 'bandit', 'semgrep', 'checkov', 'nuclei', 'ffuf', 'gitleaks', 'trivy', 'nmap', 'retire'."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable tool title."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Category label e.g. 'Network', 'Web DAST', 'Code SAST', 'Secrets', 'Infra IaC'."""
        pass

    @property
    @abstractmethod
    def install_method(self) -> ToolInstallMethod:
        """Installation classification."""
        pass

    @property
    def is_elevated_required(self) -> bool:
        """Whether tool installation requires sudo/admin elevation."""
        return False

    @property
    def install_command_hint(self) -> str:
        """Manual CLI instructions if in-app automation is unavailable."""
        return ""

    @property
    def download_url(self) -> Optional[str]:
        """Upstream download URL or official documentation link."""
        return None

    def get_bin_dir(self) -> str:
        """Returns the local user-space bin directory: backend/bin/."""
        return get_default_bin_dir()

    def is_assured_installation(self, path: Optional[str]) -> bool:
        """Return whether the resolved installation has a verified trust record.

        Registry metadata alone establishes eligibility, not trust in the
        executable currently present on disk. Installers that can verify a
        concrete installation override this hook; the fail-closed default
        prevents status reporting from overstating assurance.
        """
        return False

    def resolve_binary_path(self) -> Optional[str]:
        """
        Deterministic 5-Tier Binary Resolution Order:
        Tier 1: Explicit custom configured path (if applicable)
        Tier 2: In-App Managed Binaries directory ('backend/bin/<tool_name>[.exe|.bat|.cmd|.pl]')
        Tier 3: Active Python environment Scripts / bin directory (for pip-installed tools)
        Tier 4: System PATH discovery via shutil.which(tool_name)
        Tier 5: Platform-Specific Auto-Discovery (Windows Registry, multi-drive Program Files, package managers, Unix paths)
        """
        return resolve_tool_binary(
            tool_name=getattr(self, "_cfg", {}).get("binary_name") or self.tool_name,
            local_bin_dir=self.get_bin_dir(),
        )

    @abstractmethod
    async def get_version(self) -> Optional[str]:
        """Retrieves installed binary or package version string."""
        pass

    async def get_info(self) -> ToolInstallationInfo:
        """
        Gathers current installation information and status.
        """
        from app.installers.tool_manifest import audit_tool_manifest

        path = self.resolve_binary_path()
        version = await self.get_version() if (path and os.path.isfile(path)) else None
        is_installed = bool(path and os.path.isfile(path) and (version is not None or self.install_method != ToolInstallMethod.SYSTEM_PACKAGE_MANAGER))

        status = ToolInstallStatus.INSTALLED if is_installed else ToolInstallStatus.NOT_INSTALLED
        manifest_status = audit_tool_manifest([self.tool_name])
        if self.tool_name in manifest_status["assured"]:
            assurance_status = "ASSURED" if self.is_assured_installation(path) else "UNASSURED"
        elif self.tool_name in manifest_status["incomplete"]:
            assurance_status = "DELEGATED" if self.tool_name == "nmap" else "INCOMPLETE"
        elif self.tool_name in manifest_status["invalid"]:
            assurance_status = "INVALID"
        else:
            assurance_status = "UNREGISTERED"

        return ToolInstallationInfo(
            name=self.tool_name,
            display_name=self.display_name,
            category=self.category,
            install_method=self.install_method,
            status=status,
            version=version,
            path=path,
            is_elevated_required=self.is_elevated_required,
            install_command_hint=self.install_command_hint,
            download_url=self.download_url,
            error_message=None,
            progress_percent=100 if is_installed else 0,
            assurance_status=assurance_status,
        )

    @abstractmethod
    async def install(
        self,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        force: bool = False,
    ) -> bool:
        """
        Asynchronously provisions the tool with real-time log and progress callbacks.
        """
        pass
