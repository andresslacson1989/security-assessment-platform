"""
Contract 03 & 08 In-App Tool Installers Package.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from app.installers.base_installer import BaseToolInstaller, SecurityError
from app.installers.pip_installer import PipToolInstaller
from app.installers.github_release_installer import GithubReleaseInstaller
from app.installers.system_installer import SystemToolHelper
from app.installers.manager import ToolInstallationManager

__all__ = [
    "BaseToolInstaller",
    "SecurityError",
    "PipToolInstaller",
    "GithubReleaseInstaller",
    "SystemToolHelper",
    "ToolInstallationManager",
]
