"""
Contract 03 (Section 4) Pluggable External Security Tool Adapters Registry.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import platform
from typing import Optional, Dict, List

from app.core.models import (
    ToolAdapterConfig,
    ToolStatus,
    ToolExecutionMode,
    SystemCapabilities,
    ToolInstallMethod,
    ToolInstallStatus,
)
from app.adapters.base_adapter import BaseToolAdapter
from app.adapters.nmap_adapter import NmapAdapter
from app.adapters.sslyze_adapter import SslyzeAdapter
from app.adapters.nuclei_adapter import NucleiAdapter
from app.adapters.ffuf_adapter import FfufAdapter
from app.adapters.nikto_adapter import NiktoAdapter
from app.adapters.semgrep_adapter import SemgrepAdapter
from app.adapters.gitleaks_adapter import GitleaksAdapter
from app.adapters.bandit_adapter import BanditAdapter
from app.adapters.trivy_adapter import TrivyAdapter
from app.adapters.checkov_adapter import CheckovAdapter


__all__ = [
    "BaseToolAdapter",
    "NmapAdapter",
    "SslyzeAdapter",
    "NucleiAdapter",
    "FfufAdapter",
    "NiktoAdapter",
    "SemgrepAdapter",
    "GitleaksAdapter",
    "BanditAdapter",
    "TrivyAdapter",
    "CheckovAdapter",
    "get_adapter_registry",
    "discover_system_capabilities",
]


def get_adapter_registry() -> Dict[str, BaseToolAdapter]:
    """
    Returns an initialized registry of all 10 available tool adapter instances.
    """
    return {
        "nmap": NmapAdapter(),
        "sslyze": SslyzeAdapter(),
        "nuclei": NucleiAdapter(),
        "ffuf": FfufAdapter(),
        "nikto": NiktoAdapter(),
        "semgrep": SemgrepAdapter(),
        "gitleaks": GitleaksAdapter(),
        "bandit": BanditAdapter(),
        "trivy": TrivyAdapter(),
        "checkov": CheckovAdapter(),
    }


async def discover_system_capabilities(
    config: Optional[ToolAdapterConfig] = None,
) -> SystemCapabilities:
    """
    Discovers installed CLI tools on the host system across all 10 adapters,
    inspects their versions and paths, and returns the structured SystemCapabilities model.
    """
    cfg = config or ToolAdapterConfig()
    registry = get_adapter_registry()
    tool_statuses: List[ToolStatus] = []

    # Map tool name to its enable flag and custom path configuration
    adapter_configs = {
        "nmap": (cfg.enable_nmap, cfg.nmap_path or cfg.custom_nmap_path),
        "sslyze": (cfg.enable_sslyze, cfg.sslyze_path or cfg.custom_sslyze_path),
        "nuclei": (cfg.enable_nuclei, cfg.nuclei_path or cfg.custom_nuclei_path),
        "ffuf": (cfg.enable_ffuf, cfg.ffuf_path or cfg.custom_ffuf_path),
        "nikto": (cfg.enable_nikto, cfg.nikto_path or cfg.custom_nikto_path),
        "semgrep": (cfg.enable_semgrep, cfg.semgrep_path or cfg.custom_semgrep_path),
        "gitleaks": (cfg.enable_gitleaks, cfg.gitleaks_path or cfg.custom_gitleaks_path),
        "bandit": (cfg.enable_bandit, cfg.bandit_path or cfg.custom_bandit_path),
        "trivy": (cfg.enable_trivy, cfg.trivy_path or cfg.custom_trivy_path),
        "checkov": (cfg.enable_checkov, cfg.checkov_path or cfg.custom_checkov_path),
    }

    # Tool install methods mapping
    tool_install_methods = {
        "sslyze": ToolInstallMethod.PIP,
        "bandit": ToolInstallMethod.PIP,
        "semgrep": ToolInstallMethod.PIP,
        "checkov": ToolInstallMethod.PIP,
        "nuclei": ToolInstallMethod.STANDALONE_BINARY,
        "ffuf": ToolInstallMethod.STANDALONE_BINARY,
        "gitleaks": ToolInstallMethod.STANDALONE_BINARY,
        "trivy": ToolInstallMethod.STANDALONE_BINARY,
        "nmap": ToolInstallMethod.SYSTEM_PACKAGE_MANAGER,
        "nikto": ToolInstallMethod.SYSTEM_PACKAGE_MANAGER,
    }

    for name, adapter in registry.items():
        is_enabled, custom_path = adapter_configs.get(name, (True, None))
        inst_method = tool_install_methods.get(name, ToolInstallMethod.MANUAL)

        if not is_enabled:
            tool_statuses.append(
                ToolStatus(
                    name=name,
                    available=False,
                    version=None,
                    path=adapter.resolve_binary_path(custom_path),
                    execution_mode=ToolExecutionMode.DISABLED,
                    install_method=inst_method,
                    is_installed=False,
                    installable=True,
                )
            )
            continue

        resolved_path = adapter.resolve_binary_path(custom_path)
        available = await adapter.is_available(custom_path)
        version = await adapter.get_version(custom_path) if available else None

        if available and resolved_path:
            mode = ToolExecutionMode.ADAPTER_ACTIVE
        else:
            mode = ToolExecutionMode.NATIVE_FALLBACK

        tool_statuses.append(
            ToolStatus(
                name=name,
                available=bool(available and resolved_path),
                version=version,
                path=resolved_path,
                execution_mode=mode,
                install_method=inst_method,
                is_installed=bool(available and resolved_path),
                installable=True,
            )
        )

    return SystemCapabilities(
        tools=tool_statuses,
        native_engines_ready=True,
        os_platform=platform.platform(),
    )

