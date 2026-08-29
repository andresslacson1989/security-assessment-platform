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
)
from app.adapters.base_adapter import BaseToolAdapter
from app.adapters.nmap_adapter import NmapAdapter
from app.adapters.nuclei_adapter import NucleiAdapter
from app.adapters.semgrep_adapter import SemgrepAdapter
from app.adapters.trivy_adapter import TrivyAdapter


__all__ = [
    "BaseToolAdapter",
    "NmapAdapter",
    "NucleiAdapter",
    "SemgrepAdapter",
    "TrivyAdapter",
    "get_adapter_registry",
    "discover_system_capabilities",
]


def get_adapter_registry() -> Dict[str, BaseToolAdapter]:
    """
    Returns an initialized registry of available tool adapter instances.
    """
    return {
        "nmap": NmapAdapter(),
        "nuclei": NucleiAdapter(),
        "semgrep": SemgrepAdapter(),
        "trivy": TrivyAdapter(),
    }


async def discover_system_capabilities(
    config: Optional[ToolAdapterConfig] = None,
) -> SystemCapabilities:
    """
    Discovers installed CLI tools on the host system, inspects their versions and paths,
    and returns the structured SystemCapabilities model.
    """
    cfg = config or ToolAdapterConfig()
    registry = get_adapter_registry()
    tool_statuses: List[ToolStatus] = []

    # Map tool name to its enable flag and custom path configuration
    adapter_configs = {
        "nmap": (cfg.enable_nmap, cfg.nmap_path or cfg.custom_nmap_path),
        "nuclei": (cfg.enable_nuclei, cfg.nuclei_path or cfg.custom_nuclei_path),
        "semgrep": (cfg.enable_semgrep, cfg.semgrep_path or cfg.custom_semgrep_path),
        "trivy": (cfg.enable_trivy, cfg.trivy_path or cfg.custom_trivy_path),
    }

    for name, adapter in registry.items():
        is_enabled, custom_path = adapter_configs.get(name, (True, None))

        if not is_enabled:
            tool_statuses.append(
                ToolStatus(
                    name=name,
                    available=False,
                    version=None,
                    path=adapter.resolve_binary_path(custom_path),
                    execution_mode=ToolExecutionMode.DISABLED,
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
            )
        )

    return SystemCapabilities(
        tools=tool_statuses,
        native_engines_ready=True,
        os_platform=platform.platform(),
    )
