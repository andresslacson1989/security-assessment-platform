"""
Contract 03 (Section 4) Pluggable External Security Tool Adapters Registry.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import platform
import inspect
import re
import asyncio
import json
import time
from typing import Optional, Dict, List

from app.core.models import (
    ToolAdapterConfig,
    ToolStatus,
    ToolExecutionMode,
    SystemCapabilities,
    ToolInstallMethod,
    ToolInstallStatus,
    utc_now,
)
from app.adapters.base_adapter import BaseToolAdapter
from app.adapters.nmap_adapter import NmapAdapter
from app.adapters.sslyze_adapter import SslyzeAdapter
from app.adapters.nuclei_adapter import NucleiAdapter
from app.adapters.ffuf_adapter import FfufAdapter
from app.adapters.semgrep_adapter import SemgrepAdapter
from app.adapters.gitleaks_adapter import GitleaksAdapter
from app.adapters.bandit_adapter import BanditAdapter
from app.adapters.trivy_adapter import TrivyAdapter
from app.adapters.checkov_adapter import CheckovAdapter
from app.adapters.subfinder_adapter import SubfinderAdapter
from app.adapters.httpx_adapter import HttpxAdapter
from app.adapters.katana_adapter import KatanaAdapter
from app.adapters.schemathesis_adapter import SchemathesisAdapter
from app.adapters.trufflehog_adapter import TruffleHogAdapter
from app.adapters.retirejs_adapter import RetireJSAdapter
from app.adapters.syft_adapter import SyftAdapter
from app.adapters.grype_adapter import GrypeAdapter
from app.adapters.osv_scanner_adapter import OSVScannerAdapter
from app.adapters.prowler_adapter import ProwlerAdapter
from app.adapters.kubebench_adapter import KubeBenchAdapter
from app.adapters.dockle_adapter import DockleAdapter
from app.adapters.gtfobins_adapter import GTFOBinsAdapter
from app.adapters.metasploit_adapter import MetasploitAdapter
from app.adapters.sqlmap_adapter import SqlmapAdapter
from app.adapters.amass_adapter import AmassAdapter
from app.adapters.hydra_adapter import HydraAdapter
from app.installers.tool_manifest import PINNED_TOOL_MANIFEST, audit_tool_manifest
from app.core.tool_fleet import SUPPORTED_TOOL_IDS


CAPABILITY_CACHE_TTL_SECONDS = 60
_capability_cache: Dict[str, tuple[float, SystemCapabilities]] = {}
_capability_cache_lock: Optional[asyncio.Lock] = None
_capability_cache_loop = None


def _get_capability_cache_lock() -> asyncio.Lock:
    global _capability_cache_lock, _capability_cache_loop
    loop = asyncio.get_running_loop()
    if _capability_cache_lock is None or _capability_cache_loop is not loop:
        _capability_cache_lock = asyncio.Lock()
        _capability_cache_loop = loop
    return _capability_cache_lock


def _capability_config_key(config: Optional[ToolAdapterConfig]) -> str:
    cfg = config or ToolAdapterConfig()
    return json.dumps(cfg.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def invalidate_system_capabilities_cache() -> None:
    """Drop cached host capability observations after installation lifecycle changes."""
    _capability_cache.clear()


async def get_cached_system_capabilities(
    config: Optional[ToolAdapterConfig] = None,
    *,
    force_refresh: bool = False,
) -> SystemCapabilities:
    """Return a bounded API snapshot; scans continue to call live discovery directly."""
    key = _capability_config_key(config)
    requested_at = time.monotonic()
    lock = _get_capability_cache_lock()
    async with lock:
        now = time.monotonic()
        cached = _capability_cache.get(key)
        if cached:
            cached_at, snapshot = cached
            age = max(0.0, now - cached_at)
            if age <= CAPABILITY_CACHE_TTL_SECONDS and (not force_refresh or cached_at >= requested_at):
                return snapshot.model_copy(update={
                    "capabilities_source": "CACHE",
                    "capabilities_cache_age_seconds": round(age, 3),
                }, deep=True)

        live = await discover_system_capabilities(config)
        checked_at = utc_now()
        live = live.model_copy(update={
            "capabilities_source": "LIVE",
            "capabilities_checked_at": checked_at,
            "capabilities_cache_age_seconds": 0.0,
            "capabilities_cache_ttl_seconds": CAPABILITY_CACHE_TTL_SECONDS,
        }, deep=True)
        _capability_cache[key] = (time.monotonic(), live)
        return live.model_copy(deep=True)


__all__ = [
    "BaseToolAdapter",
    "NmapAdapter",
    "SslyzeAdapter",
    "NucleiAdapter",
    "FfufAdapter",
    "SemgrepAdapter",
    "GitleaksAdapter",
    "BanditAdapter",
    "TrivyAdapter",
    "CheckovAdapter",
    "SubfinderAdapter",
    "HttpxAdapter",
    "KatanaAdapter",
    "SchemathesisAdapter",
    "TruffleHogAdapter",
    "RetireJSAdapter",
    "SyftAdapter",
    "GrypeAdapter",
    "OSVScannerAdapter",
    "ProwlerAdapter",
    "KubeBenchAdapter",
    "DockleAdapter",
    "GTFOBinsAdapter",
    "MetasploitAdapter",
    "SqlmapAdapter",
    "AmassAdapter",
    "HydraAdapter",
    "get_adapter_registry",
    "discover_system_capabilities",
]


def get_adapter_registry() -> Dict[str, BaseToolAdapter]:
    """
    Returns an initialized registry of all 26 registered tool/native adapters.
    """
    return {
        "nmap": NmapAdapter(),
        "sslyze": SslyzeAdapter(),
        "subfinder": SubfinderAdapter(),
        "httpx": HttpxAdapter(),
        "nuclei": NucleiAdapter(),
        "ffuf": FfufAdapter(),
        "katana": KatanaAdapter(),
        "schemathesis": SchemathesisAdapter(),
        "semgrep": SemgrepAdapter(),
        "bandit": BanditAdapter(),
        "gitleaks": GitleaksAdapter(),
        "trufflehog": TruffleHogAdapter(),
        "retire": RetireJSAdapter(),
        "trivy": TrivyAdapter(),
        "syft": SyftAdapter(),
        "grype": GrypeAdapter(),
        "osv-scanner": OSVScannerAdapter(),
        "checkov": CheckovAdapter(),
        "dockle": DockleAdapter(),
        "kube-bench": KubeBenchAdapter(),
        "prowler": ProwlerAdapter(),
        "gtfobins": GTFOBinsAdapter(),
        "metasploit": MetasploitAdapter(),
        "sqlmap": SqlmapAdapter(),
        "amass": AmassAdapter(),
        "hydra": HydraAdapter(),
    }


async def discover_system_capabilities(
    config: Optional[ToolAdapterConfig] = None,
) -> SystemCapabilities:
    """
    Discovers installed CLI tools and native evaluators across the registered adapters,
    inspects their versions and paths, and returns the structured SystemCapabilities model.
    """
    cfg = config or ToolAdapterConfig()
    registry = get_adapter_registry()
    if not set(registry).issubset(SUPPORTED_TOOL_IDS):
        raise RuntimeError("Adapter registry contains a tool outside the complete 26-tool fleet")
    tool_statuses: List[ToolStatus] = []

    # Map tool name to its enable flag and custom path configuration
    adapter_configs = {
        "nmap": (cfg.enable_nmap, cfg.nmap_path or cfg.custom_nmap_path),
        "sslyze": (cfg.enable_sslyze, cfg.sslyze_path or cfg.custom_sslyze_path),
        "subfinder": (cfg.enable_subfinder, cfg.subfinder_path or cfg.custom_subfinder_path),
        "httpx": (cfg.enable_httpx, cfg.httpx_path or cfg.custom_httpx_path),
        "nuclei": (cfg.enable_nuclei, cfg.nuclei_path or cfg.custom_nuclei_path),
        "ffuf": (cfg.enable_ffuf, cfg.ffuf_path or cfg.custom_ffuf_path),
        "katana": (cfg.enable_katana, cfg.katana_path or cfg.custom_katana_path),
        "schemathesis": (cfg.enable_schemathesis, cfg.schemathesis_path or cfg.custom_schemathesis_path),
        "semgrep": (cfg.enable_semgrep, cfg.semgrep_path or cfg.custom_semgrep_path),
        "bandit": (cfg.enable_bandit, cfg.bandit_path or cfg.custom_bandit_path),
        "gitleaks": (cfg.enable_gitleaks, cfg.gitleaks_path or cfg.custom_gitleaks_path),
        "trufflehog": (cfg.enable_trufflehog, cfg.trufflehog_path or cfg.custom_trufflehog_path),
        "retire": (cfg.enable_retirejs, cfg.retirejs_path or cfg.custom_retirejs_path),
        "trivy": (cfg.enable_trivy, cfg.trivy_path or cfg.custom_trivy_path),
        "syft": (cfg.enable_syft, cfg.syft_path or cfg.custom_syft_path),
        "grype": (cfg.enable_grype, cfg.grype_path or cfg.custom_grype_path),
        "osv-scanner": (cfg.enable_osv_scanner, cfg.osv_scanner_path or cfg.custom_osv_scanner_path),
        "checkov": (cfg.enable_checkov, cfg.checkov_path or cfg.custom_checkov_path),
        "dockle": (cfg.enable_dockle, cfg.dockle_path or cfg.custom_dockle_path),
        "kube-bench": (cfg.enable_kube_bench, cfg.kube_bench_path or cfg.custom_kube_bench_path),
        "prowler": (cfg.enable_prowler, cfg.prowler_path or cfg.custom_prowler_path),
        "gtfobins": (cfg.enable_gtfobins, None),
        "metasploit": (cfg.enable_metasploit, cfg.metasploit_path or cfg.custom_metasploit_path),
        "sqlmap": (cfg.enable_sqlmap, cfg.sqlmap_path or cfg.custom_sqlmap_path),
        "amass": (cfg.enable_amass, cfg.amass_path or cfg.custom_amass_path),
        "hydra": (cfg.enable_hydra, cfg.hydra_path or cfg.custom_hydra_path),
    }

    # Tool install methods mapping
    tool_install_methods = {
        "sslyze": ToolInstallMethod.PIP,
        "bandit": ToolInstallMethod.PIP,
        "semgrep": ToolInstallMethod.PIP,
        "checkov": ToolInstallMethod.PIP,
        "prowler": ToolInstallMethod.PIP,
        "schemathesis": ToolInstallMethod.PIP,
        "nuclei": ToolInstallMethod.STANDALONE_BINARY,
        "ffuf": ToolInstallMethod.STANDALONE_BINARY,
        "gitleaks": ToolInstallMethod.STANDALONE_BINARY,
        "trivy": ToolInstallMethod.STANDALONE_BINARY,
        "subfinder": ToolInstallMethod.STANDALONE_BINARY,
        "httpx": ToolInstallMethod.STANDALONE_BINARY,
        "katana": ToolInstallMethod.STANDALONE_BINARY,
        "syft": ToolInstallMethod.STANDALONE_BINARY,
        "grype": ToolInstallMethod.STANDALONE_BINARY,
        "osv-scanner": ToolInstallMethod.STANDALONE_BINARY,
        "trufflehog": ToolInstallMethod.STANDALONE_BINARY,
        "dockle": ToolInstallMethod.STANDALONE_BINARY,
        "kube-bench": ToolInstallMethod.STANDALONE_BINARY,
        "nmap": ToolInstallMethod.STANDALONE_BINARY,
        "retire": ToolInstallMethod.SYSTEM_PACKAGE_MANAGER,
        "gtfobins": ToolInstallMethod.MANUAL,
        "metasploit": ToolInstallMethod.MANUAL,
        "sqlmap": ToolInstallMethod.MANUAL,
        "amass": ToolInstallMethod.STANDALONE_BINARY,
        "hydra": ToolInstallMethod.MANUAL,
    }
    manual_only_tools = {"metasploit", "sqlmap", "hydra"}
    native_engine_tools = {"gtfobins"}

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
                    assurance_status="DISABLED",
                )
            )
            continue

        if name in native_engine_tools:
            native_available = await adapter.is_available(custom_path)
            native_version = await adapter.get_version(custom_path) if native_available else None
            tool_statuses.append(
                ToolStatus(
                    name=name,
                    available=bool(native_available),
                    version=native_version,
                    path=None,
                    execution_mode=ToolExecutionMode.NATIVE_ENGINE_READY if native_available else ToolExecutionMode.NATIVE_FALLBACK,
                    install_method=inst_method,
                    is_installed=False,
                    installable=False,
                    assurance_status="NOT_APPLICABLE" if native_available else "UNASSURED",
                )
            )
            continue

        resolved_path = adapter.resolve_binary_path(custom_path)
        available = await adapter.is_available(custom_path)
        assurance_status = "UNASSURED"
        assured_for_execution = False
        if available and resolved_path:
            manifest_status = audit_tool_manifest([name])
            verified = False
            try:
                verified = bool(adapter.verify_managed_binary(resolved_path))
            except Exception:
                verified = False
            if name in manifest_status["assured"]:
                assurance_status = "ASSURED" if verified else "UNASSURED"
            elif name in manifest_status["incomplete"]:
                assurance_status = (
                    "DELEGATED"
                    if inst_method == ToolInstallMethod.SYSTEM_PACKAGE_MANAGER
                    else "INCOMPLETE"
                )
            elif name in manifest_status["invalid"]:
                assurance_status = "INVALID"
            else:
                assurance_status = "UNREGISTERED"
            assured_for_execution = verified and assurance_status in {"ASSURED", "DELEGATED"}

        version = None
        if available and resolved_path and assured_for_execution:
            version_kwargs = {}
            try:
                supports_pre_launch_check = "pre_launch_check" in inspect.signature(
                    adapter.get_version
                ).parameters
            except (TypeError, ValueError):
                supports_pre_launch_check = False
            if supports_pre_launch_check:
                version_kwargs["pre_launch_check"] = lambda: bool(
                    adapter.verify_managed_binary(resolved_path)
                )
            version = await adapter.get_version(custom_path, **version_kwargs)
            configured_version = getattr(adapter, "approved_version", None)
            expected_version = str(
                configured_version
                if isinstance(configured_version, str) and configured_version.strip()
                else PINNED_TOOL_MANIFEST.get(name, {}).get("version", "")
            ).lstrip("v")
            version_match = re.search(r"(?<![0-9A-Za-z.-])v?(\d+(?:\.\d+){1,2})(?![0-9A-Za-z.-])", version or "")
            if expected_version and (not version_match or version_match.group(1) != expected_version):
                assurance_status = "INVALID"
                assured_for_execution = False
                version = None

        if name in manual_only_tools:
            mode = ToolExecutionMode.MANUAL_ONLY
        elif available and resolved_path and assured_for_execution:
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
                assurance_status=assurance_status,
            )
        )

    return SystemCapabilities(
        tools=tool_statuses,
        native_engines_ready=True,
        os_platform=platform.platform(),
    )
