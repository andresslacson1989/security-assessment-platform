"""
Bridge module for CT Log IP Discovery & Exposure Auditor.
Re-exports origin_exposure functionality from the network reconnaissance engine.
"""

from app.engines.network.origin_exposure import (
    is_cloudflare_ip,
    is_private_or_loopback_ip,
    fetch_ct_logs,
    resolve_host_ips,
    safe_probe_exposed_ip,
    audit_origin_exposure,
    CLOUDFLARE_IPV4_CIDRS,
    CLOUDFLARE_IPV6_CIDRS,
    CLOUDFLARE_NETWORKS,
)

__all__ = [
    "is_cloudflare_ip",
    "is_private_or_loopback_ip",
    "fetch_ct_logs",
    "resolve_host_ips",
    "safe_probe_exposed_ip",
    "audit_origin_exposure",
    "CLOUDFLARE_IPV4_CIDRS",
    "CLOUDFLARE_IPV6_CIDRS",
    "CLOUDFLARE_NETWORKS",
]
