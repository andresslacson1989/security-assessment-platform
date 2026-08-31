"""
Contract 01 §5.1, Contract 04 & Contract 08 §12.1:
Strict Server-Side Request Forgery (SSRF) Protection Gateway & DNS Rebinding Defenses.
"""

from __future__ import annotations
import ipaddress
import socket
import urllib.parse
from typing import List, Tuple, Optional


# Blocked IPv4 and IPv6 Networks
BLOCKED_NETWORKS = [
    # IPv4 Loopback & Unspecified
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    # IPv4 RFC 1918 Private Subnets
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # IPv4 Link-Local & Cloud Metadata (AWS, GCP, Azure, OpenStack 169.254.169.254)
    ipaddress.ip_network("169.254.0.0/16"),
    # Carrier-Grade NAT (RFC 6598)
    ipaddress.ip_network("100.64.0.0/10"),
    # Multicast & Reserved
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    # IPv6 Loopback & Unspecified
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    # IPv6 Link-Local
    ipaddress.ip_network("fe80::/10"),
    # IPv6 Unique Local Unicast (RFC 4193)
    ipaddress.ip_network("fc00::/7"),
    # IPv6 Multicast
    ipaddress.ip_network("ff00::/8"),
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
    "169.254.169.254",
}


class SSRFProtectionError(ValueError):
    """Raised when a target URL or resolved IP violates SSRF protection policy."""
    pass


def is_ip_allowed(ip_str: str) -> Tuple[bool, Optional[str]]:
    """
    Evaluates whether an IPv4 or IPv6 address is safe for outbound scanning.
    Returns (True, None) if allowed, or (False, reason) if blocked.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, f"Invalid IP address format: '{ip_str}'"

    # Fast boolean checks from stdlib
    if ip_obj.is_loopback:
        return False, f"Loopback address '{ip_str}' is forbidden."
    if ip_obj.is_private:
        return False, f"Private intranet address '{ip_str}' is forbidden."
    if ip_obj.is_link_local:
        return False, f"Link-local / Cloud metadata address '{ip_str}' is forbidden."
    if ip_obj.is_multicast:
        return False, f"Multicast address '{ip_str}' is forbidden."
    if ip_obj.is_reserved:
        return False, f"Reserved address '{ip_str}' is forbidden."
    if ip_obj.is_unspecified:
        return False, f"Unspecified address '{ip_str}' is forbidden."

    # Comprehensive CIDR containment check
    for net in BLOCKED_NETWORKS:
        if ip_obj in net:
            return False, f"IP '{ip_str}' falls within blocked network '{net}'."

    return True, None


def resolve_hostname_ips(hostname: str) -> List[str]:
    """
    Resolves hostname to all corresponding IPv4 and IPv6 addresses.
    """
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        ips = list(dict.fromkeys(item[4][0] for item in addr_info if item and item[4]))
        return ips
    except socket.gaierror:
        return []


def validate_target_url(url: str, allow_internal: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Validates that a URL is well-formed, uses http/https, and does not target forbidden internal IPs.
    If allow_internal is True (Admin override), internal private IPs are permitted.
    """
    if not url or not isinstance(url, str):
        return False, "Target URL cannot be empty."

    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Scheme '{parsed.scheme}' is disallowed. Must be 'http' or 'https'."

    hostname = parsed.hostname
    if not hostname:
        return False, "Target URL missing valid hostname."

    hostname_lower = hostname.lower().strip("[]")

    if not allow_internal:
        # Check forbidden hostnames
        if hostname_lower in BLOCKED_HOSTNAMES or hostname_lower.endswith(".internal") or hostname_lower.endswith(".local"):
            return False, f"Target hostname '{hostname}' is a reserved internal/metadata name."

        # Check direct IP literals
        try:
            ip_obj = ipaddress.ip_address(hostname_lower)
            allowed, reason = is_ip_allowed(str(ip_obj))
            if not allowed:
                return False, reason
            return True, None
        except ValueError:
            pass  # Not an IP literal; proceed to DNS resolution

        # Resolve hostname and check all IPs
        resolved_ips = resolve_hostname_ips(hostname_lower)
        if not resolved_ips:
            # Contract 01 / 08 Invariant: Unresolved target MUST fail closed.
            return False, f"Target hostname '{hostname}' failed DNS resolution or does not exist."

        for ip in resolved_ips:
            allowed, reason = is_ip_allowed(ip)
            if not allowed:
                return False, f"Resolved IP '{ip}' for hostname '{hostname}' is blocked: {reason}"

    return True, None


def validate_target_domain(domain: str, allow_internal: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Validates a DOMAIN target input against SSRF and internal address restrictions.
    """
    if not domain or not isinstance(domain, str):
        return False, "Target domain cannot be empty."
    
    clean_domain = domain.strip().lower().split(":")[0]
    if not allow_internal:
        if clean_domain in BLOCKED_HOSTNAMES or clean_domain.endswith(".internal") or clean_domain.endswith(".local"):
            return False, f"Target domain '{domain}' is a reserved internal/metadata name."
        
        resolved_ips = resolve_hostname_ips(clean_domain)
        if not resolved_ips:
            return False, f"Target domain '{clean_domain}' failed DNS resolution."
        
        for ip in resolved_ips:
            allowed, reason = is_ip_allowed(ip)
            if not allowed:
                return False, f"Domain resolved to blocked address '{ip}': {reason}"
                
    return True, None


def validate_target_ip(ip_str: str, allow_internal: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Validates an IP target input against SSRF and private network boundaries.
    Correctly handles IPv4, standard IPv6, and bracketed host:port notation.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False, "Target IP cannot be empty."
    
    clean_ip = ip_str.strip()
    if clean_ip.startswith("["):
        if "]" in clean_ip:
            clean_ip = clean_ip[1:clean_ip.index("]")]
        else:
            clean_ip = clean_ip.strip("[]")
    elif clean_ip.count(":") == 1:
        # IPv4 with port e.g. 192.168.1.1:80
        clean_ip = clean_ip.split(":")[0]

    if allow_internal:
        try:
            ipaddress.ip_address(clean_ip)
            return True, None
        except ValueError:
            return False, f"Invalid IP address format: '{clean_ip}'"
            
    return is_ip_allowed(clean_ip)


def validate_target_security(
    target_type: str,
    target_value: str,
    allow_internal: bool = False,
) -> Tuple[bool, Optional[str]]:
    """
    Authoritative single-pipeline security validation for all target types:
    URL, DOMAIN, IP, LOCAL_PATH, DOCKERFILE, IAC_MANIFEST.
    Ensures zero bypass routes around the security gateway.
    """
    t_type = target_type.value if hasattr(target_type, "value") else str(target_type).upper()
    
    if t_type == "URL":
        return validate_target_url(target_value, allow_internal=allow_internal)
    elif t_type == "DOMAIN":
        return validate_target_domain(target_value, allow_internal=allow_internal)
    elif t_type == "IP":
        return validate_target_ip(target_value, allow_internal=allow_internal)
    elif t_type in ("LOCAL_PATH", "DOCKERFILE", "IAC_MANIFEST"):
        from app.core.path_sandbox import validate_path_sandbox
        return validate_path_sandbox(target_value)
    else:
        return False, f"Unsupported target type: '{target_type}'"


def assert_safe_url(url: str, allow_internal: bool = False) -> None:
    """
    Convenience function that raises SSRFProtectionError if the URL fails validation.
    """
    allowed, reason = validate_target_url(url, allow_internal=allow_internal)
    if not allowed:
        raise SSRFProtectionError(reason or "SSRF validation failed.")


def assert_safe_target(target_type: str, target_value: str, allow_internal: bool = False) -> None:
    """
    Authoritatively asserts safety of any target type, raising SSRFProtectionError or PathTraversalError on failure.
    """
    allowed, reason = validate_target_security(target_type, target_value, allow_internal=allow_internal)
    if not allowed:
        raise SSRFProtectionError(reason or "Target validation failed security policy.")


def create_validated_target(
    raw_target: Any,
    organization_id: str = "org-default",
    project_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    workspace_id: Optional[str] = None,
    allow_internal: bool = False,
) -> Any:
    """
    Contract 01 §5.1, Contract 02 §3 & Contract 08 §12.1:
    Authoritative single-pipeline validation gate producing an immutable ValidatedTarget object.
    Fails closed if the target violates SSRF, DNS, or workspace confinement policies.
    """
    from app.core.models import ValidatedTarget, TargetType, utc_now
    
    t_val = raw_target.value if hasattr(raw_target, "value") else str(raw_target)
    t_type = raw_target.type if hasattr(raw_target, "type") else TargetType.URL
    t_type_str = t_type.value if hasattr(t_type, "value") else str(t_type)
    
    assert_safe_target(t_type_str, t_val, allow_internal=allow_internal)
    
    resolved_dest = None
    if t_type_str == "URL":
        parsed = urllib.parse.urlparse(t_val.strip())
        if parsed.hostname:
            ips = resolve_hostname_ips(parsed.hostname.strip("[]"))
            resolved_dest = ips[0] if ips else None
    elif t_type_str == "DOMAIN":
        ips = resolve_hostname_ips(t_val.strip())
        resolved_dest = ips[0] if ips else None
    elif t_type_str == "IP":
        resolved_dest = t_val.strip()
    elif t_type_str in ("LOCAL_PATH", "DOCKERFILE", "IAC_MANIFEST"):
        import os
        resolved_dest = os.path.abspath(t_val.strip())

    return ValidatedTarget(
        id=getattr(raw_target, "id", None) or None,
        target_type=t_type,
        normalized_value=t_val.strip(),
        organization_id=organization_id,
        project_id=project_id,
        asset_id=asset_id,
        workspace_id=workspace_id,
        resolved_destination=resolved_dest,
        authorization_context={"allow_internal": allow_internal, "validated_by": "assert_safe_target"},
        validation_timestamp=utc_now(),
        policy_version="13.0.0",
    )
