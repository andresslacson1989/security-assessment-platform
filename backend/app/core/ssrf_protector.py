"""
Contract 01 §5.1, Contract 04 & Contract 08 §12.1:
Strict Server-Side Request Forgery (SSRF) Protection Gateway & DNS Rebinding Defenses.
"""

from __future__ import annotations
import ipaddress
import socket
import urllib.parse
import httpx
import httpcore
from typing import Any, List, Tuple, Optional


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


class ValidatedTargetTransport(httpx.AsyncBaseTransport):
    """httpx transport that pins TCP connections while preserving hostname SNI."""

    def __init__(self, validated_target: Any):
        self._validated_target = validated_target
        self._transport = httpx.AsyncHTTPTransport(retries=0, verify=True, trust_env=False)
        self._transport._pool._network_backend = _PinnedNetworkBackend(
            str(getattr(validated_target, "selected_destination", ""))
        )
        raw_value = str(getattr(validated_target, "canonical_value", ""))
        parsed = urllib.parse.urlsplit(raw_value if "://" in raw_value else f"https://{raw_value}")
        self._authorized_host = (parsed.hostname or "").lower().strip("[]")

    async def handle_async_request(self, request: Any) -> Any:
        request_host = request.url.host.lower().strip("[]")
        if request_host != self._authorized_host and request_host != str(
            getattr(self._validated_target, "selected_destination", "")
        ).lower().strip("[]"):
            raise SSRFProtectionError(f"Redirect or request escaped validated origin: {request.url}")

        if not getattr(self._validated_target, "selected_destination", ""):
            raise SSRFProtectionError("Validated target has no selected destination.")
        request.headers["host"] = self._authorized_host
        return await self._transport.handle_async_request(request)

    async def aclose(self) -> None:
        await self._transport.aclose()


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connect to the selected address; httpcore retains the original origin for TLS SNI."""

    def __init__(self, destination: str):
        self._destination = destination
        self._delegate = httpcore.AnyIOBackend()

    async def connect_tcp(self, host: str, port: int, timeout: float | None = None, local_address: str | None = None, socket_options: Any = None) -> Any:
        return await self._delegate.connect_tcp(
            self._destination,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


def bind_url_to_validated_target(url: str, validated_target: Any) -> Tuple[str, str]:
    """Bind an HTTP URL to the gateway-selected address and retain its Host name."""
    parsed = urllib.parse.urlsplit(url.strip())
    host = parsed.hostname
    selected = getattr(validated_target, "selected_destination", None)
    if not host or not selected:
        raise SSRFProtectionError("Validated target is missing a selected destination or hostname.")

    port = parsed.port
    if ":" in selected and not selected.startswith("["):
        selected = f"[{selected}]"
    bound_netloc = selected
    if port:
        bound_netloc = f"{bound_netloc}:{port}"
    bound_url = urllib.parse.urlunsplit((parsed.scheme, bound_netloc, parsed.path, parsed.query, parsed.fragment))
    return bound_url, host


def is_url_in_validated_origin(url: str, validated_target: Any) -> bool:
    """Return whether an observed URL remains within the validated web origin."""
    try:
        candidate = urllib.parse.urlsplit(str(url).strip())
        canonical_raw = str(getattr(validated_target, "canonical_value", ""))
        canonical = urllib.parse.urlsplit(
            canonical_raw if "://" in canonical_raw else f"https://{canonical_raw}"
        )
        candidate_host = (candidate.hostname or "").lower().strip("[]")
        canonical_host = (canonical.hostname or "").lower().strip("[]")
        if not candidate_host or candidate_host != canonical_host:
            return False
        if "://" in canonical_raw and candidate.scheme.lower() != canonical.scheme.lower():
            return False
        expected_port = getattr(validated_target, "port", None) or canonical.port or (443 if canonical.scheme == "https" else 80)
        actual_port = candidate.port or (443 if candidate.scheme.lower() == "https" else 80)
        return actual_port == expected_port
    except (TypeError, ValueError):
        return False


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
    Authoritative single-pipeline security validation for all target and asset types:
    TargetType: URL, DOMAIN, IP, LOCAL_PATH, DOCKERFILE, IAC_MANIFEST
    AssetType: WEB_APPLICATION, API_ENDPOINT, DOMAIN, IP_ADDRESS, GIT_REPOSITORY,
               CONTAINER_IMAGE, KUBERNETES_CLUSTER, CLOUD_ACCOUNT, IAC_TEMPLATE
    Ensures zero bypass routes around the security gateway.
    """
    t_type = target_type.value if hasattr(target_type, "value") else str(target_type).upper()
    val = target_value.strip()

    if t_type == "URL":
        return validate_target_url(val, allow_internal=allow_internal)
    elif t_type in ("WEB_APPLICATION", "API_ENDPOINT"):
        if not val.startswith("http://") and not val.startswith("https://") and "://" not in val:
            if "/" not in val and ":" not in val and "." in val:
                return validate_target_domain(val, allow_internal=allow_internal)
            val = f"https://{val}"
        return validate_target_url(val, allow_internal=allow_internal)
    elif t_type in ("DOMAIN",):
        return validate_target_domain(val, allow_internal=allow_internal)
    elif t_type in ("IP", "IP_ADDRESS"):
        return validate_target_ip(val, allow_internal=allow_internal)
    elif t_type in ("LOCAL_PATH", "DOCKERFILE", "IAC_MANIFEST", "IAC_TEMPLATE"):
        from app.core.path_sandbox import validate_path_sandbox
        return validate_path_sandbox(val)
    elif t_type in ("GIT_REPOSITORY",):
        if val.startswith("http://") or val.startswith("https://"):
            return validate_target_url(val, allow_internal=allow_internal)
        elif val.startswith("git@"):
            # SSH format: git@github.com:org/repo.git -> extract domain
            parts = val.split("@", 1)[1].split(":", 1)[0]
            return validate_target_domain(parts, allow_internal=allow_internal)
        else:
            from app.core.path_sandbox import validate_path_sandbox
            return validate_path_sandbox(val)
    elif t_type in ("CONTAINER_IMAGE", "KUBERNETES_CLUSTER", "CLOUD_ACCOUNT"):
        # Safe format check: ensure no control chars or shell injection attempts
        if any(c in val for c in [";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r", "\0"]):
            return False, f"Dangerous characters detected in {t_type} specification: '{val}'"
        if t_type == "KUBERNETES_CLUSTER" and (val.startswith("http://") or val.startswith("https://")):
            return validate_target_url(val, allow_internal=allow_internal)
        return True, None
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
    authorized_scope: Optional[List[str]] = None,
    state_changing_granted: bool = False,
) -> Any:
    """
    Contract 01 §5.1, Contract 02 §3, Contract 08 §12.1 & Contract 09 §1.1:
    Authoritative single-pipeline validation gate producing an immutable ValidatedTarget object.
    Fails closed if the target violates SSRF, DNS, or workspace confinement policies.
    """
    import hashlib
    from app.core.models import ValidatedTarget, TargetType, utc_now
    
    t_val = raw_target.value if hasattr(raw_target, "value") else str(raw_target)
    t_type = raw_target.type if hasattr(raw_target, "type") else TargetType.URL
    t_type_str = t_type.value if hasattr(t_type, "value") else str(t_type)
    
    assert_safe_target(t_type_str, t_val, allow_internal=allow_internal)
    
    canonical_val = t_val.strip()
    resolved_ips: List[str] = []
    selected_dest = ""
    port: Optional[int] = None
    scheme: Optional[str] = None

    if t_type_str == "URL":
        parsed = urllib.parse.urlparse(canonical_val)
        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        port = parsed.port or (443 if scheme == "https" else 80)
        if parsed.hostname:
            clean_host = parsed.hostname.strip("[]")
            resolved_ips = resolve_hostname_ips(clean_host)
            selected_dest = resolved_ips[0] if resolved_ips else clean_host
        else:
            selected_dest = canonical_val
    elif t_type_str == "DOMAIN":
        clean_domain = canonical_val.lower().split(":")[0]
        resolved_ips = resolve_hostname_ips(clean_domain)
        selected_dest = resolved_ips[0] if resolved_ips else clean_domain
    elif t_type_str == "IP":
        clean_ip = canonical_val.split(":")[0].strip("[]")
        resolved_ips = [clean_ip]
        selected_dest = clean_ip
        if ":" in canonical_val and canonical_val.count(":") == 1:
            try:
                port = int(canonical_val.split(":")[1])
            except ValueError:
                pass
    elif t_type_str in ("LOCAL_PATH", "DOCKERFILE", "IAC_MANIFEST"):
        import os
        selected_dest = os.path.abspath(canonical_val)

    # The authoritative constructor performs a second DNS lookup after the
    # initial input gate. Re-apply the address policy here so a DNS answer
    # changing between those two points cannot become the pinned destination.
    if t_type_str in ("URL", "DOMAIN"):
        if not resolved_ips:
            raise SSRFProtectionError("Target hostname did not resolve at validated-target construction time.")
        for resolved_ip in resolved_ips:
            try:
                ipaddress.ip_address(resolved_ip)
            except ValueError as exc:
                raise SSRFProtectionError("Target hostname returned an invalid address.") from exc
            if not allow_internal:
                allowed, reason = is_ip_allowed(resolved_ip)
                if not allowed:
                    raise SSRFProtectionError(
                        f"Resolved IP '{resolved_ip}' for target is blocked: {reason}"
                    )

    # Compute cryptographic identity digests per Contract 09 §1.1
    policy_version = "14.3.0"
    target_id = hashlib.sha256(f"{canonical_val}:{selected_dest}".encode("utf-8")).hexdigest()
    auth_decision_id = hashlib.sha256(
        f"{organization_id}:{project_id or ''}:{asset_id or ''}:{target_id}:{policy_version}".encode("utf-8")
    ).hexdigest()
    integrity_seal = hashlib.sha256(
        f"GATEWAY_SEAL:{target_id}:{auth_decision_id}:{policy_version}".encode("utf-8")
    ).hexdigest()

    auth_ctx = {
        "allow_internal": allow_internal,
        "validated_by": "assert_safe_target",
        "active_probing_granted": True,
        "state_changing_granted": bool(state_changing_granted),
        "dns_zone_authorized": (t_type_str == "DOMAIN"),
    }

    return ValidatedTarget(
        target_id=target_id,
        authorization_decision_id=auth_decision_id,
        integrity_seal=integrity_seal,
        organization_id=organization_id,
        project_id=project_id,
        asset_id=asset_id,
        workspace_id=workspace_id,
        target_type=t_type,
        raw_value=t_val,
        canonical_value=canonical_val,
        authorized_scope=authorized_scope or [],
        resolved_addresses=resolved_ips,
        selected_destination=selected_dest,
        port=port,
        scheme=scheme,
        authorization_context=auth_ctx,
        validation_timestamp=utc_now(),
        policy_version=policy_version,
    )
