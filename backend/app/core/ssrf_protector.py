"""
Contract 01 §5.1, Contract 04 & Contract 08 §12.1:
Strict Server-Side Request Forgery (SSRF) Protection Gateway & DNS Rebinding Defenses.
"""

from __future__ import annotations
import ipaddress
import socket
import urllib.parse
import hashlib
import hmac
import json
import httpx
import httpcore
import os
import secrets
from typing import Any, List, Tuple, Optional, Union
from enum import Enum
from app.core.version import APP_VERSION


class NetworkClassification(str, Enum):
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"
    LOOPBACK = "LOOPBACK"
    LINK_LOCAL = "LINK_LOCAL"
    METADATA = "METADATA"
    RESERVED = "RESERVED"
    MULTICAST = "MULTICAST"
    UNSPECIFIED = "UNSPECIFIED"


METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("168.63.129.16/32"),
    ipaddress.ip_network("100.100.100.200/32"),
]

LOOPBACK_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

UNSPECIFIED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::/128"),
]

LINK_LOCAL_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]

MULTICAST_NETWORKS = [
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
]

RESERVED_NETWORKS = [
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("100::/64"),
    ipaddress.ip_network("2001:2::/48"),
]

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]

BLOCKED_NETWORKS = (
    METADATA_NETWORKS
    + LOOPBACK_NETWORKS
    + UNSPECIFIED_NETWORKS
    + LINK_LOCAL_NETWORKS
    + MULTICAST_NETWORKS
    + RESERVED_NETWORKS
    + PRIVATE_NETWORKS
)

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


_GATEWAY_SEAL_DOMAIN = b"cyberassess:validated-target-seal:v1"
_EPHEMERAL_GATEWAY_SEAL_KEY = secrets.token_bytes(32)


def _gateway_seal_key() -> bytes:
    """Return a key dedicated to validated-target authorization seals.

    Production deployments should provide TARGET_GATEWAY_SEAL_SECRET.  The
    JWT secret is an explicitly derived fallback so key material is separated
    by domain; the ephemeral fallback keeps test/development processes
    self-contained while production authentication still requires a durable
    configured secret.
    """
    configured = os.getenv("TARGET_GATEWAY_SEAL_SECRET") or os.getenv("JWT_SECRET")
    if configured and configured.strip():
        return hmac.new(
            configured.strip().encode("utf-8"),
            _GATEWAY_SEAL_DOMAIN,
            hashlib.sha256,
        ).digest()
    return _EPHEMERAL_GATEWAY_SEAL_KEY


def _compute_gateway_seal(
    target_id: str,
    authorization_decision_id: str,
    policy_version: str,
    context_digest: str,
) -> str:
    """Compute the authenticated integrity seal for a validated target."""
    payload = (
        f"GATEWAY_SEAL:{target_id}:{authorization_decision_id}:"
        f"{policy_version}:{context_digest}"
    ).encode("utf-8")
    return hmac.new(_gateway_seal_key(), payload, hashlib.sha256).hexdigest()


def _validated_target_context_digest(validated_target: Any) -> str:
    """Return the digest of authorization data bound into the gateway seal."""
    context = getattr(validated_target, "authorization_context", None)
    if not isinstance(context, dict):
        raise SSRFProtectionError("Validated target authorization context is invalid.")
    material = {
        "allow_internal": context.get("allow_internal"),
        "active_probing_granted": context.get("active_probing_granted"),
        "state_changing_granted": context.get("state_changing_granted"),
        "dns_zone_authorized": context.get("dns_zone_authorized"),
        "cloud_provider": context.get("cloud_provider"),
        "authorized_scope": list(getattr(validated_target, "authorized_scope", [])),
        "workspace_id": getattr(validated_target, "workspace_id", None) or "",
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def validate_validated_target(validated_target: Any) -> Any:
    """Re-validate the gateway-issued target identity immediately before use."""
    from app.core.models import ValidatedTarget, TargetType

    if not isinstance(validated_target, ValidatedTarget):
        raise SSRFProtectionError("Execution requires a gateway-issued ValidatedTarget instance.")

    required_strings = (
        "target_id",
        "authorization_decision_id",
        "integrity_seal",
        "organization_id",
        "canonical_value",
        "selected_destination",
        "policy_version",
    )
    if any(
        not isinstance(getattr(validated_target, field, None), str)
        or not getattr(validated_target, field)
        for field in required_strings
    ):
        raise SSRFProtectionError("Validated target is missing required identity fields.")
    if validated_target.policy_version != APP_VERSION:
        raise SSRFProtectionError("Validated target policy version is no longer current.")

    expected_target_id = hashlib.sha256(
        f"{validated_target.canonical_value}:{validated_target.selected_destination}".encode("utf-8")
    ).hexdigest()
    if not hmac.compare_digest(validated_target.target_id, expected_target_id):
        raise SSRFProtectionError("Validated target identity does not match its canonical destination.")

    expected_decision_id = hashlib.sha256(
        f"{validated_target.organization_id}:{validated_target.project_id or ''}:{validated_target.asset_id or ''}:"
        f"{validated_target.target_id}:{validated_target.policy_version}".encode("utf-8")
    ).hexdigest()
    if not hmac.compare_digest(validated_target.authorization_decision_id, expected_decision_id):
        raise SSRFProtectionError("Validated target authorization identity is invalid.")

    context = validated_target.authorization_context
    expected_context = {
        "allow_internal": isinstance(context.get("allow_internal"), bool),
        "active_probing_granted": isinstance(context.get("active_probing_granted"), bool),
        "state_changing_granted": isinstance(context.get("state_changing_granted"), bool),
        "dns_zone_authorized": isinstance(context.get("dns_zone_authorized"), bool),
    }
    if not all(expected_context.values()) or context.get("validated_by") != "assert_safe_target":
        raise SSRFProtectionError("Validated target authorization context is invalid.")
    if context["dns_zone_authorized"] != (validated_target.target_type == TargetType.DOMAIN):
        raise SSRFProtectionError("Validated target DNS authorization context is inconsistent.")
    if validated_target.target_type in (TargetType.CLOUD_ACCOUNT, TargetType.KUBERNETES_CLUSTER):
        if context.get("cloud_provider") not in {"aws", "azure", "gcp", "kubernetes"}:
            raise SSRFProtectionError("Validated cloud target provider is invalid.")
    if (context["active_probing_granted"] or context["state_changing_granted"]) and not validated_target.asset_id:
        raise SSRFProtectionError("Intrusive authorization is not bound to an inventory asset.")
    if not validated_target.selected_destination:
        raise SSRFProtectionError("Validated target has no selected destination.")

    expected_seal = _compute_gateway_seal(
        validated_target.target_id,
        validated_target.authorization_decision_id,
        validated_target.policy_version,
        _validated_target_context_digest(validated_target),
    )
    if not hmac.compare_digest(validated_target.integrity_seal, expected_seal):
        raise SSRFProtectionError("Validated target integrity seal is invalid.")
    return validated_target


class ValidatedTargetTransport(httpx.AsyncBaseTransport):
    """httpx transport that pins TCP connections while preserving hostname SNI."""

    def __init__(self, validated_target: Any):
        self._validated_target = validate_validated_target(validated_target)
        self._transport = httpx.AsyncHTTPTransport(retries=0, verify=True, trust_env=False)
        self._transport._pool._network_backend = _PinnedNetworkBackend(
            str(self._validated_target.selected_destination)
        )
        raw_value = str(self._validated_target.canonical_value)
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
    validated_target = validate_validated_target(validated_target)
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
        validated_target = validate_validated_target(validated_target)
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


def classify_ip(ip_val: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Tuple[NetworkClassification, Optional[str]]:
    """
    Authoritatively classifies an IP address into distinct network categories.
    Evaluation order prioritizes dangerous and non-routable categories before private/public:
    1. METADATA
    2. LOOPBACK
    3. UNSPECIFIED
    4. LINK_LOCAL
    5. MULTICAST
    6. RESERVED
    7. PRIVATE
    8. PUBLIC
    """
    if isinstance(ip_val, str):
        try:
            ip_obj = ipaddress.ip_address(ip_val.strip())
        except ValueError:
            return NetworkClassification.UNSPECIFIED, f"Invalid IP address format: '{ip_val}'"
    else:
        ip_obj = ip_val

    ip_str = str(ip_obj)

    # 1. Cloud Metadata (Check FIRST)
    if any(ip_obj in net for net in METADATA_NETWORKS):
        return NetworkClassification.METADATA, f"Cloud metadata address '{ip_str}' is strictly forbidden."

    # 2. Loopback
    if ip_obj.is_loopback or any(ip_obj in net for net in LOOPBACK_NETWORKS):
        return NetworkClassification.LOOPBACK, f"Loopback address '{ip_str}' is forbidden."

    # 3. Unspecified
    if ip_obj.is_unspecified or any(ip_obj in net for net in UNSPECIFIED_NETWORKS):
        return NetworkClassification.UNSPECIFIED, f"Unspecified address '{ip_str}' is forbidden."

    # 4. Link-Local
    if ip_obj.is_link_local or any(ip_obj in net for net in LINK_LOCAL_NETWORKS):
        return NetworkClassification.LINK_LOCAL, f"Link-local address '{ip_str}' is forbidden."

    # 5. Multicast
    if ip_obj.is_multicast or any(ip_obj in net for net in MULTICAST_NETWORKS):
        return NetworkClassification.MULTICAST, f"Multicast address '{ip_str}' is forbidden."

    # 6. Reserved & Non-Global
    if ip_obj.is_reserved or any(ip_obj in net for net in RESERVED_NETWORKS):
        return NetworkClassification.RESERVED, f"Reserved/non-global address '{ip_str}' is forbidden."

    # 7. Private Intranet (RFC 1918 & IPv6 ULA)
    if any(ip_obj in net for net in PRIVATE_NETWORKS):
        return NetworkClassification.PRIVATE, None

    # 8. Must be globally routable public address
    if getattr(ip_obj, "is_global", False):
        return NetworkClassification.PUBLIC, None

    # Fail closed for any unclassified or non-global IP
    return NetworkClassification.RESERVED, f"Non-global routable address '{ip_str}' is forbidden."


def is_ip_allowed_for_policy(ip_str: str, allow_internal: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Evaluates whether an IPv4 or IPv6 address is safe for outbound operations under the given authorization policy.
    - If allow_internal is False: only PUBLIC is allowed.
    - If allow_internal is True: PUBLIC and PRIVATE are allowed.
    - LOOPBACK, LINK_LOCAL, METADATA, RESERVED, MULTICAST, UNSPECIFIED are ALWAYS denied.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, f"Invalid IP address format: '{ip_str}'"

    classification, reason = classify_ip(ip_obj)

    if classification in (
        NetworkClassification.LOOPBACK,
        NetworkClassification.LINK_LOCAL,
        NetworkClassification.METADATA,
        NetworkClassification.RESERVED,
        NetworkClassification.MULTICAST,
        NetworkClassification.UNSPECIFIED,
    ):
        return False, reason or f"{classification.value} address '{ip_str}' is strictly forbidden."

    if classification == NetworkClassification.PRIVATE:
        if not allow_internal:
            return False, f"Private intranet address '{ip_str}' requires explicit 'scan:internal' authorization."
        return True, None

    if classification == NetworkClassification.PUBLIC:
        return True, None

    return False, f"Address '{ip_str}' with classification '{classification.value}' is forbidden."


def is_ip_allowed(ip_str: str) -> Tuple[bool, Optional[str]]:
    """
    Evaluates whether an IPv4 or IPv6 address is safe for public outbound operations.
    Maintains backward compatibility with callers expecting default public-only policy.
    """
    return is_ip_allowed_for_policy(ip_str, allow_internal=False)


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
    Validates that a URL is well-formed, uses http/https, and does not target forbidden destinations.
    Enforces central network classification policy:
    - Dangerous categories (LOOPBACK, LINK_LOCAL, METADATA, RESERVED, MULTICAST, UNSPECIFIED) are always denied.
    - PRIVATE destinations require allow_internal=True.
    - All resolved DNS addresses must be permitted under policy.
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

    # 1. Check forbidden hostnames (always blocked regardless of allow_internal)
    if hostname_lower in BLOCKED_HOSTNAMES or hostname_lower == "localhost" or hostname_lower.startswith("localhost."):
        return False, f"Target hostname '{hostname}' is a reserved internal/metadata name."

    # 2. Check direct IP literals
    try:
        ip_obj = ipaddress.ip_address(hostname_lower)
        return is_ip_allowed_for_policy(str(ip_obj), allow_internal=allow_internal)
    except ValueError:
        pass  # Not an IP literal; proceed to DNS resolution

    # 3. Check reserved domain suffixes if not authorized for internal
    if not allow_internal:
        if hostname_lower.endswith(".internal") or hostname_lower.endswith(".local"):
            return False, f"Target hostname '{hostname}' is a reserved internal name."

    # 4. Resolve hostname and check all IPs
    resolved_ips = resolve_hostname_ips(hostname_lower)
    if not resolved_ips:
        # Contract 01 / 08 Invariant: Unresolved target MUST fail closed.
        return False, f"Target hostname '{hostname}' failed DNS resolution or does not exist."

    for ip in resolved_ips:
        allowed, reason = is_ip_allowed_for_policy(ip, allow_internal=allow_internal)
        if not allowed:
            return False, f"Resolved IP '{ip}' for hostname '{hostname}' is blocked: {reason}"

    return True, None


def validate_target_domain(domain: str, allow_internal: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Validates a DOMAIN target input against SSRF and network classification boundaries.
    """
    if not domain or not isinstance(domain, str):
        return False, "Target domain cannot be empty."

    clean_domain = domain.strip().lower().split(":")[0]

    if clean_domain in BLOCKED_HOSTNAMES or clean_domain == "localhost" or clean_domain.startswith("localhost."):
        return False, f"Target domain '{domain}' is a reserved internal/metadata name."

    if not allow_internal:
        if clean_domain.endswith(".internal") or clean_domain.endswith(".local"):
            return False, f"Target domain '{domain}' is a reserved internal name."

    resolved_ips = resolve_hostname_ips(clean_domain)
    if not resolved_ips:
        return False, f"Target domain '{clean_domain}' failed DNS resolution."

    for ip in resolved_ips:
        allowed, reason = is_ip_allowed_for_policy(ip, allow_internal=allow_internal)
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

    return is_ip_allowed_for_policy(clean_ip, allow_internal=allow_internal)


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
        if t_type == "CLOUD_ACCOUNT":
            provider, separator, identifier = val.partition("://")
            if provider.lower() not in {"aws", "azure", "gcp"} or not separator or not identifier or "/" in identifier:
                return False, "Cloud account targets must use aws://, azure://, or gcp:// followed by an account identifier."
        if t_type == "KUBERNETES_CLUSTER":
            provider, separator, identifier = val.partition("://")
            if provider.lower() != "kubernetes" or not separator or not identifier:
                return False, "Kubernetes targets must use kubernetes:// followed by a cluster identifier or API endpoint."
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
    active_probing_granted: bool = False,
) -> Any:
    """
    Contract 01 §5.1, Contract 02 §3, Contract 08 §12.1 & Contract 09 §1.1:
    Authoritative single-pipeline validation gate producing an immutable ValidatedTarget object.
    Fails closed if the target violates SSRF, DNS, or workspace confinement policies.
    """
    import hashlib
    from app.core.models import ValidatedTarget, TargetType, utc_now

    if (active_probing_granted or state_changing_granted) and not asset_id:
        raise SSRFProtectionError(
            "Intrusive or state-changing authorization requires an explicitly authorized inventory asset."
        )
    
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
    elif t_type_str in ("CLOUD_ACCOUNT", "KUBERNETES_CLUSTER"):
        selected_dest = canonical_val

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
            allowed, reason = is_ip_allowed_for_policy(resolved_ip, allow_internal=allow_internal)
            if not allowed:
                raise SSRFProtectionError(
                    f"Resolved IP '{resolved_ip}' for target is blocked: {reason}"
                )

    auth_ctx = {
        "allow_internal": allow_internal,
        "validated_by": "assert_safe_target",
        "active_probing_granted": bool(active_probing_granted),
        "state_changing_granted": bool(state_changing_granted),
        "dns_zone_authorized": (t_type_str == "DOMAIN"),
        "cloud_provider": (
            canonical_val.split("://", 1)[0].lower()
            if t_type_str in ("CLOUD_ACCOUNT", "KUBERNETES_CLUSTER") and "://" in canonical_val
            else None
        ),
    }

    # Compute cryptographic identity digests per Contract 09 §1.1. The seal
    # also binds authorization context so nested mutable data cannot be changed
    # after construction without failing the next execution-boundary check.
    policy_version = APP_VERSION
    target_id = hashlib.sha256(f"{canonical_val}:{selected_dest}".encode("utf-8")).hexdigest()
    auth_decision_id = hashlib.sha256(
        f"{organization_id}:{project_id or ''}:{asset_id or ''}:{target_id}:{policy_version}".encode("utf-8")
    ).hexdigest()
    context_material = {
        "allow_internal": auth_ctx["allow_internal"],
        "active_probing_granted": auth_ctx["active_probing_granted"],
        "state_changing_granted": auth_ctx["state_changing_granted"],
        "dns_zone_authorized": auth_ctx["dns_zone_authorized"],
        "cloud_provider": auth_ctx["cloud_provider"],
        "authorized_scope": list(authorized_scope or []),
        "workspace_id": workspace_id or "",
    }
    context_digest = hashlib.sha256(
        json.dumps(context_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    integrity_seal = _compute_gateway_seal(
        target_id,
        auth_decision_id,
        policy_version,
        context_digest,
    )

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
