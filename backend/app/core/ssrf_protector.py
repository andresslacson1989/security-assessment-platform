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
from typing import Any, List, Tuple, Optional
from app.core.version import APP_VERSION

# Private address space that may be assessed only with explicit scan:internal authority.
INTERNAL_ALLOWED_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)

# These destinations are never made reachable by scan:internal. A future need
# for any of them requires a separate capability, audit trail, and threat model.
NEVER_ALLOWED_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)

# Compatibility alias used by existing tests/contracts. It denotes all
# non-public networks, not the set permitted by an internal-target grant.
BLOCKED_NETWORKS = list(NEVER_ALLOWED_NETWORKS) + list(INTERNAL_ALLOWED_NETWORKS)

# Named metadata/loopback targets are forbidden regardless of scan:internal.
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
    configured = os.getenv("TARGET_GATEWAY_SEAL_SECRET") or os.getenv("JWT_SECRET")
    if configured and configured.strip():
        return hmac.new(configured.strip().encode("utf-8"), _GATEWAY_SEAL_DOMAIN, hashlib.sha256).digest()
    return _EPHEMERAL_GATEWAY_SEAL_KEY


def _compute_gateway_seal(target_id: str, authorization_decision_id: str, policy_version: str, context_digest: str) -> str:
    payload = f"GATEWAY_SEAL:{target_id}:{authorization_decision_id}:{policy_version}:{context_digest}".encode("utf-8")
    return hmac.new(_gateway_seal_key(), payload, hashlib.sha256).hexdigest()


def _validated_target_context_digest(validated_target: Any) -> str:
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
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def validate_validated_target(validated_target: Any) -> Any:
    from app.core.models import ValidatedTarget, TargetType

    if not isinstance(validated_target, ValidatedTarget):
        raise SSRFProtectionError("Execution requires a gateway-issued ValidatedTarget instance.")
    required_strings = (
        "target_id", "authorization_decision_id", "integrity_seal", "organization_id",
        "canonical_value", "selected_destination", "policy_version",
    )
    if any(not isinstance(getattr(validated_target, field, None), str) or not getattr(validated_target, field) for field in required_strings):
        raise SSRFProtectionError("Validated target is missing required identity fields.")
    if validated_target.policy_version != APP_VERSION:
        raise SSRFProtectionError("Validated target policy version is no longer current.")

    expected_target_id = hashlib.sha256(f"{validated_target.canonical_value}:{validated_target.selected_destination}".encode("utf-8")).hexdigest()
    if not hmac.compare_digest(validated_target.target_id, expected_target_id):
        raise SSRFProtectionError("Validated target identity does not match its canonical destination.")
    expected_decision_id = hashlib.sha256(
        f"{validated_target.organization_id}:{validated_target.project_id or ''}:{validated_target.asset_id or ''}:{validated_target.target_id}:{validated_target.policy_version}".encode("utf-8")
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
        self._transport._pool._network_backend = _PinnedNetworkBackend(str(self._validated_target.selected_destination))
        raw_value = str(self._validated_target.canonical_value)
        parsed = urllib.parse.urlsplit(raw_value if "://" in raw_value else f"https://{raw_value}")
        self._authorized_host = (parsed.hostname or "").lower().strip("[]")

    async def handle_async_request(self, request: Any) -> Any:
        request_host = request.url.host.lower().strip("[]")
        if request_host != self._authorized_host and request_host != str(getattr(self._validated_target, "selected_destination", "")).lower().strip("[]"):
            raise SSRFProtectionError(f"Redirect or request escaped validated origin: {request.url}")
        if not getattr(self._validated_target, "selected_destination", ""):
            raise SSRFProtectionError("Validated target has no selected destination.")
        request.headers["host"] = self._authorized_host
        return await self._transport.handle_async_request(request)

    async def aclose(self) -> None:
        await self._transport.aclose()


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, destination: str):
        self._destination = destination
        self._delegate = httpcore.AnyIOBackend()

    async def connect_tcp(self, host: str, port: int, timeout: float | None = None, local_address: str | None = None, socket_options: Any = None) -> Any:
        return await self._delegate.connect_tcp(self._destination, port, timeout=timeout, local_address=local_address, socket_options=socket_options)


def bind_url_to_validated_target(url: str, validated_target: Any) -> Tuple[str, str]:
    validated_target = validate_validated_target(validated_target)
    parsed = urllib.parse.urlsplit(url.strip())
    host = parsed.hostname
    selected = getattr(validated_target, "selected_destination", None)
    if not host or not selected:
        raise SSRFProtectionError("Validated target is missing a selected destination or hostname.")
    port = parsed.port
    if ":" in selected and not selected.startswith("["):
        selected = f"[{selected}]"
    bound_netloc = f"{selected}:{port}" if port else selected
    return urllib.parse.urlunsplit((parsed.scheme, bound_netloc, parsed.path, parsed.query, parsed.fragment)), host


def is_url_in_validated_origin(url: str, validated_target: Any) -> bool:
    try:
        validated_target = validate_validated_target(validated_target)
        candidate = urllib.parse.urlsplit(str(url).strip())
        canonical_raw = str(getattr(validated_target, "canonical_value", ""))
        canonical = urllib.parse.urlsplit(canonical_raw if "://" in canonical_raw else f"https://{canonical_raw}")
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


def is_ip_allowed(ip_str: str, allow_internal: bool = False) -> Tuple[bool, Optional[str]]:
    """Evaluate an IP against public/private and never-allowed destination policy."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, f"Invalid IP address format: '{ip_str}'"

    # Never-allowed classes are evaluated before private authorization because
    # Python's is_private classification intentionally covers some non-global
    # special-use space too broadly for an SSRF privilege decision.
    if ip_obj.is_loopback:
        return False, f"Loopback address '{ip_str}' is forbidden."
    if ip_obj.is_unspecified:
        return False, f"Unspecified address '{ip_str}' is forbidden."
    if ip_obj.is_link_local:
        return False, f"Link-local / cloud metadata address '{ip_str}' is forbidden."
    if ip_obj.is_multicast:
        return False, f"Multicast address '{ip_str}' is forbidden."
    if ip_obj.is_reserved:
        return False, f"Reserved address '{ip_str}' is forbidden."
    for network in NEVER_ALLOWED_NETWORKS:
        if ip_obj in network:
            return False, f"IP '{ip_str}' falls within forbidden network '{network}'."

    for network in INTERNAL_ALLOWED_NETWORKS:
        if ip_obj in network:
            if allow_internal:
                return True, None
            return False, f"Private intranet address '{ip_str}' requires explicit internal-target authorization."

    # Reject any remaining non-global special-use address that is not one of
    # the explicitly admitted private networks above.
    if not ip_obj.is_global:
        return False, f"Non-global special-use address '{ip_str}' is forbidden."
    return True, None


def resolve_hostname_ips(hostname: str) -> List[str]:
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        return list(dict.fromkeys(item[4][0] for item in addr_info if item and item[4]))
    except socket.gaierror:
        return []


def _validate_hostname_resolution(hostname: str, allow_internal: bool) -> Tuple[bool, Optional[str]]:
    resolved_ips = resolve_hostname_ips(hostname)
    if not resolved_ips:
        return False, f"Target hostname '{hostname}' failed DNS resolution or does not exist."
    for resolved_ip in resolved_ips:
        allowed, reason = is_ip_allowed(resolved_ip, allow_internal=allow_internal)
        if not allowed:
            return False, f"Resolved IP '{resolved_ip}' for hostname '{hostname}' is blocked: {reason}"
    return True, None


def validate_target_url(url: str, allow_internal: bool = False) -> Tuple[bool, Optional[str]]:
    if not url or not isinstance(url, str):
        return False, "Target URL cannot be empty."
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Scheme '{parsed.scheme}' is disallowed. Must be 'http' or 'https'."
    hostname = parsed.hostname
    if not hostname:
        return False, "Target URL missing valid hostname."
    hostname_lower = hostname.lower().strip("[]")

    if hostname_lower in BLOCKED_HOSTNAMES:
        return False, f"Target hostname '{hostname}' is a forbidden loopback/metadata name."
    if not allow_internal and (hostname_lower.endswith(".internal") or hostname_lower.endswith(".local")):
        return False, f"Target hostname '{hostname}' requires explicit internal-target authorization."

    try:
        ip_obj = ipaddress.ip_address(hostname_lower)
    except ValueError:
        return _validate_hostname_resolution(hostname_lower, allow_internal)
    return is_ip_allowed(str(ip_obj), allow_internal=allow_internal)


def validate_target_domain(domain: str, allow_internal: bool = False) -> Tuple[bool, Optional[str]]:
    if not domain or not isinstance(domain, str):
        return False, "Target domain cannot be empty."
    clean_domain = domain.strip().lower().split(":")[0]
    if clean_domain in BLOCKED_HOSTNAMES:
        return False, f"Target domain '{domain}' is a forbidden loopback/metadata name."
    if not allow_internal and (clean_domain.endswith(".internal") or clean_domain.endswith(".local")):
        return False, f"Target domain '{domain}' requires explicit internal-target authorization."
    return _validate_hostname_resolution(clean_domain, allow_internal)


def validate_target_ip(ip_str: str, allow_internal: bool = False) -> Tuple[bool, Optional[str]]:
    if not ip_str or not isinstance(ip_str, str):
        return False, "Target IP cannot be empty."
    clean_ip = ip_str.strip()
    if clean_ip.startswith("["):
        if "]" in clean_ip:
            clean_ip = clean_ip[1:clean_ip.index("]")]
        else:
            clean_ip = clean_ip.strip("[]")
    elif clean_ip.count(":") == 1:
        clean_ip = clean_ip.split(":")[0]
    return is_ip_allowed(clean_ip, allow_internal=allow_internal)


def validate_target_security(target_type: str, target_value: str, allow_internal: bool = False) -> Tuple[bool, Optional[str]]:
    t_type = target_type.value if hasattr(target_type, "value") else str(target_type).upper()
    val = target_value.strip()
    if t_type == "URL":
        return validate_target_url(val, allow_internal=allow_internal)
    if t_type in ("WEB_APPLICATION", "API_ENDPOINT"):
        if not val.startswith("http://") and not val.startswith("https://") and "://" not in val:
            if "/" not in val and ":" not in val and "." in val:
                return validate_target_domain(val, allow_internal=allow_internal)
            val = f"https://{val}"
        return validate_target_url(val, allow_internal=allow_internal)
    if t_type == "DOMAIN":
        return validate_target_domain(val, allow_internal=allow_internal)
    if t_type in ("IP", "IP_ADDRESS"):
        return validate_target_ip(val, allow_internal=allow_internal)
    if t_type in ("LOCAL_PATH", "DOCKERFILE", "IAC_MANIFEST", "IAC_TEMPLATE"):
        from app.core.path_sandbox import validate_path_sandbox
        return validate_path_sandbox(val)
    if t_type == "GIT_REPOSITORY":
        if val.startswith("http://") or val.startswith("https://"):
            return validate_target_url(val, allow_internal=allow_internal)
        if val.startswith("git@"):
            parts = val.split("@", 1)[1].split(":", 1)[0]
            return validate_target_domain(parts, allow_internal=allow_internal)
        from app.core.path_sandbox import validate_path_sandbox
        return validate_path_sandbox(val)
    if t_type in ("CONTAINER_IMAGE", "KUBERNETES_CLUSTER", "CLOUD_ACCOUNT"):
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
    return False, f"Unsupported target type: '{target_type}'"


def assert_safe_url(url: str, allow_internal: bool = False) -> None:
    allowed, reason = validate_target_url(url, allow_internal=allow_internal)
    if not allowed:
        raise SSRFProtectionError(reason or "SSRF validation failed.")


def assert_safe_target(target_type: str, target_value: str, allow_internal: bool = False) -> None:
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
    from app.core.models import ValidatedTarget, TargetType, utc_now

    if (active_probing_granted or state_changing_granted) and not asset_id:
        raise SSRFProtectionError("Intrusive or state-changing authorization requires an explicitly authorized inventory asset.")

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
        selected_dest = os.path.abspath(canonical_val)
    elif t_type_str in ("CLOUD_ACCOUNT", "KUBERNETES_CLUSTER"):
        selected_dest = canonical_val

    if t_type_str in ("URL", "DOMAIN"):
        if not resolved_ips:
            raise SSRFProtectionError("Target hostname did not resolve at validated-target construction time.")
        for resolved_ip in resolved_ips:
            allowed, reason = is_ip_allowed(resolved_ip, allow_internal=allow_internal)
            if not allowed:
                raise SSRFProtectionError(f"Resolved IP '{resolved_ip}' for target is blocked: {reason}")
    elif t_type_str == "IP":
        allowed, reason = is_ip_allowed(selected_dest, allow_internal=allow_internal)
        if not allowed:
            raise SSRFProtectionError(reason or "Selected target IP violates SSRF policy.")

    auth_ctx = {
        "allow_internal": allow_internal,
        "validated_by": "assert_safe_target",
        "active_probing_granted": bool(active_probing_granted),
        "state_changing_granted": bool(state_changing_granted),
        "dns_zone_authorized": t_type_str == "DOMAIN",
        "cloud_provider": (
            canonical_val.split("://", 1)[0].lower()
            if t_type_str in ("CLOUD_ACCOUNT", "KUBERNETES_CLUSTER") and "://" in canonical_val
            else None
        ),
    }

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
    context_digest = hashlib.sha256(json.dumps(context_material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    integrity_seal = _compute_gateway_seal(target_id, auth_decision_id, policy_version, context_digest)

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
