"""Allowlist enforcement for platform-owned passive provider requests."""

from __future__ import annotations

from urllib.parse import urlsplit


class ProviderEgressViolation(ValueError):
    """Raised when a provider request is outside its server policy."""


PROVIDER_HOST_ALLOWLIST = {
    "crtsh": frozenset({"crt.sh"}),
    "certspotter": frozenset({"api.certspotter.com"}),
}


def assert_provider_url(provider: str, url: str) -> str:
    """Require an HTTPS URL to the exact host assigned to a provider.

    This is an application-layer control for platform-owned HTTP clients. It
    deliberately rejects userinfo, explicit ports, IP literals, and unknown
    providers. External tool network namespaces remain an infrastructure
    responsibility and are not implied by this helper.
    """
    allowed_hosts = PROVIDER_HOST_ALLOWLIST.get(str(provider).strip().lower())
    if not allowed_hosts or not isinstance(url, str):
        raise ProviderEgressViolation("provider is not enabled by egress policy")

    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ProviderEgressViolation("provider URL has an invalid port") from exc
    hostname = (parsed.hostname or "").rstrip(".").lower()
    if (
        parsed.scheme.lower() != "https"
        or hostname not in allowed_hosts
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or not parsed.path.startswith("/")
    ):
        raise ProviderEgressViolation("provider URL is outside the exact HTTPS destination allowlist")
    return url
