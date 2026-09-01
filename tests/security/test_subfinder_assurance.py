import pytest
from unittest.mock import AsyncMock

from app.core.models import ScanConfig, Target, TargetType

from app.adapters.subfinder_adapter import SubfinderAdapter


def test_normalization_and_scope_are_deterministic():
    adapter = SubfinderAdapter
    assert adapter.normalize_domain(" API.Example.com. ") == "api.example.com"
    assert adapter.normalize_domain("https://api.example.com") is None
    assert adapter.normalize_domain("127.0.0.1") is None
    assert adapter.classify_scope("api.example.com.", "example.com") == "IN_SCOPE"
    assert adapter.classify_scope("example.net", "example.com") == "OUT_OF_SCOPE"


def test_command_is_structured_and_has_no_client_flags():
    command = SubfinderAdapter.build_command("/opt/subfinder", "Example.com")
    assert command == ["/opt/subfinder", "-d", "example.com", "-silent", "-json", "-timeout", "10", "-max-time", "1"]
    with pytest.raises(ValueError):
        SubfinderAdapter.build_command("/opt/subfinder", "example.com; -all")


def test_unmanaged_binary_cannot_satisfy_assured_execution():
    assert SubfinderAdapter().verify_managed_binary("/usr/local/bin/subfinder") is False


@pytest.mark.asyncio
async def test_wrong_version_fails_closed():
    adapter = SubfinderAdapter()
    assert adapter.APPROVED_VERSION == "v2.6.5"
    assert "subfinder v2.6.4" != f"subfinder {adapter.APPROVED_VERSION}"


@pytest.mark.asyncio
async def test_discovery_never_promotes_out_of_scope_or_resolves_hosts(monkeypatch):
    adapter = SubfinderAdapter()
    emitted = []
    monkeypatch.setattr(adapter, "resolve_binary_path", lambda *_: "/bin/subfinder")
    monkeypatch.setattr(adapter, "verify_managed_binary", lambda *_: True)
    monkeypatch.setattr(adapter, "get_version", AsyncMock(return_value="subfinder v2.6.5"))
    monkeypatch.setattr(adapter, "safe_execute_subprocess", AsyncMock(return_value=(
        0,
        '{"host":"admin.example.com","sources":["crtsh"]}\n'
        '{"host":"outside.example.net","sources":["provider"]}\n'
        "not-json\n",
        "",
    )))
    async def callback(*_args):
        return None

    async def subdomain(value):
        emitted.append(value)

    await adapter.run(Target(name="root", type=TargetType.DOMAIN, value="example.com"), ScanConfig(), callback, callback, emit_subdomain=subdomain)
    assert [item.domain for item in emitted] == ["admin.example.com"]
