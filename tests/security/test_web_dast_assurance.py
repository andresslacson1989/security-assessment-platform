"""Focused E12 execution-state assurance for the four external DAST adapters."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from app.core.models import NormalizedExecutionState, ScanConfig, Target, TargetType, sanitize_reproduction_curl
from app.adapters.nuclei_adapter import NucleiAdapter
from app.adapters.ffuf_adapter import FfufAdapter
from app.adapters.katana_adapter import KatanaAdapter
from app.adapters.schemathesis_adapter import SchemathesisAdapter
from app.engines.web_dast.engine import WebDastAssessmentEngine
from app.core.ssrf_protector import (
    ValidatedTargetTransport,
    create_validated_target,
    validate_validated_target,
)


TARGET = Target(name="Example", type=TargetType.URL, value="https://example.com")


def make_validated_target():
    with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
        return create_validated_target(TARGET, asset_id="asset-test", active_probing_granted=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter_cls, path_attr", [
    (NucleiAdapter, "nuclei_path"),
    (FfufAdapter, "ffuf_path"),
    (KatanaAdapter, "katana_path"),
    (SchemathesisAdapter, "schemathesis_path"),
])
async def test_missing_e12_binary_is_explicit_failure(adapter_cls, path_attr):
    adapter = adapter_cls()
    config = ScanConfig()
    setattr(config.adapters, path_attr, None)

    with patch.object(adapter, "resolve_binary_path", return_value=None):
        findings = await adapter.run(TARGET, config, AsyncMock(), AsyncMock())

    assert findings == []
    assert adapter.last_execution_state == NormalizedExecutionState.TOOL_EXECUTION_FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter_cls, path_attr, reported_version", [
    (NucleiAdapter, "nuclei_path", "nuclei v3.2.50"),
    (FfufAdapter, "ffuf_path", "ffuf 2.1.0-dev"),
    (KatanaAdapter, "katana_path", "katana v1.0.4"),
    (SchemathesisAdapter, "schemathesis_path", "schemathesis 3.21.0"),
])
async def test_wrong_e12_version_blocks_execution(adapter_cls, path_attr, reported_version):
    adapter = adapter_cls()
    config = ScanConfig()
    setattr(config.adapters, path_attr, None)
    execute = AsyncMock(return_value=(0, "should not launch", ""))

    with patch.object(adapter, "resolve_binary_path", return_value="/managed/tool"), \
         patch.object(adapter, "get_version", new=AsyncMock(return_value=reported_version)), \
         patch.object(adapter, "execute_command", new=execute):
        findings = await adapter.run(TARGET, config, AsyncMock(), AsyncMock())

    assert findings == []
    assert adapter.last_execution_state == NormalizedExecutionState.INVALID_VERSION
    execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_e12_nonzero_output_is_partial_not_success():
    adapter = NucleiAdapter()
    config = ScanConfig()
    with patch.object(adapter, "resolve_binary_path", return_value="/bin/nuclei"), \
         patch.object(adapter, "get_version", new=AsyncMock(return_value="nuclei v3.2.0")), \
         patch.object(adapter, "execute_command", new=AsyncMock(return_value=(1, "not-json\n", "partial"))):
        await adapter.run(TARGET, config, AsyncMock(), AsyncMock())

    assert adapter.last_execution_state == NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING


def test_e12_reproduction_commands_redact_headers_and_query_secrets():
    command = 'curl -H "Authorization: Bearer super-secret-token" -H "X-Auth-Token: header-secret" "https://example.com/?access_token=another-secret&safe=1"'
    sanitized = sanitize_reproduction_curl(command)
    assert sanitized is not None
    assert "super-secret-token" not in sanitized
    assert "header-secret" not in sanitized
    assert "another-secret" not in sanitized
    assert "[REDACTED]" in sanitized


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter_cls, path_attr", [
    (NucleiAdapter, "nuclei_path"),
    (FfufAdapter, "ffuf_path"),
    (KatanaAdapter, "katana_path"),
    (SchemathesisAdapter, "schemathesis_path"),
])
async def test_e12_unmanaged_binary_is_policy_blocked(adapter_cls, path_attr):
    adapter = adapter_cls()
    config = ScanConfig()
    setattr(config.adapters, path_attr, None)
    with patch.object(adapter, "resolve_binary_path", return_value="/managed/tool"), \
         patch.object(adapter, "verify_managed_binary", return_value=False), \
         patch.object(adapter, "execute_command", new=AsyncMock()) as execute:
        await adapter.run(TARGET, config, AsyncMock(), AsyncMock(), require_managed_binary=True)

    assert adapter.last_execution_state == NormalizedExecutionState.EXECUTION_BLOCKED
    execute.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter_cls, path_attr", [
    (NucleiAdapter, "nuclei_path"),
    (FfufAdapter, "ffuf_path"),
])
async def test_e12_intrusive_adapters_require_active_authorization(adapter_cls, path_attr):
    adapter = adapter_cls()
    config = ScanConfig()
    setattr(config.adapters, path_attr, None)
    with patch.object(adapter, "resolve_binary_path", return_value="/managed/tool"), \
         patch.object(adapter, "verify_managed_binary", return_value=True), \
         patch.object(adapter, "execute_command", new=AsyncMock()) as execute, \
         patch.object(adapter, "get_version", new=AsyncMock(return_value="approved version")):
        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
            validated = create_validated_target(TARGET, active_probing_granted=False)
        await adapter.run(
            TARGET,
            config,
            AsyncMock(),
            AsyncMock(),
            require_managed_binary=True,
            validated_target=validated,
        )

    assert adapter.last_execution_state == NormalizedExecutionState.EXECUTION_BLOCKED
    execute.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter_cls, path_attr, version", [
    (NucleiAdapter, "nuclei_path", "nuclei v3.2.0"),
    (FfufAdapter, "ffuf_path", "FFuF 2.1.0"),
    (KatanaAdapter, "katana_path", "katana v1.0.5"),
    (SchemathesisAdapter, "schemathesis_path", "schemathesis 3.20.0"),
])
async def test_e12_managed_execution_passes_prelaunch_check_to_process_boundary(adapter_cls, path_attr, version):
    adapter = adapter_cls()
    config = ScanConfig()
    setattr(config.adapters, path_attr, None)
    launches = []
    validated = make_validated_target()

    async def capture(command, **kwargs):
        launches.append((command, kwargs))
        return 0, "", ""

    with patch.object(adapter, "resolve_binary_path", return_value="/managed/tool"), \
         patch.object(adapter, "verify_managed_binary", return_value=True), \
         patch("app.adapters.nuclei_adapter.verify_managed_nuclei_templates", return_value=True), \
         patch.object(adapter, "get_version", new=AsyncMock(return_value=version)), \
         patch.object(adapter, "execute_command", new=capture):
        await adapter.run(
            TARGET,
            config,
            AsyncMock(),
            AsyncMock(),
            require_managed_binary=True,
            validated_target=validated,
        )
        assert len(launches) >= 1
        assert callable(launches[-1][1]["pre_launch_check"])
        assert launches[-1][1]["pre_launch_check"]() is True


@pytest.mark.asyncio
async def test_nuclei_command_binds_validated_destination_and_preserves_host():
    adapter = NucleiAdapter()
    captured = []

    async def capture_command(command, **kwargs):
        captured.append(command)
        return 0, "", ""

    validated = make_validated_target()
    with patch.object(adapter, "resolve_binary_path", return_value="/managed/nuclei"), \
         patch.object(adapter, "get_version", new=AsyncMock(return_value="nuclei v3.2.0")), \
         patch.object(adapter, "execute_command", new=capture_command):
        await adapter.run(TARGET, ScanConfig(), AsyncMock(), AsyncMock(), validated_target=validated)

    assert "https://93.184.216.34" in captured[-1]
    assert "Host: example.com" in captured[-1]


@pytest.mark.asyncio
async def test_katana_discards_out_of_origin_endpoint_observations():
    adapter = KatanaAdapter()
    validated = make_validated_target()
    endpoints = []
    output = (
        '{"request":{"endpoint":"https://example.com/account"}}\n'
        '{"request":{"endpoint":"https://attacker.example/exfil"}}\n'
    )

    async def capture_endpoint(endpoint):
        endpoints.append(endpoint)

    with patch.object(adapter, "resolve_binary_path", return_value="/bin/katana"), \
         patch.object(adapter, "get_version", new=AsyncMock(return_value="katana v1.0.5")), \
         patch.object(adapter, "execute_command", new=AsyncMock(return_value=(0, output, ""))):
        await adapter.run(
            TARGET,
            ScanConfig(),
            AsyncMock(),
            AsyncMock(),
            validated_target=validated,
            emit_endpoint=capture_endpoint,
        )

    assert [endpoint.url for endpoint in endpoints] == ["https://example.com/account"]


@pytest.mark.asyncio
async def test_validated_http_transport_pins_address_and_rejects_origin_escape():
    validated = make_validated_target()
    transport = ValidatedTargetTransport(validated)
    response = httpx.Response(200, request=httpx.Request("GET", "https://93.184.216.34/"))
    transport._transport.handle_async_request = AsyncMock(return_value=response)

    request = httpx.Request("GET", "https://example.com/login")
    await transport.handle_async_request(request)
    assert request.url.host == "example.com"
    assert request.headers["host"] == "example.com"

    with pytest.raises(ValueError, match="escaped validated origin"):
        await transport.handle_async_request(httpx.Request("GET", "https://attacker.example/"))


def test_validated_target_rejects_tampered_authorization_context():
    validated = make_validated_target()
    validated.authorized_scope.append("attacker.example")

    with pytest.raises(ValueError, match="integrity seal"):
        validate_validated_target(validated)


def test_validated_target_rejects_lookalike_object():
    with pytest.raises(ValueError, match="gateway-issued ValidatedTarget"):
        validate_validated_target({"selected_destination": "93.184.216.34"})


@pytest.mark.asyncio
async def test_web_dast_blocks_private_target_before_adapter_execution():
    states = []
    config = ScanConfig()
    config.adapters.enable_ffuf = True
    config.adapters.enable_nuclei = True
    config.adapters.enable_katana = True
    config.adapters.enable_schemathesis = True

    async def capture_state(tool, state):
        states.append((tool, state))

    findings = await WebDastAssessmentEngine().run(
        Target(name="Internal", type=TargetType.URL, value="http://127.0.0.1"),
        config, AsyncMock(), AsyncMock(), AsyncMock(),
        emit_tool_execution_state=capture_state,
    )

    assert findings == []
    assert states == [
        ("ffuf", "EXECUTION_BLOCKED"),
        ("nuclei", "EXECUTION_BLOCKED"),
        ("katana", "EXECUTION_BLOCKED"),
        ("schemathesis", "EXECUTION_BLOCKED"),
    ]


@pytest.mark.asyncio
async def test_schemathesis_state_changing_probe_requires_explicit_grant():
    config = ScanConfig()
    config.crawler.enabled = False
    config.adapters.enable_ffuf = False
    config.adapters.enable_nuclei = False
    config.adapters.enable_katana = False
    states = []

    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=httpx.Response(200, text="<html></html>"))

    async def capture_state(tool, state):
        states.append((tool, state))

    with patch.object(SchemathesisAdapter, "is_available", new=AsyncMock(return_value=True)), \
         patch.object(SchemathesisAdapter, "run", new=AsyncMock()) as run_mock, \
         patch("app.engines.web_dast.engine.httpx.AsyncClient", return_value=mock_client), \
         patch("app.engines.web_dast.engine.audit_security_headers_and_cookies", new=AsyncMock(return_value=[])), \
         patch("app.engines.web_dast.engine.audit_cors_policies", new=AsyncMock(return_value=[])), \
         patch("app.engines.web_dast.engine.audit_sensitive_exposure_and_methods", new=AsyncMock(return_value=[])), \
         patch("app.engines.web_dast.engine.audit_browser_posture", new=AsyncMock(return_value=[])), \
         patch("app.engines.web_dast.engine.audit_graphql_endpoints", new=AsyncMock(return_value=[])), \
         patch("app.engines.web_dast.engine.audit_parameter_fuzzing", new=AsyncMock(return_value=[])):
        await WebDastAssessmentEngine().run(
            Target(name="API", type=TargetType.URL, value="https://example.com"),
            config, AsyncMock(), AsyncMock(), AsyncMock(),
            organization_id="org-test", emit_tool_execution_state=capture_state,
        )

    run_mock.assert_not_awaited()
    assert ("schemathesis", "EXECUTION_BLOCKED") in states
