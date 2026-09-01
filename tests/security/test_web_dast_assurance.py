"""Focused E12 execution-state assurance for the four external DAST adapters."""

import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import httpx

from app.core.models import NormalizedExecutionState, ScanConfig, Target, TargetType
from app.adapters.nuclei_adapter import NucleiAdapter
from app.adapters.ffuf_adapter import FfufAdapter
from app.adapters.katana_adapter import KatanaAdapter
from app.adapters.schemathesis_adapter import SchemathesisAdapter
from app.engines.web_dast.engine import WebDastAssessmentEngine
from app.core.ssrf_protector import ValidatedTargetTransport


TARGET = Target(name="Example", type=TargetType.URL, value="https://example.com")


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


@pytest.mark.asyncio
async def test_nuclei_command_binds_validated_destination_and_preserves_host():
    adapter = NucleiAdapter()
    captured = []

    async def capture_command(command, **kwargs):
        captured.append(command)
        return 0, "", ""

    validated = SimpleNamespace(selected_destination="93.184.216.34")
    with patch.object(adapter, "resolve_binary_path", return_value="/managed/nuclei"), \
         patch.object(adapter, "get_version", new=AsyncMock(return_value="nuclei v3.2.0")), \
         patch.object(adapter, "execute_command", new=capture_command):
        await adapter.run(TARGET, ScanConfig(), AsyncMock(), AsyncMock(), validated_target=validated)

    assert "https://93.184.216.34" in captured[-1]
    assert "Host: example.com" in captured[-1]


@pytest.mark.asyncio
async def test_validated_http_transport_pins_address_and_rejects_origin_escape():
    validated = SimpleNamespace(
        canonical_value="https://example.com",
        selected_destination="93.184.216.34",
    )
    transport = ValidatedTargetTransport(validated)
    response = httpx.Response(200, request=httpx.Request("GET", "https://93.184.216.34/"))
    transport._transport.handle_async_request = AsyncMock(return_value=response)

    request = httpx.Request("GET", "https://example.com/login")
    await transport.handle_async_request(request)
    assert request.url.host == "93.184.216.34"
    assert request.headers["host"] == "example.com"

    with pytest.raises(ValueError, match="escaped validated origin"):
        await transport.handle_async_request(httpx.Request("GET", "https://attacker.example/"))


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
