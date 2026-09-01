"""Focused E12 execution-state assurance for the four external DAST adapters."""

import pytest
from unittest.mock import AsyncMock, patch

from app.core.models import NormalizedExecutionState, ScanConfig, Target, TargetType
from app.adapters.nuclei_adapter import NucleiAdapter
from app.adapters.ffuf_adapter import FfufAdapter
from app.adapters.katana_adapter import KatanaAdapter
from app.adapters.schemathesis_adapter import SchemathesisAdapter
from app.engines.web_dast.engine import WebDastAssessmentEngine


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
async def test_e12_nonzero_output_is_partial_not_success():
    adapter = NucleiAdapter()
    config = ScanConfig()
    with patch.object(adapter, "resolve_binary_path", return_value="/bin/nuclei"), \
         patch.object(adapter, "execute_command", new=AsyncMock(return_value=(1, "not-json\n", "partial"))):
        await adapter.run(TARGET, config, AsyncMock(), AsyncMock())

    assert adapter.last_execution_state == NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING


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
