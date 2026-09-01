"""Contract 03 extended adapter command and fail-closed assurance tests."""

from __future__ import annotations

import pytest

from app.adapters.amass_adapter import AmassAdapter
from app.adapters.hydra_adapter import HydraAdapter
from app.adapters.metasploit_adapter import MetasploitAdapter
from app.adapters.sqlmap_adapter import SqlmapAdapter
from app.core.models import ScanConfig


def test_metasploit_command_is_fixed_to_non_destructive_auxiliary_scanner():
    command = MetasploitAdapter.build_command("msfconsole", "https://example.test", 443)
    script = command[-1]
    assert "auxiliary/scanner/ssl/openssl_heartbleed" in script
    assert "exploit/" not in script
    assert command[:2] == ["msfconsole", "-q"]


def test_sqlmap_command_enforces_bounded_batch_profile():
    command = SqlmapAdapter.build_command("sqlmap", "https://example.test/item?id=1", "C:\\workspace\\sqlmap")
    assert {"--batch", "--level=1", "--risk=1", "--threads=2", "--retries=1"}.issubset(command)
    assert not any(argument in command for argument in ("--dump", "--dump-all", "--os-shell"))


def test_amass_command_is_passive_and_requires_absolute_output():
    command = AmassAdapter.build_command("amass", "example.test", "C:\\workspace\\amass.jsonl")
    assert command[1:4] == ["enum", "-passive", "-d"]
    with pytest.raises(ValueError):
        AmassAdapter.build_command("amass", "example.test", "relative.jsonl")


def test_hydra_command_is_rate_limited_and_rejects_unsafe_inputs():
    command = HydraAdapter.build_command("hydra", "C:\\workspace\\users", "C:\\workspace\\passwords", "ssh", "192.0.2.10", 22, "C:\\workspace\\hydra.json")
    assert command[command.index("-t") + 1] == "2"
    assert command[command.index("-W") + 1] == "1"
    with pytest.raises(ValueError):
        HydraAdapter.build_command("hydra", "C:\\workspace\\users", "C:\\workspace\\passwords", "telnet", "192.0.2.10", 23, "C:\\workspace\\hydra.json")


@pytest.mark.asyncio
async def test_managed_extended_adapter_blocks_runtime_version_mismatch(monkeypatch):
    adapter = MetasploitAdapter()
    monkeypatch.setattr(adapter, "resolve_binary_path", lambda _path=None: "C:\\managed\\msfconsole.exe")
    monkeypatch.setattr(adapter, "verify_managed_binary", lambda _binary: True)

    async def wrong_version(_path=None, pre_launch_check=None):
        return "metasploit 7.0.0"

    monkeypatch.setattr(adapter, "get_version", wrong_version)
    messages = []

    async def emit_log(_level, message):
        messages.append(message)

    result = await adapter._binary_or_block(ScanConfig(), None, emit_log)

    assert result is None
    assert adapter.last_execution_state.value == "EXECUTION_BLOCKED"
    assert any("runtime version" in message or "expected managed version" in message for message in messages)
