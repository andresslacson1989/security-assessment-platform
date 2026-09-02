"""Regression checks for security-sensitive frontend capability semantics."""

from pathlib import Path


FRONTEND_APP = Path(__file__).parents[1] / "frontend" / "js" / "app.js"


def test_capability_ui_uses_execution_mode_not_binary_availability():
    source = FRONTEND_APP.read_text(encoding="utf-8")

    assert source.count("async loadSystemCapabilities()") == 1
    assert 'tool.execution_mode === "ADAPTER_ACTIVE" || tool.available' not in source
    assert 'tool.execution_mode === "ADAPTER_ACTIVE"' in source
    assert 'this.authFetch("/api/system/capabilities")' in source
