"""Contract 03 §4.5 / Contract 08 §6.5 native GTFOBins assurance tests."""

from __future__ import annotations

import json

from app.adapters.gtfobins_adapter import evaluate_host_audit, GTFOBINS_CATALOG_REVISION
from app.adapters.gtfobins_adapter import GTFOBinsAdapter
from app.core.models import LogLevel, ScanConfig, Target, TargetType, NormalizedExecutionState
import pytest


def test_gtfobins_fixture_emits_only_canonical_privilege_findings():
    """SEC-034: GTFOBins evaluates only canonical host privilege findings."""
    findings = evaluate_host_audit(
        {
            "suid_binaries": ["/usr/bin/find", "/usr/bin/passwd"],
            "sudo_rules": ["(ALL) NOPASSWD: /usr/bin/vim", "(ALL) NOPASSWD: /usr/bin/systemctl"],
            "capabilities": ["/usr/bin/python3.11 = cap_setuid+ep"],
        },
        scan_id="scan-gtfo",
        organization_id="org-test",
    )
    assert {finding.check_id for finding in findings} == {"HOST-PRIV-001", "HOST-SUDO-001"}
    assert all(finding.source_tool == "gtfobins" for finding in findings)
    assert all(finding.organization_id == "org-test" for finding in findings)
    assert not any("systemctl" in finding.evidence.raw_response_snippet for finding in findings)
    evidence = json.loads(findings[0].evidence.raw_response_snippet)
    assert evidence["catalog_revision"] == GTFOBINS_CATALOG_REVISION
    assert len(evidence["catalog_revision"]) == 64


def test_gtfobins_does_not_execute_or_accept_non_catalog_commands():
    findings = evaluate_host_audit(
        {
            "suid_binaries": ["/tmp/attacker-tool"],
            "sudo_rules": ["(ALL) NOPASSWD: /usr/bin/systemctl"],
            "capabilities": ["/usr/bin/custom-helper = cap_setuid+ep"],
        },
        scan_id="scan-empty",
        organization_id="org-test",
    )
    assert findings == []


def test_gtfobins_matches_versioned_python_catalog_entry():
    findings = evaluate_host_audit(
        {"capabilities": ["/usr/bin/python3.11 = cap_setuid+ep"]},
        scan_id="scan-python",
        organization_id="org-test",
    )
    assert [finding.check_id for finding in findings] == ["HOST-PRIV-001"]


def test_gtfobins_evaluator_rejects_missing_tenant_identity():
    with pytest.raises(ValueError, match="organization ID"):
        evaluate_host_audit(
            {"suid_binaries": ["/usr/bin/find"]},
            scan_id="scan-no-tenant",
        )


@pytest.mark.asyncio
async def test_gtfobins_adapter_requires_authoritative_tenant_context():
    adapter = GTFOBinsAdapter()
    logs = []

    async def emit_log(level: LogLevel, message: str):
        logs.append((level, message))

    async def emit_finding(_finding):
        raise AssertionError("tenant-less GTFOBins execution must not emit findings")

    findings = await adapter.run(
        Target(name="Local", type=TargetType.LOCAL_PATH, value="C:\\workspace"),
        ScanConfig(),
        emit_log,
        emit_finding,
        host_audit_input={"suid_binaries": ["/usr/bin/find"]},
    )

    assert findings == []
    assert adapter.last_execution_state == NormalizedExecutionState.EXECUTION_BLOCKED
    assert any("organization context" in message for _, message in logs)
