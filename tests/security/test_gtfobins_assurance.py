"""Contract 03 §4.5 / Contract 08 §6.5 native GTFOBins assurance tests."""

from __future__ import annotations

from app.adapters.gtfobins_adapter import evaluate_host_audit


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


def test_gtfobins_does_not_execute_or_accept_non_catalog_commands():
    findings = evaluate_host_audit(
        {
            "suid_binaries": ["/tmp/attacker-tool"],
            "sudo_rules": ["(ALL) NOPASSWD: /usr/bin/systemctl"],
            "capabilities": ["/usr/bin/custom-helper = cap_setuid+ep"],
        },
        scan_id="scan-empty",
    )
    assert findings == []


def test_gtfobins_matches_versioned_python_catalog_entry():
    findings = evaluate_host_audit(
        {"capabilities": ["/usr/bin/python3.11 = cap_setuid+ep"]},
        scan_id="scan-python",
    )
    assert [finding.check_id for finding in findings] == ["HOST-PRIV-001"]
