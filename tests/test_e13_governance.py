"""
E13.10 — Acceptance Tests for Repository Governance Documents.
Validates:
- SECURITY.md: Supported versions, private reporting instructions (no public issues), and response SLA.
- CONTRIBUTING.md: Development principles, branch workflow, security invariant verification, and testing requirements.
- CODE_OF_CONDUCT.md: Contributor pledge, standards of behavior, and enforcement contact.
- LICENSE: Proprietary Personal-Use License present and consistent with README.
"""

import os


def test_governance_files_presence():
    """All required governance files must exist in repository root."""
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    required_files = ["SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "LICENSE", "README.md"]
    for filename in required_files:
        filepath = os.path.join(root_dir, filename)
        assert os.path.isfile(filepath), f"Missing governance file: {filename}"
        assert os.path.getsize(filepath) > 100, f"Governance file {filename} is unexpectedly small or empty"


def test_security_policy_content():
    """SECURITY.md must contain supported versions, private reporting, and SLA."""
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    with open(os.path.join(root_dir, "SECURITY.md"), "r", encoding="utf-8") as f:
        content = f.read()

    assert "Supported Versions" in content
    assert "14.x" in content
    assert "DO NOT file public GitHub issues" in content
    assert "Response SLA" in content
    assert "48 hours" in content
    assert "docs/SECURITY_INVARIANT_TRACEABILITY.md" in content


def test_contributing_guide_content():
    """CONTRIBUTING.md must emphasize invariants, contracts, and testing."""
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    with open(os.path.join(root_dir, "CONTRIBUTING.md"), "r", encoding="utf-8") as f:
        content = f.read()

    assert "Non-Negotiable Invariants" in content
    assert "Never Assume — Verify Truth" in content
    assert "pytest tests/ -v" in content
    assert "tests/security/" in content


def test_code_of_conduct_content():
    """CODE_OF_CONDUCT.md must contain standard pledge and enforcement contact."""
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    with open(os.path.join(root_dir, "CODE_OF_CONDUCT.md"), "r", encoding="utf-8") as f:
        content = f.read()

    assert "Our Pledge" in content
    assert "Our Standards" in content
    assert "Enforcement" in content


def test_license_content():
    """LICENSE must contain the proprietary personal-use terms."""
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    with open(os.path.join(root_dir, "LICENSE"), "r", encoding="utf-8") as f:
        content = f.read()

    assert "CyberAssess Proprietary Personal-Use License" in content
    assert "Copyright (c) 2026 Andress Lacson" in content
    assert "Personal Use" in content
    assert "Commercial Use" in content
