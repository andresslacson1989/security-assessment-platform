"""Authoritative tool-fleet identity shared by runtime registries and tests."""

from __future__ import annotations


# Keep every supported capability in this inventory, including native and
# manual-only tools.  Capability mode must not be confused with fleet scope.
SUPPORTED_TOOL_IDS: frozenset[str] = frozenset(
    {
        "amass",
        "bandit",
        "checkov",
        "dockle",
        "ffuf",
        "gitleaks",
        "grype",
        "gtfobins",
        "httpx",
        "hydra",
        "katana",
        "kube-bench",
        "metasploit",
        "nmap",
        "nuclei",
        "osv-scanner",
        "prowler",
        "retire",
        "schemathesis",
        "semgrep",
        "sqlmap",
        "sslyze",
        "subfinder",
        "syft",
        "trivy",
        "trufflehog",
    }
)

SUPPORTED_TOOL_COUNT = 26

if len(SUPPORTED_TOOL_IDS) != SUPPORTED_TOOL_COUNT:  # pragma: no cover
    raise RuntimeError("The authoritative tool fleet must contain exactly 26 tools")
