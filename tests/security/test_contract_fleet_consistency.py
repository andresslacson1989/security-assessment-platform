"""Regression checks for the authoritative 26-tool contract fleet."""

from pathlib import Path
import re

from app.installers.manager import ToolInstallationManager
from app.installers.tool_manifest import PINNED_TOOL_MANIFEST


EXPECTED_TOOLS = {
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

MATRIX_TOOL_ID_ALIASES = {"RETIRE": "RETIREJS"}


def test_registry_manifest_and_installers_preserve_complete_26_tool_fleet():
    manager_tools = set(ToolInstallationManager()._installers)

    assert set(PINNED_TOOL_MANIFEST) == EXPECTED_TOOLS
    assert manager_tools == EXPECTED_TOOLS


def test_authoritative_contract_mirrors_and_scope_match_26_tool_fleet():
    repository_root = Path(__file__).resolve().parents[2]
    canonical = repository_root / "contracts"
    mirror = repository_root / "docs" / "contracts"

    contract_01 = (canonical / "01_PROJECT_SCOPE_AND_SAFETY_CONTRACT.md").read_text()
    contract_03 = (canonical / "03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md").read_text()
    contract_07 = (canonical / "07_FRONTEND_UI_UX_SPECIFICATION_CONTRACT.md").read_text()
    contract_08 = (canonical / "08_TECHNICAL_IMPLEMENTATION_AND_TEST_VECTORS_CONTRACT.md").read_text()
    contract_09 = (canonical / "09_TOOL_IMPLEMENTATION_CONTRACT.md").read_text()
    assurance_matrix = (repository_root / "docs" / "TOOL_ASSURANCE_MATRIX.md").read_text()
    dockerfile = (repository_root / "Dockerfile").read_text()
    models = (repository_root / "backend" / "app" / "core" / "models.py").read_text()
    frontend_index = (repository_root / "frontend" / "index.html").read_text(encoding="utf-8")

    assert "26 specialized security tool adapters" in contract_01
    assert "across seven security domains" in contract_01
    assert "hashcat" not in contract_01
    assert "john" not in contract_01
    assert "Supported 26 Tools" in contract_03
    assert "26 tools" in contract_07
    assert "`grype`: `v0.74.0`" in contract_08
    assert "`nmap`: `7.95` -> verified official source archive" in contract_08
    assert "complete 26-tool fleet" in contract_09
    assert "21 numbered external-tool specifications" in contract_09
    assert "five auxiliary/manual adapter specifications" in contract_09
    assert "26-tool Enterprise Security Pentesting & Compliance Fleet" in dockerfile
    assert "all 26 available modern adapters" in models
    assert "/ 26 Tools Active" in frontend_index
    assert "all 26 registered tool/native adapters" in (repository_root / "backend" / "app" / "adapters" / "__init__.py").read_text()
    for tool in (
        "nuclei", "ffuf", "gitleaks", "katana", "syft", "grype",
        "osv-scanner", "trufflehog", "dockle", "kube-bench",
    ):
        assert f"COPY --from=builder /tmp/bin/{tool} /app/backend/bin/{tool}" in dockerfile
    assert "write_direct_artifact_trust_record" in dockerfile
    assert "write_source_artifact_trust_record" in dockerfile
    assert "COPY --from=builder /tmp/nmap-root/usr/local/bin/nmap /app/backend/bin/nmap" in dockerfile
    assert "nmap-7.95.tar.bz2" in dockerfile
    assert "does not claim upstream release-binary provenance" in contract_09.lower()
    assert "npm install -g retire" not in dockerfile
    assert "CYBERASSESS_NPM_PREFIX_DIR=/app/backend/.tool-npm" in dockerfile
    assert "build_npm_trust_record" in dockerfile
    matrix_ids = set(re.findall(r"`(TOOL-[A-Z0-9-]+)`", assurance_matrix))
    assert len(matrix_ids) == 26
    expected_matrix_names = {
        MATRIX_TOOL_ID_ALIASES.get(tool.upper(), tool.upper().replace("_", "-"))
        for tool in EXPECTED_TOOLS
    }
    assert expected_matrix_names == {
        tool.removeprefix("TOOL-") for tool in matrix_ids
    }

    for contract_file in canonical.glob("*.md"):
        assert (mirror / contract_file.name).read_text() == contract_file.read_text()
