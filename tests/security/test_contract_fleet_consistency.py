"""Regression checks for the authoritative 26-tool contract fleet."""

from pathlib import Path
import re

from app.adapters import get_adapter_registry
from app.installers.manager import ToolInstallationManager
from app.installers.tool_manifest import PINNED_TOOL_MANIFEST
from app.core.tool_fleet import SUPPORTED_TOOL_COUNT, SUPPORTED_TOOL_IDS


EXPECTED_TOOLS = SUPPORTED_TOOL_IDS

MATRIX_TOOL_ID_ALIASES = {"RETIRE": "RETIREJS"}


def test_registry_manifest_and_installers_preserve_complete_26_tool_fleet():
    assert SUPPORTED_TOOL_COUNT == 26
    assert len(EXPECTED_TOOLS) == SUPPORTED_TOOL_COUNT
    registry_tools = set(get_adapter_registry())
    manager_tools = set(ToolInstallationManager()._installers)

    assert registry_tools == EXPECTED_TOOLS
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
    assert "one assurance entry for each supported tool" in assurance_matrix
    assert "numbered external-tool reviews" not in assurance_matrix
    assurance_review_sections = re.findall(
        r"^### (\d+)\.", assurance_matrix, re.MULTILINE
    )
    assert assurance_review_sections == [str(index) for index in range(1, 27)]
    matrix_tool_ids = set(re.findall(r"\| `(TOOL-[A-Z0-9_-]+)` \|", assurance_matrix))
    assert len(matrix_tool_ids) == 26
    expected_matrix_ids = {
        f"TOOL-{tool.upper().replace('_', '-')}" for tool in EXPECTED_TOOLS
    }
    expected_matrix_ids.discard("TOOL-RETIRE")
    expected_matrix_ids.add("TOOL-RETIREJS")
    assert matrix_tool_ids == expected_matrix_ids
    assert "Part II defines all 26 supported tools" in contract_09
    assert "five auxiliary/manual adapter specifications" in contract_09
    detailed_sections = re.findall(r"^## TOOL (\d{2}):", contract_09, re.MULTILINE)
    assert detailed_sections == [f"{index:02d}" for index in range(1, 27)]
    traceability_rows = [line for line in contract_09.splitlines() if line.startswith("| `TOOL-")]
    traceability_ids = {line.split("|")[1].strip().strip("`") for line in traceability_rows}
    assert len(traceability_rows) == 26
    assert {"TOOL-AMASS", "TOOL-METASPLOIT", "TOOL-SQLMAP", "TOOL-HYDRA", "TOOL-GTFOBINS"}.issubset(traceability_ids)
    assert "26-tool Enterprise Security Pentesting & Compliance Fleet" in dockerfile
    assert "all 26 available modern adapters" in models
    config_fields = set(re.findall(r"^    enable_([a-z0-9_]+):", models, re.MULTILINE))
    expected_config_fields = {tool.replace("-", "_") for tool in EXPECTED_TOOLS}
    expected_config_fields.discard("retire")
    expected_config_fields.add("retirejs")
    assert config_fields == expected_config_fields
    assert "FLEET (26):" in frontend_index
    frontend_tool_ids = set(re.findall(r'id="tool-pill-([a-z0-9-]+)"', frontend_index))
    assert frontend_tool_ids == EXPECTED_TOOLS
    assert len(frontend_tool_ids) == 26
    assert "all 26 registered tool/native adapters" in (repository_root / "backend" / "app" / "adapters" / "__init__.py").read_text()
    for tool in (
        "nuclei", "ffuf", "gitleaks", "katana", "syft", "grype",
        "osv-scanner", "trufflehog", "dockle", "kube-bench",
    ):
        assert f"COPY --from=builder /tmp/bin/{tool} /app/backend/bin/{tool}" in dockerfile
    assert "write_direct_artifact_trust_record" in dockerfile
    assert "write_source_artifact_trust_record" in dockerfile
    assert "COPY --from=builder /tmp/nmap-root/usr/local/bin/nmap /app/backend/bin/nmap" in dockerfile
    assert "COPY --from=builder /tmp/bin/amass /app/backend/bin/amass" in dockerfile
    assert "COPY --from=builder /tmp/bin/resources /app/backend/bin/resources" in dockerfile
    assert "amass_linux_amd64.tar.gz" in dockerfile
    assert "nmap-7.95.tar.bz2" in dockerfile
    assert 'TARGETARCH" != "amd64"' in dockerfile
    assert "does not claim upstream release-binary provenance" in contract_09.lower()
    assert "no active a/aaaa/cname dns resolution" in contract_03.lower()
    assert 'correlates active IP DNS resolutions' not in contract_03
    assert 'dns_status="UNRESOLVED"' in contract_03
    assert "-s crtsh" in contract_03
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
