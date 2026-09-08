"""Regression checks for the authoritative 26-tool contract fleet."""

import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess

import pytest

MATRIX_TOOL_ID_ALIASES = {"RETIRE": "RETIREJS"}


def _read_porcelain_status_entries(repository_root: Path) -> list[dict[str, str]]:
    result = subprocess.run(
        [
            "git",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--no-renames",
            "-z",
        ],
        cwd=repository_root,
        check=True,
        stdout=subprocess.PIPE,
    )
    records = result.stdout.split(b"\0")
    assert records[-1] == b""
    entries = []
    for record in records[:-1]:
        assert len(record) >= 3 and record[2:3] == b" "
        entries.append(
            {
                "state": record[:2].decode("ascii"),
                "path": record[3:].decode("utf-8"),
            }
        )
    return sorted(entries, key=lambda entry: entry["path"])


def _inventory_digest(entries: list[dict[str, str]], include_state: bool) -> str:
    if include_state:
        values = [f"{entry['state']}\t{entry['path']}" for entry in entries]
    else:
        values = [entry["path"] for entry in entries]
    return hashlib.sha256("\n".join(values).encode("utf-8")).hexdigest()


def _is_ci_path(entry: dict[str, str]) -> bool:
    return entry["path"] == ".ci" or entry["path"].startswith(".ci/")


def _git_text(repository_root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository_root,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _checkpoint_change_to_pre_publication_status(status: str, path: str) -> dict[str, str]:
    status_mapping = {"M": " M", "A": "??"}
    assert status in status_mapping, f"unsupported checkpoint transition status: {status}"
    entry = {"state": status_mapping[status], "path": path}
    assert not _is_ci_path(entry), f"checkpoint transition contains forbidden .ci path: {path}"
    assert path != "data/cyberassess.db", "checkpoint transition contains the runtime database"
    return entry


def _read_checkpoint_transition_entries(
    repository_root: Path,
    pre_publication_head: str,
    checkpoint_commit: str,
) -> list[dict[str, str]]:
    result = subprocess.run(
        [
            "git",
            "diff",
            "--name-status",
            "--no-renames",
            "-z",
            pre_publication_head,
            checkpoint_commit,
            "--",
        ],
        cwd=repository_root,
        check=True,
        stdout=subprocess.PIPE,
    )
    fields = result.stdout.split(b"\0")
    assert fields[-1] == b""
    fields = fields[:-1]
    assert len(fields) % 2 == 0

    entries = []
    for offset in range(0, len(fields), 2):
        status = fields[offset].decode("ascii")
        path = fields[offset + 1].decode("utf-8")
        entries.append(_checkpoint_change_to_pre_publication_status(status, path))
    return sorted(entries, key=lambda entry: entry["path"])


def _manifest_reference_path_and_locator(reference: str | dict[str, str]) -> tuple[str, str | None]:
    assert isinstance(reference, (str, dict))
    if isinstance(reference, str):
        assert reference == reference.strip()
        if " §" in reference:
            assert reference.count(" §") == 1
            path, locator = reference.split(" §", 1)
            assert path and locator.strip()
            return path, locator.strip()
        return reference, None

    assert set(reference) == {"path", "locator"}
    path = reference["path"]
    locator = reference["locator"]
    assert path == path.strip() and path
    assert locator == locator.strip() and locator
    return path, locator


def _assert_manifest_reference(repository_root: Path, reference: str | dict[str, str]) -> None:
    path_text, locator = _manifest_reference_path_and_locator(reference)
    relative_path = Path(path_text)
    assert not relative_path.is_absolute()
    assert ".." not in relative_path.parts
    referenced_path = repository_root / relative_path
    assert referenced_path.is_file(), path_text
    if locator is not None:
        assert "\r" not in locator and "\n" not in locator
        assert locator in referenced_path.read_text(encoding="utf-8")


def _qualified_python_symbols(source_path: Path) -> set[str]:
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    symbols: set[str] = set()

    def visit(nodes: list[ast.AST], prefix: tuple[str, ...] = ()) -> None:
        for node in nodes:
            if isinstance(node, ast.ClassDef):
                qualified = (*prefix, node.name)
                symbols.add("::".join(qualified))
                visit(node.body, qualified)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = (*prefix, node.name)
                symbols.add("::".join(qualified))

    visit(tree.body)
    return symbols


def _assert_manifest_test_vector(repository_root: Path, vector: str) -> None:
    assert isinstance(vector, str) and vector == vector.strip() and vector
    components = vector.split("::")
    test_path = repository_root / Path(components[0])
    assert not Path(components[0]).is_absolute()
    assert ".." not in Path(components[0]).parts
    assert test_path.is_file(), vector
    if len(components) > 1:
        qualified_symbol = "::".join(components[1:])
        assert qualified_symbol in _qualified_python_symbols(test_path), vector


def test_registry_manifest_and_installers_preserve_complete_26_tool_fleet():
    from app.adapters import get_adapter_registry
    from app.installers.manager import ToolInstallationManager
    from app.installers.tool_manifest import PINNED_TOOL_MANIFEST
    from app.core.tool_fleet import SUPPORTED_TOOL_COUNT, SUPPORTED_TOOL_IDS

    expected_tools = SUPPORTED_TOOL_IDS
    assert SUPPORTED_TOOL_COUNT == 26
    assert len(expected_tools) == SUPPORTED_TOOL_COUNT
    registry_tools = set(get_adapter_registry())
    manager_tools = set(ToolInstallationManager()._installers)

    assert registry_tools == expected_tools
    assert set(PINNED_TOOL_MANIFEST) == expected_tools
    assert manager_tools == expected_tools


def test_contract_05_provider_authority_and_database_delivery_policy():
    repository_root = Path(__file__).resolve().parents[2]
    canonical_path = repository_root / "contracts" / "05_DELIVERABLES_AND_ACCEPTANCE_CRITERIA_CONTRACT.md"
    mirror_path = repository_root / "docs" / "contracts" / canonical_path.name
    contract_05 = canonical_path.read_text(encoding="utf-8")
    normalized_contract_05 = " ".join(contract_05.split())

    assert "GitHub Actions is the sole authoritative CI/CD" in normalized_contract_05
    assert "GitLab is a repository mirror only" in normalized_contract_05
    assert "GitLab CI/CD results are separately attributable diagnostics" in normalized_contract_05
    assert "GitLab may be the authoritative CI/CD provider" not in normalized_contract_05
    assert "GitLab alone is authoritative" not in normalized_contract_05
    assert "An exact-path read-only inspection is permitted" in normalized_contract_05
    assert "MUST NOT be modified, staged, committed, mirrored, archived, published" in normalized_contract_05
    section_2_position = contract_05.find("## 2. Mandatory Adversarial Security Matrix (SEC-001 to SEC-035)")
    section_3_position = contract_05.find("## 3. Repository Delivery and Provider Promotion")
    sec_001_position = contract_05.find("| **SEC-001**")
    sec_035_position = contract_05.find("| **SEC-035**")
    assert section_2_position >= 0
    assert section_3_position >= 0
    assert sec_001_position >= 0
    assert sec_035_position >= 0
    assert section_2_position < sec_001_position < sec_035_position < section_3_position
    section_3 = contract_05[section_3_position:]
    normalized_section_3 = " ".join(section_3.split())
    assert "GitHub Actions is the sole authoritative CI/CD" in normalized_section_3
    assert "GitLab is a repository mirror only" in normalized_section_3
    assert "An exact-path read-only inspection is permitted" in normalized_section_3
    assert canonical_path.read_bytes() == mirror_path.read_bytes()


def test_worktree_inventory_snapshot_matches_documented_git_serialization():
    repository_root = Path(__file__).resolve().parents[2]
    inventory_path = repository_root / "docs" / "evidence" / "section_a_worktree_inventory_2026-09-08.json"
    if not inventory_path.is_file():
        pytest.skip("dirty-worktree evidence snapshot is not present in this checkout")

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    assert inventory["schema"] == "cyberassess.section_a.worktree_inventory.v2"
    assert inventory["snapshot_kind"] == "HISTORICAL_PRE_PUBLICATION_WORKTREE"
    git_status = inventory["git_status"]
    checkpoint = inventory["checkpoint"]
    pre_publication_head = inventory["head"]
    checkpoint_commit = checkpoint["commit"]

    assert re.fullmatch(r"[0-9a-f]{40}", pre_publication_head)
    assert re.fullmatch(r"[0-9a-f]{40}", checkpoint_commit)
    assert re.fullmatch(r"[0-9a-f]{40}", checkpoint["tree"])
    assert checkpoint["parent"] == pre_publication_head
    assert _git_text(repository_root, "show", "-s", "--format=%P", checkpoint_commit).split() == [
        pre_publication_head
    ]
    assert _git_text(repository_root, "rev-parse", f"{checkpoint_commit}^") == pre_publication_head
    assert _git_text(repository_root, "rev-parse", f"{checkpoint_commit}^{{tree}}") == checkpoint["tree"]
    assert int(_git_text(repository_root, "rev-list", "--count", checkpoint_commit)) == checkpoint[
        "reachable_history_count"
    ]
    assert subprocess.run(
        ["git", "merge-base", "--is-ancestor", checkpoint_commit, "HEAD"],
        cwd=repository_root,
        check=False,
    ).returncode == 0
    current_branch = _git_text(repository_root, "branch", "--show-current")
    if current_branch:
        assert current_branch == inventory["branch"]

    expected_transition_command = (
        f"git diff --name-status --no-renames -z {pre_publication_head} "
        f"{checkpoint_commit} --"
    )
    assert checkpoint["transition_command"] == expected_transition_command
    assert checkpoint["status_mapping"] == {"M": " M", "A": "??"}

    reconstructed_non_ci = _read_checkpoint_transition_entries(
        repository_root,
        pre_publication_head,
        checkpoint_commit,
    )
    recorded_non_ci = sorted(git_status["non_ci_entries"], key=lambda entry: entry["path"])
    assert recorded_non_ci == reconstructed_non_ci
    assert len(recorded_non_ci) == len({entry["path"] for entry in recorded_non_ci})
    assert all(entry["state"] in {" M", "??"} for entry in recorded_non_ci)
    assert all(entry["path"] != "data/cyberassess.db" for entry in recorded_non_ci)
    assert all(not _is_ci_path(entry) for entry in recorded_non_ci)

    checkpoint_tree_paths = set(
        _git_text(repository_root, "ls-tree", "-r", "--name-only", checkpoint_commit).splitlines()
    )
    assert ".ci" not in checkpoint_tree_paths
    assert all(not path.startswith(".ci/") for path in checkpoint_tree_paths)
    assert "data/cyberassess.db" not in checkpoint_tree_paths
    assert inventory["runtime_database"] == {
        "path": "data/cyberassess.db",
        "delivery_scope": "outside",
        "included_in_inventory": False,
        "modification_authorized": False,
    }

    current_entries = _read_porcelain_status_entries(repository_root)
    current_ci_entries = [entry for entry in current_entries if _is_ci_path(entry)]
    assert all(entry["path"] != "data/cyberassess.db" for entry in current_entries)

    assert git_status["non_ci_entry_count"] == len(recorded_non_ci)
    assert git_status["non_ci_entry_count"] == 106
    assert git_status["state_counts"]["non_ci"] == dict(
        Counter(entry["state"] for entry in recorded_non_ci)
    )
    assert git_status["non_ci_path_sha256"] == _inventory_digest(recorded_non_ci, False)
    assert git_status["non_ci_state_path_sha256"] == _inventory_digest(recorded_non_ci, True)

    if (repository_root / ".ci").exists():
        assert git_status["ci_entry_count"] == len(current_ci_entries)
        assert git_status["state_counts"]["ci"] == dict(
            Counter(entry["state"] for entry in current_ci_entries)
        )
        assert git_status["ci_path_sha256"] == _inventory_digest(current_ci_entries, False)
        assert git_status["ci_state_path_sha256"] == _inventory_digest(current_ci_entries, True)

        reconstructed_all = sorted(
            [*recorded_non_ci, *current_ci_entries],
            key=lambda entry: entry["path"],
        )
        assert git_status["visible_entry_count"] == len(reconstructed_all)
        assert git_status["state_counts"]["all"] == dict(
            Counter(entry["state"] for entry in reconstructed_all)
        )
        assert git_status["all_path_sha256"] == _inventory_digest(reconstructed_all, False)
        assert git_status["all_state_path_sha256"] == _inventory_digest(reconstructed_all, True)
    else:
        assert current_ci_entries == []
        assert inventory["preserved_ci_tree"]["included_in_checkpoint"] is False

    delivery = inventory["delivery"]
    assert delivery["capture_state"] == {
        "staged": False,
        "commit_created": False,
        "published": False,
    }
    checkpoint_state = delivery["checkpoint_state"]
    assert checkpoint_state["commit_created"] is True
    assert checkpoint_state["commit"] == checkpoint_commit
    assert checkpoint_state["tree"] == checkpoint["tree"]
    assert checkpoint_state["github"]["role"] == "FIRST_PUBLICATION"
    assert checkpoint_state["gitlab"]["role"] == "MIRROR_ONLY"
    assert checkpoint_state["github"]["sha"] == checkpoint_commit
    assert checkpoint_state["gitlab"]["sha"] == checkpoint_commit
    assert checkpoint_state["gitlab"]["tree"] == checkpoint["tree"]
    assert checkpoint_state["gitlab"]["previous_sha"] == pre_publication_head
    assert checkpoint_state["gitlab"]["update_type"] == "NORMAL_FAST_FORWARD"
    assert checkpoint_state["gitlab"]["reachable_history_count"] == checkpoint[
        "reachable_history_count"
    ]
    assert checkpoint_state["github_actions"] == "NOT_RUN_FOR_NON_PRODUCTION_CHECKPOINT"
    assert checkpoint_state["deployment"] == "NOT_DEPLOYED"
    assert checkpoint_state["server_synchronization"] == "NOT_CLAIMED"
    assert checkpoint_state["contract_acceptance"] == "NOT_CLAIMED"


def test_section_a_delivery_candidate_manifest_covers_captured_non_ci_snapshot():
    repository_root = Path(__file__).resolve().parents[2]
    manifest_path = repository_root / "docs" / "evidence" / "section_a_delivery_candidate_manifest_2026-09-08.json"
    if not manifest_path.is_file():
        pytest.skip("Section A delivery-candidate evidence manifest is not present in this checkout")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema"] == "cyberassess.section_a.delivery_candidate_manifest.v2"
    snapshot_identity = manifest["snapshot_identity"]
    inventory_path = repository_root / snapshot_identity["inventory_path"]
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    captured_non_ci = sorted(
        inventory["git_status"]["non_ci_entries"],
        key=lambda entry: entry["path"],
    )
    assert snapshot_identity["kind"] == inventory["snapshot_kind"]
    assert snapshot_identity["branch"] == inventory["branch"]
    assert snapshot_identity["pre_publication_head"] == inventory["head"]
    assert snapshot_identity["checkpoint_commit"] == inventory["checkpoint"]["commit"]
    assert snapshot_identity["checkpoint_tree"] == inventory["checkpoint"]["tree"]
    assert manifest["scope_status"] == "BLOCKED_BY_UNRESOLVED_OWNERSHIP_AND_A6_PROVENANCE"
    allowed_classifications = {
        "SECTION_A_CANDIDATE",
        "EVIDENCE/GOVERNANCE",
        "OUTSIDE-A",
        "RUNTIME-EXCLUDED",
        "UNRESOLVED",
    }
    expanded_entries = []
    for group in manifest["groups"]:
        classification = group["classification"]
        assert classification in allowed_classifications
        assert group["porcelain_state"] in {" M", "??"}
        assert isinstance(group["tracked"], bool)
        assert group["tracked"] is (group["porcelain_state"] == " M")
        assert group["ownership_status"] == "UNRESOLVED"
        assert group["paths"]
        if classification == "SECTION_A_CANDIDATE":
            assert group["checkpoints"]
            assert group["contract_references"]
            assert group["test_vectors"]
            assert group["change_kind"]
            assert group["independent_test_exercised"] is True
        for path in group["paths"]:
            expanded_entries.append(
                {
                    "state": group["porcelain_state"],
                    "path": path,
                    "classification": classification,
                }
            )

    manifest_paths = [entry["path"] for entry in expanded_entries]
    assert manifest["captured_non_ci_entry_count"] == len(captured_non_ci)
    assert len(expanded_entries) == len(captured_non_ci)
    assert len(manifest_paths) == len(set(manifest_paths))
    assert all(not _is_ci_path(entry) for entry in expanded_entries)
    assert all(entry["path"] != "data/cyberassess.db" for entry in expanded_entries)
    assert sorted(
        ({"state": entry["state"], "path": entry["path"]} for entry in expanded_entries),
        key=lambda entry: entry["path"],
    ) == captured_non_ci
    expected_classification_counts = {
        "SECTION_A_CANDIDATE": 39,
        "EVIDENCE/GOVERNANCE": 9,
        "OUTSIDE-A": 55,
        "UNRESOLVED": 3,
    }
    assert manifest["classification_counts"] == expected_classification_counts
    assert Counter(entry["classification"] for entry in expanded_entries) == Counter(
        manifest["classification_counts"]
    )

    source_of_truth = manifest["source_of_truth_rule"]
    source_path = repository_root / source_of_truth["source_path"]
    assert source_path.is_file()
    assert source_of_truth["source_locator"] in source_path.read_text(encoding="utf-8")
    assert source_of_truth["mirror_path_pattern"] == "docs/contracts/<same contract filename>"
    assert "raw bytes" in source_of_truth["synchronization_rule"]
    for evidence in source_of_truth["mirror_rule_evidence"]:
        _assert_manifest_reference(repository_root, evidence)

    for group in manifest["groups"]:
        for reference in group["contract_references"]:
            _assert_manifest_reference(repository_root, reference)
        for vector in group["test_vectors"]:
            _assert_manifest_test_vector(repository_root, vector)

    for exclusion in manifest["scope_exclusions"]:
        assert exclusion["classification"] == "RUNTIME-EXCLUDED"
        assert exclusion["path"] in {".ci", "data/cyberassess.db"}

    delivery = manifest["delivery"]
    assert delivery["checkpoint"]["commit"] == snapshot_identity["checkpoint_commit"]
    assert delivery["checkpoint"]["tree"] == snapshot_identity["checkpoint_tree"]
    assert delivery["github"]["role"] == "FIRST_PUBLICATION"
    assert delivery["gitlab"]["role"] == "MIRROR_ONLY"
    assert delivery["github"]["sha"] == snapshot_identity["checkpoint_commit"]
    assert delivery["gitlab"]["sha"] == snapshot_identity["checkpoint_commit"]
    assert delivery["gitlab"]["tree"] == snapshot_identity["checkpoint_tree"]
    assert delivery["gitlab"]["previous_sha"] == snapshot_identity["pre_publication_head"]
    assert delivery["gitlab"]["update_type"] == "NORMAL_FAST_FORWARD"
    assert delivery["gitlab"]["reachable_history_count"] == inventory["checkpoint"][
        "reachable_history_count"
    ]
    assert delivery["github_actions_acceptance"] == "NOT_RUN_FOR_CHECKPOINT"
    assert delivery["deployment_status"] == "NOT_DEPLOYED"
    assert delivery["server_synchronization"] == "NOT_CLAIMED"
    assert delivery["contract_acceptance"] == "NOT_CLAIMED"


def test_historical_snapshot_transition_rejects_unsupported_or_forbidden_changes():
    invalid_changes = (
        ("D", "backend/app/core/models.py"),
        ("R100", "backend/app/core/models.py"),
        ("C100", "backend/app/core/models.py"),
        ("T", "backend/app/core/models.py"),
        ("M", ".ci/forbidden-evidence.xml"),
        ("A", "data/cyberassess.db"),
    )
    for status, path in invalid_changes:
        with pytest.raises(AssertionError):
            _checkpoint_change_to_pre_publication_status(status, path)


def test_manifest_string_locator_mutation_is_rejected():
    repository_root = Path(__file__).resolve().parents[2]
    manifest_path = repository_root / "docs" / "evidence" / "section_a_delivery_candidate_manifest_2026-09-08.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    reference = next(
        reference
        for group in manifest["groups"]
        for reference in group["contract_references"]
        if isinstance(reference, str) and " §" in reference
    )
    path, locator = _manifest_reference_path_and_locator(reference)
    assert locator is not None
    mutated_reference = f"{path} §{locator} [tampered-locator]"

    with pytest.raises(AssertionError):
        _assert_manifest_reference(repository_root, mutated_reference)


def test_authoritative_contract_mirrors_and_scope_match_26_tool_fleet():
    from app.core.tool_fleet import SUPPORTED_TOOL_IDS
    from app.core.version import CONTRACT_VERSION

    expected_tools = SUPPORTED_TOOL_IDS
    repository_root = Path(__file__).resolve().parents[2]
    canonical = repository_root / "contracts"
    mirror = repository_root / "docs" / "contracts"

    contract_01 = (canonical / "01_PROJECT_SCOPE_AND_SAFETY_CONTRACT.md").read_text(encoding="utf-8")
    contract_03 = (canonical / "03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md").read_text(encoding="utf-8")
    contract_04 = (canonical / "04_API_AND_STREAMING_EVENTS_CONTRACT.md").read_text(encoding="utf-8")
    contract_05_path = canonical / "05_DELIVERABLES_AND_ACCEPTANCE_CRITERIA_CONTRACT.md"
    contract_05_mirror_path = mirror / contract_05_path.name
    contract_05 = contract_05_path.read_text(encoding="utf-8")
    normalized_contract_05 = " ".join(contract_05.split())
    contract_07 = (canonical / "07_FRONTEND_UI_UX_SPECIFICATION_CONTRACT.md").read_text(encoding="utf-8")
    contract_08 = (canonical / "08_TECHNICAL_IMPLEMENTATION_AND_TEST_VECTORS_CONTRACT.md").read_text(encoding="utf-8")
    contract_09 = (canonical / "09_TOOL_IMPLEMENTATION_CONTRACT.md").read_text(encoding="utf-8")
    assurance_matrix = (repository_root / "docs" / "TOOL_ASSURANCE_MATRIX.md").read_text(encoding="utf-8")
    dockerfile = (repository_root / "Dockerfile").read_text(encoding="utf-8")
    models = (repository_root / "backend" / "app" / "core" / "models.py").read_text(encoding="utf-8")
    frontend_index = (repository_root / "frontend" / "index.html").read_text(encoding="utf-8")

    contract_headers = []
    for contract_file in sorted(canonical.glob("[0-9][0-9]_*.md")):
        contract_text = contract_file.read_text(encoding="utf-8")
        match = re.search(r"^\*\*Document Version:\*\* ([0-9]+\.[0-9]+\.[0-9]+)", contract_text, re.MULTILINE)
        assert match, f"missing document version header: {contract_file.name}"
        contract_headers.append(match.group(1))
    assert contract_headers == [CONTRACT_VERSION] * len(contract_headers)

    traceability = contract_08.split("## 5. Security Invariant Traceability Matrix", 1)[1].split(
        "## 6. Adversarial Test Vectors", 1
    )[0]
    for row in traceability.splitlines():
        if not row.startswith("|") or row.startswith("|---") or row.startswith("| Requirement"):
            continue
        references = re.findall(r"`(tests/[^`]+)`", row)
        for reference in references:
            if "::" not in reference:
                assert "(suite-scoped)" in row, f"unqualified test reference: {reference}"
                assert (repository_root / reference).is_file(), f"missing test suite: {reference}"
                continue
            test_path, test_name = reference.split("::", 1)
            source_path = repository_root / test_path
            assert source_path.is_file(), f"missing test file: {test_path}"
            tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=test_path)
            symbols = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
            assert test_name in symbols, f"missing test symbol: {reference}"

    assert "26 specialized security tool adapters" in contract_01
    assert "across seven security domains" in contract_01
    assert "hashcat" not in contract_01
    assert "john" not in contract_01
    assert "Supported 26 Tools" in contract_03
    assert "26 tools" in contract_07
    assert "NATIVE_ENGINE_READY" in contract_07
    assert "GET /api/system/tools?refresh=true" in contract_04
    assert "backend snapshot" in contract_04
    assert "target_policy_version" in contract_04
    assert "operation_policy_revision" in contract_04
    assert "GitHub Actions is the sole authoritative CI/CD" in contract_05
    assert "GitLab is a repository mirror only" in contract_05
    assert "GitLab CI/CD results are separately attributable diagnostics" in normalized_contract_05
    assert "GitLab may be the authoritative CI/CD provider" not in contract_05
    assert "GitLab alone is authoritative" not in contract_05
    assert contract_05_path.read_bytes() == contract_05_mirror_path.read_bytes()
    assert "immutable nested representations" in contract_09
    assert "NOT_SUPPORTED`" in contract_09
    assert "permanent" in contract_09
    assert "platform exclusion" in contract_09
    assert "DELEGATED` to FFuF" in contract_09
    assert "refresh=true" in contract_04
    assert "capabilities_source" in contract_04
    assert "process-local, 60-second cache" in contract_04
    assert "Authentication Side-Effect Boundary" in contract_04
    assert "Backend-Owned Observation Service" in contract_04
    assert "canonical response envelope" in contract_04
    assert "Current Implementation-Gap Register" in contract_04
    assert "No ordinary scan-history delete endpoint is exposed" in contract_04
    assert "lifecycle-managed backend observation service" in contract_04
    assert "observational only" in contract_03
    assert "Capability Detection Cache Vectors" in contract_08
    assert "Authentication Isolation and Backend Observation Vectors" in contract_08
    assert "Historical Persistence and Retention Vectors" in contract_08
    assert "Managed Resolution and Probe Vectors" in contract_08
    assert "Managed Package-Adapter Resolution" in contract_03
    assert "NATIVE_ENGINE_READY" in models
    assert "authentication-only interaction" in contract_07
    assert "canonical `items` collection" in contract_07
    assert 'id="tool-pill-gtfobins"' in frontend_index
    assert 'tool-pill--active" id="tool-pill-gtfobins"' in frontend_index
    assert "observational telemetry only" in contract_09
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
        f"TOOL-{tool.upper().replace('_', '-')}" for tool in expected_tools
    }
    expected_matrix_ids.discard("TOOL-RETIRE")
    expected_matrix_ids.add("TOOL-RETIREJS")
    assert matrix_tool_ids == expected_matrix_ids
    assert "Part II defines all 26 supported tools" in contract_09
    assert "policy-gated automation specifications" in contract_09
    assert "Full-Capability Tool Principle" in contract_09
    assert "complete supported command, module, protocol, and option surface" in contract_03
    assert "Tool Installation and Full-Capability Execution Requests" in contract_04
    assert "recursive evidence sanitizer" in contract_04
    assert "Contract Authority and Registry Reconciliation" in (
        (canonical / "06_SECURITY_CHECK_CATALOG_AND_CWE_MAPPING_CONTRACT.md").read_text(encoding="utf-8")
    )
    assert "Enterprise cross-cutting security and automation vectors" in contract_08
    assert "Full-capability automated-tool vectors" in contract_08
    contract_02 = (canonical / "02_DATA_SCHEMA_AND_MODELS_CONTRACT.md").read_text(encoding="utf-8")
    assert "asvs_control: ASVSControl | ASVSNotApplicable" in contract_02
    assert "ASVS_NOT_APPLICABLE" in (
        canonical / "06_SECURITY_CHECK_CATALOG_AND_CWE_MAPPING_CONTRACT.md"
    ).read_text(encoding="utf-8")
    contract_06 = (canonical / "06_SECURITY_CHECK_CATALOG_AND_CWE_MAPPING_CONTRACT.md").read_text(encoding="utf-8")
    asvs_pattern = r"^v5\.0\.0-V[0-9]+\.[0-9]+\.[0-9]+$"
    assert asvs_pattern in contract_06
    assert re.fullmatch(asvs_pattern, "v5.0.0-V5.3.4")
    assert not re.fullmatch(asvs_pattern, "V5.3.4")
    assert not re.fullmatch(asvs_pattern, "v5.0.0-V5.3")
    assert not re.fullmatch(asvs_pattern, "v5.0.0-V5.3.4-extra")
    assert "14.3.0" in contract_02
    detailed_sections = re.findall(r"^## TOOL (\d{2}):", contract_09, re.MULTILINE)
    assert detailed_sections == [f"{index:02d}" for index in range(1, 27)]
    traceability_rows = [line for line in contract_09.splitlines() if line.startswith("| `TOOL-")]
    traceability_ids = {line.split("|")[1].strip().strip("`") for line in traceability_rows}
    assert len(traceability_rows) == 26
    assert {"TOOL-AMASS", "TOOL-METASPLOIT", "TOOL-SQLMAP", "TOOL-HYDRA", "TOOL-GTFOBINS"}.issubset(traceability_ids)
    assert "26-tool Enterprise Security Pentesting & Compliance Fleet" in dockerfile
    assert "all 26 available modern adapters" in models
    config_fields = set(re.findall(r"^    enable_([a-z0-9_]+):", models, re.MULTILINE))
    expected_config_fields = {tool.replace("-", "_") for tool in expected_tools}
    expected_config_fields.discard("retire")
    expected_config_fields.add("retirejs")
    assert config_fields == expected_config_fields
    assert "FLEET (26):" in frontend_index
    frontend_tool_ids = set(re.findall(r'id="tool-pill-([a-z0-9-]+)"', frontend_index))
    assert frontend_tool_ids == expected_tools
    assert len(frontend_tool_ids) == 26
    assert "all 26 registered tool/native adapters" in (repository_root / "backend" / "app" / "adapters" / "__init__.py").read_text()
    for tool in (
        "nuclei", "ffuf", "gitleaks", "katana", "syft", "grype",
        "osv-scanner", "trufflehog", "dockle", "kube-bench",
    ):
        assert f"COPY --from=builder /tmp/bin/{tool} /app/backend/bin/{tool}" in dockerfile
    assert "write_direct_artifact_trust_record" in dockerfile
    assert "write_source_artifact_trust_record" in dockerfile
    assert "-update-templates" not in dockerfile
    assert "COPY --from=builder /tmp/bin/nuclei-templates /app/backend/resources/nuclei-templates" in dockerfile
    assert "nuclei-templates.trust.json" in dockerfile
    assert "source-commit, archive-digest, and extracted-tree-digest" in contract_09
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
        for tool in expected_tools
    }
    assert expected_matrix_names == {
        tool.removeprefix("TOOL-") for tool in matrix_ids
    }

    for contract_file in canonical.glob("*.md"):
        mirror_file = mirror / contract_file.name
        assert mirror_file.read_bytes() == contract_file.read_bytes(), (
            f"contract mirror is not byte-identical to the authoritative source: "
            f"{contract_file.name}"
        )
