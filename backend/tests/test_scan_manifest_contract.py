"""Isolated tests for deterministic scan authorization manifests."""

import importlib.util
import ast
import hashlib
import json
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError


CORE = Path(__file__).resolve().parents[1] / "app" / "core"
_ORIGINAL_APP_MODULES = {
    name: module
    for name, module in sys.modules.items()
    if name == "app" or name.startswith("app.")
}
app_package = types.ModuleType("app")
app_package.__path__ = []
core_package = types.ModuleType("app.core")
core_package.__path__ = []
sys.modules.setdefault("app", app_package)
sys.modules.setdefault("app.core", core_package)
version = types.ModuleType("app.core.version")
version.APP_VERSION = "4.1.0"
version.API_VERSION = "1"
version.SCHEMA_VERSION = "4.1.0"
version.CONTRACT_VERSION = "14.3.0"
version.RULESET_VERSION = "1"
version.RISK_MODEL_VERSION = "1"
sys.modules["app.core.version"] = version


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


models = _load("app.core.models", CORE / "models.py")
fleet = _load("app.core.tool_fleet", CORE / "tool_fleet.py")
_load("app.core.tool_operation_policy", CORE / "tool_operation_policy.py")
manifest_module = _load("app.core.scan_manifest", CORE / "scan_manifest.py")

# These modules are loaded under a minimal package solely to keep this file
# independent from application startup and the protected production database.
# Restore the interpreter's module table immediately so this contract test
# cannot poison the import environment for the rest of the repository suite.
for _name in [
    name for name in list(sys.modules)
    if (name == "app" or name.startswith("app.")) and name not in _ORIGINAL_APP_MODULES
]:
    sys.modules.pop(_name, None)
for _name, _module in _ORIGINAL_APP_MODULES.items():
    sys.modules[_name] = _module


class _Engine:
    def __init__(self, name: str, tools: set[str]):
        self.name = name
        self.allowed_tool_ids = tools


def _target():
    return models.ValidatedTarget(
        target_id="target-1",
        authorization_decision_id="decision-1",
        integrity_seal="seal-1",
        organization_id="org-1",
        project_id="project-1",
        asset_id="asset-1",
        target_type=models.TargetType.DOMAIN,
        raw_value="example.com",
        canonical_value="example.com",
        selected_destination="93.184.216.34",
        policy_version="4.1.0",
    )


def _engines():
    return [
        _Engine("network", {"nmap", "subfinder"}),
        _Engine("web_dast", {"ffuf"}),
        _Engine("code_sast", {"semgrep"}),
        _Engine("infra_iac", {"prowler", "gtfobins"}),
        _Engine("cicd_audit", set()),
    ]


def test_validated_target_deep_freezes_authorization_inputs_and_serializes_stably():
    authorized_scope = ["example.com"]
    resolved_addresses = ["93.184.216.34"]
    authorization_context = {
        "grants": {"active_probing": False},
        "labels": ["production"],
    }
    validation_timestamp = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    target = models.ValidatedTarget(
        target_id="target-stable",
        authorization_decision_id="decision-stable",
        integrity_seal="seal-stable",
        organization_id="org-1",
        target_type=models.TargetType.DOMAIN,
        raw_value="example.com",
        canonical_value="example.com",
        authorized_scope=authorized_scope,
        resolved_addresses=resolved_addresses,
        selected_destination="93.184.216.34",
        authorization_context=authorization_context,
        validation_timestamp=validation_timestamp,
        policy_version="4.1.0",
    )

    # Mutating the caller-owned inputs after construction must not affect the
    # gateway-issued object.
    authorized_scope.append("attacker.example")
    resolved_addresses[0] = "192.0.2.1"
    authorization_context["grants"]["active_probing"] = True
    authorization_context["labels"].append("mutable")

    assert target.authorized_scope == ("example.com",)
    assert target.resolved_addresses == ("93.184.216.34",)
    assert target.authorization_context["grants"]["active_probing"] is False
    assert target.authorization_context["labels"] == ("production",)

    with pytest.raises(ValidationError):
        target.authorized_scope = ("attacker.example",)
    with pytest.raises(TypeError, match="immutable"):
        target.authorization_context["grants"]["active_probing"] = True
    with pytest.raises(AttributeError):
        target.authorization_context["labels"].append("attacker")
    with pytest.raises(TypeError):
        target.resolved_addresses[0] = "192.0.2.1"

    canonical = json.dumps(target.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    reconstructed = models.ValidatedTarget.model_validate(target.model_dump(mode="json"))
    reconstructed_canonical = json.dumps(
        reconstructed.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    assert canonical == reconstructed_canonical
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == hashlib.sha256(
        reconstructed_canonical.encode("utf-8")
    ).hexdigest()


def test_validated_target_public_copy_paths_revalidate_and_deep_freeze():
    target = _target()

    copied = target.model_copy(
        update={
            "authorized_scope": ["copy.example"],
            "authorization_context": {"nested": {"approved": True}},
        }
    )
    assert copied.authorized_scope == ("copy.example",)
    with pytest.raises(AttributeError):
        copied.authorized_scope.append("attacker.example")
    with pytest.raises(TypeError, match="immutable"):
        copied.authorization_context["nested"]["approved"] = False

    deeply_copied = target.model_copy(
        deep=True,
        update={"authorization_context": {"nested": {"approved": True}}},
    )
    assert deeply_copied.authorization_context["nested"]["approved"] is True
    with pytest.raises(TypeError, match="immutable"):
        deeply_copied.authorization_context["nested"]["approved"] = False

    deprecated_copy = target.copy(
        update={
            "authorized_scope": ["legacy-copy.example"],
            "authorization_context": {"nested": {"approved": True}},
        }
    )
    assert deprecated_copy.authorized_scope == ("legacy-copy.example",)
    with pytest.raises(AttributeError):
        deprecated_copy.authorized_scope.append("attacker.example")
    with pytest.raises(TypeError, match="immutable"):
        deprecated_copy.authorization_context["nested"]["approved"] = False

    construct_scope = ["construct.example"]
    construct_context = {"nested": {"approved": True}}
    constructed = models.ValidatedTarget.model_construct(
        **{
            **target.model_dump(mode="python"),
            "authorized_scope": construct_scope,
            "authorization_context": construct_context,
        }
    )
    construct_scope.append("attacker.example")
    construct_context["nested"]["approved"] = False
    assert constructed.authorized_scope == ("construct.example",)
    with pytest.raises(TypeError, match="immutable"):
        constructed.authorization_context["nested"]["approved"] = False

    with pytest.raises(ValidationError):
        target.model_copy(update={"unexpected_authorization_field": "reject"})
    with pytest.raises(ValidationError):
        models.ValidatedTarget.model_construct(
            **{
                **target.model_dump(mode="python"),
                "unexpected_authorization_field": "reject",
            }
        )

    canonical = json.dumps(
        copied.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    reconstructed = models.ValidatedTarget.model_validate(copied.model_dump(mode="json"))
    assert json.dumps(
        reconstructed.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ) == canonical


def test_validated_target_mapping_rejects_ordinary_and_c_level_dict_mutators():
    target = models.ValidatedTarget(
        **{
            **_target().model_dump(mode="python"),
            "authorization_context": {
                "grants": {"active_probing": False},
                "labels": ["production"],
            },
        }
    )
    context = target.authorization_context
    nested = context["grants"]

    assert not isinstance(context, dict)
    assert not isinstance(nested, dict)
    ordinary_mutators = (
        lambda: context.__setitem__("unexpected", True),
        lambda: context.__delitem__("grants"),
        lambda: context.clear(),
        lambda: context.pop("grants"),
        lambda: context.popitem(),
        lambda: context.setdefault("unexpected", True),
        lambda: context.update({"unexpected": True}),
        lambda: context.__ior__({"unexpected": True}),
        lambda: nested.__setitem__("active_probing", True),
    )
    for mutate in ordinary_mutators:
        with pytest.raises(TypeError, match="immutable"):
            mutate()

    # Calling the inherited C-level dict descriptors directly must not find a
    # dict layout to mutate.  This is the adversarial path that a dict subclass
    # cannot close with Python-level method overrides.
    c_level_mutators = (
        (dict.__setitem__, ("unexpected", True)),
        (dict.__delitem__, ("grants",)),
        (dict.clear, ()),
        (dict.pop, ("grants",)),
        (dict.popitem, ()),
        (dict.setdefault, ("unexpected", True)),
        (dict.update, ({"unexpected": True},)),
        (dict.__ior__, ({"unexpected": True},)),
    )
    for mutator, args in c_level_mutators:
        with pytest.raises(TypeError):
            mutator(context, *args)
    with pytest.raises(TypeError):
        dict.__setitem__(nested, "active_probing", True)

    with pytest.raises(TypeError, match="immutable"):
        context._items = ()
    with pytest.raises(TypeError, match="immutable"):
        del context._items

    assert context["grants"]["active_probing"] is False
    assert context["labels"] == ("production",)


def _build():
    return manifest_module.build_scan_manifest(
        organization_id="org-1",
        project_id="project-1",
        asset_id="asset-1",
        validated_target=_target(),
        profile="FULL_STACK",
        selected_engine_ids=("network", "web_dast", "code_sast", "infra_iac", "cicd_audit"),
        engines=_engines(),
        requested_expiry=datetime.now(timezone.utc) + timedelta(minutes=5),
        emergency_stop_reference="stop:request-1",
    )


def _request_values(manifest):
    return dict(
        scan_request_id="request-1",
        scan_id="scan-1",
        organization_id="org-1",
        requested_by_user_id="requester-1",
        correlation_id="correlation-1",
        manifest_hash=manifest.manifest_hash,
        manifest=manifest,
        expires_at=manifest.requested_expiry,
        creation_idempotency_key="request-1-idempotency",
        creation_fingerprint="a" * 64,
    )


def test_all_public_authorization_reconstruction_apis_revalidate_and_fail_closed():
    manifest = _build()
    operation = next(item for item in manifest.operations if item.selection_state == "SELECTED")
    engine_operation = manifest.engine_operations[0]
    request = models.ScanAuthorizationRequestRecord(**_request_values(manifest))

    # Valid input remains reconstructible through the compatibility APIs.
    for model in (_target(), operation, engine_operation, manifest, request):
        reconstructed = type(model).model_construct(**model.model_dump(mode="python"))
        assert reconstructed == model

    # Ordinary operation models must not accept unknown fields through any
    # public reconstruction API.
    for model in (operation, engine_operation):
        for reconstruct in (
            lambda model=model: model.model_copy(update={"unexpected": "reject"}),
            lambda model=model: model.copy(update={"unexpected": "reject"}),
            lambda model=model: type(model).model_construct(
                **{**model.model_dump(mode="python"), "unexpected": "reject"}
            ),
        ):
            with pytest.raises(ValidationError):
                reconstruct()

    # A changed manifest preimage with its original digest must never survive
    # model_copy, deprecated copy, or model_construct.
    for reconstruct in (
        lambda: manifest.model_copy(update={"target_canonical_value": "attacker.example"}),
        lambda: manifest.copy(update={"target_canonical_value": "attacker.example"}),
        lambda: models.ScanAuthorizationManifest.model_construct(
            **{
                **manifest.model_dump(mode="python"),
                "target_canonical_value": "attacker.example",
            }
        ),
    ):
        with pytest.raises(ValidationError, match="manifest hash"):
            reconstruct()

    # The parent request must retain its tenant/manifest binding through all
    # public reconstruction APIs as well.
    for reconstruct in (
        lambda: request.model_copy(update={"organization_id": "org-2"}),
        lambda: request.copy(update={"organization_id": "org-2"}),
        lambda: models.ScanAuthorizationRequestRecord.model_construct(
            **{**request.model_dump(mode="python"), "organization_id": "org-2"}
        ),
    ):
        with pytest.raises(ValidationError, match="not bound"):
            reconstruct()

    # Invalid target/tenant identity remains rejected at the original gateway
    # boundary and is not made valid by a reconstruction shortcut.
    with pytest.raises(ValidationError):
        models.ValidatedTarget.model_construct(
            **{
                **_target().model_dump(mode="python"),
                "target_type": "NOT_A_TARGET_TYPE",
            }
        )


def test_manifest_contains_the_complete_26_tool_snapshot():
    manifest = _build()
    assert len(manifest.fleet_snapshot) == 26
    assert {entry.tool_id for entry in manifest.fleet_snapshot} == fleet.SUPPORTED_TOOL_IDS
    hydra = next(entry for entry in manifest.fleet_snapshot if entry.tool_id == "hydra")
    assert hydra.status == "DEFERRED"
    assert hydra.reason == "full_capability_automation_deferred"
    assert len(manifest.manifest_hash) == 64
    models.ScanAuthorizationManifest(**manifest.model_dump())


def test_dual_engine_selection_preserves_distinct_trivy_operations():
    engines = [
        _Engine("code_sast", {"trivy"}),
        _Engine("infra_iac", {"trivy"}),
    ]
    manifest = manifest_module.build_scan_manifest(
        organization_id="org-1",
        project_id="project-1",
        asset_id="asset-1",
        validated_target=_target(),
        profile="FULL_STACK",
        selected_engine_ids=("code_sast", "infra_iac"),
        engines=engines,
        requested_expiry=datetime.now(timezone.utc) + timedelta(minutes=5),
        emergency_stop_reference="stop:dual-trivy",
    )

    trivy_operations = [operation for operation in manifest.operations if operation.tool_id == "trivy"]
    assert {operation.operation_id for operation in trivy_operations} == {
        "code_sast:trivy",
        "infra_iac:trivy",
    }
    assert {operation.operation_family for operation in trivy_operations} == {
        "code_sast_assessment",
        "infra_iac_assessment",
    }
    fleet_entry = next(entry for entry in manifest.fleet_snapshot if entry.tool_id == "trivy")
    assert fleet_entry.status == "SELECTED_MULTI_ENGINE"
    assert fleet_entry.owner_engine_id is None
    assert fleet_entry.reason == "selected_engine_operations"


def test_cicd_is_typed_engine_operation_without_changing_26_tool_fleet():
    manifest = _build()
    assert len(manifest.fleet_snapshot) == 26
    assert len(manifest.engine_operations) == 1
    operation = manifest.engine_operations[0]
    assert operation.operation_id == "engine:cicd_audit:native-assessment"
    assert operation.engine_id == "cicd_audit"
    assert operation.capability_state == "DEFERRED_UNVERIFIED"
    assert operation.selection_state == "EXCLUDED"
    assert operation.exclusion_reason
    assert all(entry.tool_id != "cicd_audit" for entry in manifest.fleet_snapshot)


def test_cicd_engine_operation_absent_when_engine_is_not_selected():
    manifest = manifest_module.build_scan_manifest(
        organization_id="org-1", project_id="project-1", asset_id="asset-1",
        validated_target=_target(), profile="FULL_STACK",
        selected_engine_ids=("network",), engines=_engines(),
        requested_expiry=datetime.now(timezone.utc) + timedelta(minutes=5),
        emergency_stop_reference="stop:request-2",
    )
    assert manifest.engine_operations == ()
    assert len(manifest.fleet_snapshot) == 26


def test_cicd_engine_operation_mutation_invalidates_canonical_manifest():
    manifest = _build()
    original = manifest.engine_operations[0]
    mutated_operation = original.model_copy(update={"operation_options": (("provider_mode", "github-only"),)})
    with pytest.raises(ValueError, match="manifest hash"):
        models.ScanAuthorizationManifest(**{
            **manifest.model_dump(),
            "engine_operations": (mutated_operation.model_dump(),),
        })

    mutated_target = original.model_copy(update={"target_id": "other-target"})
    with pytest.raises(ValueError, match="manifest hash"):
        models.ScanAuthorizationManifest(**{
            **manifest.model_dump(),
            "engine_operations": (mutated_target.model_dump(),),
        })


def test_manifest_rejects_unknown_engine_and_cross_tenant_target():
    with pytest.raises(ValueError):
        manifest_module.build_scan_manifest(
            organization_id="org-1", project_id="project-1", asset_id="asset-1",
            validated_target=_target(), profile="FULL_STACK",
            selected_engine_ids=("unknown",), engines=_engines(),
            requested_expiry=datetime.now(timezone.utc) + timedelta(minutes=5),
            emergency_stop_reference="stop:request-1",
        )


def test_manifest_nested_values_are_deeply_immutable_and_deterministic():
    config = models.ScanConfig()
    manifest = manifest_module.build_scan_manifest(
        organization_id="org-1", project_id="project-1", asset_id="asset-1",
        validated_target=_target(), profile="FULL_STACK",
        selected_engine_ids=("network",), engines=_engines(),
        requested_expiry=datetime.now(timezone.utc) + timedelta(minutes=5),
        scan_config=config, emergency_stop_reference="stop:immutable",
    )
    canonical = json.dumps(manifest.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))

    # A caller retaining the original configuration cannot mutate the sealed
    # manifest through an alias after construction.
    config.crawler.exclude_patterns.append("*caller-mutation*")
    assert "caller-mutation" not in canonical

    effective = dict(manifest.effective_scan_config)
    with pytest.raises(TypeError):
        effective["crawler"]["exclude_patterns"] += ("*nested-mutation*",)
    with pytest.raises(TypeError):
        effective["crawler"]["exclude_patterns"][0] = "*replacement*"

    operation = next(item for item in manifest.operations if item.selection_state == "SELECTED")
    with pytest.raises((TypeError, ValueError)):
        operation.operation_options += (("unexpected", "value"),)

    reconstructed = models.ScanAuthorizationManifest.model_validate(manifest.model_dump(mode="json"))
    assert json.dumps(reconstructed.model_dump(mode="json"), sort_keys=True, separators=(",", ":")) == canonical
    assert reconstructed.manifest_hash == manifest.manifest_hash


def test_manifest_rejects_inline_credentials_before_durable_persistence():
    config = models.ScanConfig(
        auth=models.AuthConfig(
            auth_type=models.AuthType.HEADER,
            headers={"Authorization": "Bearer sentinel-secret-value"},
        )
    )
    with pytest.raises(ValueError, match="inline authentication material"):
        manifest_module.build_scan_manifest(
            organization_id="org-1", project_id="project-1", asset_id="asset-1",
            validated_target=_target(), profile="FULL_STACK",
            selected_engine_ids=("network",), engines=_engines(),
            requested_expiry=datetime.now(timezone.utc) + timedelta(minutes=5),
            scan_config=config, emergency_stop_reference="stop:secret",
        )


def test_manifest_snapshot_contains_no_secret_sentinel_for_safe_configuration():
    manifest = manifest_module.build_scan_manifest(
        organization_id="org-1", project_id="project-1", asset_id="asset-1",
        validated_target=_target(), profile="FULL_STACK",
        selected_engine_ids=("network",), engines=_engines(),
        requested_expiry=datetime.now(timezone.utc) + timedelta(minutes=5),
        scan_config=models.ScanConfig(), emergency_stop_reference="stop:safe",
    )
    serialized = json.dumps(manifest.model_dump(mode="json"), sort_keys=True)
    assert "sentinel-secret-value" not in serialized
    assert "password" in serialized
    assert '"password": null' in serialized


def test_disabled_tool_is_explicitly_excluded_and_cannot_be_selected():
    config = models.ScanConfig(
        adapters=models.ToolAdapterConfig(enable_nmap=False),
    )
    manifest = manifest_module.build_scan_manifest(
        organization_id="org-1", project_id="project-1", asset_id="asset-1",
        validated_target=_target(), profile="FULL_STACK",
        selected_engine_ids=("network",), engines=_engines(),
        requested_expiry=datetime.now(timezone.utc) + timedelta(minutes=5),
        scan_config=config, emergency_stop_reference="stop:disabled",
    )
    fleet_entry = next(entry for entry in manifest.fleet_snapshot if entry.tool_id == "nmap")
    assert fleet_entry.status == "DISABLED"
    assert fleet_entry.reason == "disabled_by_scan_configuration"
    operation = next(item for item in manifest.operations if item.operation_id == "network:nmap")
    assert operation.selection_state == "EXCLUDED"
    assert operation.exclusion_reason == "disabled_by_scan_configuration"


def test_duplicate_engine_selection_is_rejected_without_silent_deduplication():
    with pytest.raises(ValueError, match="unique"):
        manifest_module.build_scan_manifest(
            organization_id="org-1", project_id="project-1", asset_id="asset-1",
            validated_target=_target(), profile="FULL_STACK",
            selected_engine_ids=("network", "network"), engines=_engines(),
            requested_expiry=datetime.now(timezone.utc) + timedelta(minutes=5),
            emergency_stop_reference="stop:duplicate",
        )


def test_hydra_is_fleet_only_until_a_registered_automation_engine_exists():
    manifest = _build()
    assert "manual" not in {name for name, _ in manifest_module._engine_snapshot(_engines())}
    assert not [operation for operation in manifest.operations if operation.tool_id == "hydra"]
    hydra = next(entry for entry in manifest.fleet_snapshot if entry.tool_id == "hydra")
    assert hydra.status == "DEFERRED"
    assert hydra.reason == "full_capability_automation_deferred"


def test_all_26_tools_have_explicit_enable_flag_mappings():
    assert set(manifest_module._TOOL_ENABLE_FIELDS) == fleet.SUPPORTED_TOOL_IDS
    assert len(manifest_module._TOOL_ENABLE_FIELDS) == fleet.SUPPORTED_TOOL_COUNT
    other = _target().model_copy(update={"organization_id": "org-2"})
    with pytest.raises(ValueError):
        manifest_module.build_scan_manifest(
            organization_id="org-1", project_id="project-1", asset_id="asset-1",
            validated_target=other, profile="FULL_STACK",
            selected_engine_ids=("network",), engines=_engines(),
            requested_expiry=datetime.now(timezone.utc) + timedelta(minutes=5),
            emergency_stop_reference="stop:request-1",
        )


@pytest.mark.parametrize("tool_id", sorted(fleet.SUPPORTED_TOOL_IDS))
def test_each_fleet_disable_flag_excludes_that_tool_from_authority(tool_id):
    field_name = manifest_module._TOOL_ENABLE_FIELDS[tool_id]
    config = models.ScanConfig(
        adapters=models.ToolAdapterConfig(**{field_name: False}),
    )
    manifest = manifest_module.build_scan_manifest(
        organization_id="org-1", project_id="project-1", asset_id="asset-1",
        validated_target=_target(), profile="FULL_STACK",
        selected_engine_ids=("network", "web_dast", "code_sast", "infra_iac", "cicd_audit"),
        engines=_engines(),
        requested_expiry=datetime.now(timezone.utc) + timedelta(minutes=5),
        scan_config=config, emergency_stop_reference=f"stop:disabled:{tool_id}",
    )
    fleet_entry = next(entry for entry in manifest.fleet_snapshot if entry.tool_id == tool_id)
    assert fleet_entry.status == "DISABLED"
    assert fleet_entry.reason == "disabled_by_scan_configuration"
    assert all(
        operation.selection_state != "SELECTED"
        for operation in manifest.operations
        if operation.tool_id == tool_id
    )


def test_scan_api_is_request_only_and_cannot_enqueue_directly():
    source = (Path(__file__).resolve().parents[1] / "app" / "api" / "scans.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    direct_launches = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "orchestrator.start_scan"
    ]
    assert not direct_launches
    assert "save_scan_with_authorization_request" in source


def test_request_expiry_cannot_extend_the_reviewed_manifest():
    manifest = _build()
    values = dict(
        scan_request_id="request-1", scan_id="scan-1", organization_id="org-1",
        requested_by_user_id="requester-1", correlation_id="correlation-1",
        manifest_hash=manifest.manifest_hash, manifest=manifest,
        expires_at=manifest.requested_expiry,
        creation_idempotency_key="request-1-idempotency",
        creation_fingerprint="a" * 64,
    )
    request = models.ScanAuthorizationRequestRecord(**values)
    assert request.expires_at == manifest.requested_expiry
    with pytest.raises(ValueError, match="expiry differs"):
        models.ScanAuthorizationRequestRecord(**{
            **values, "expires_at": manifest.requested_expiry + timedelta(hours=1),
        })
    with pytest.raises(ValueError, match="expire after creation"):
        models.ScanAuthorizationRequestRecord(**{
            **values, "created_at": manifest.requested_expiry,
        })


def _read_top_level_ast_literals(root: Path, filename: str, names: set[str]) -> dict:
    source = (root / "backend" / "app" / "core" / filename).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(root / "backend" / "app" / "core" / filename))
    values = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in names:
                values[target.id] = ast.literal_eval(node.value)
    return values


def test_pre_v13_migration_provenance_and_current_live_identity_are_explicit():
    root = CORE.parents[2]
    evidence = json.loads(
        (root / "docs/evidence/section_a_pre_v13_migrations.json").read_text(encoding="utf-8")
    )
    baseline = evidence["committed_baseline"]
    current_live = evidence["current_live"]

    artifact = _read_top_level_ast_literals(
        root,
        "migration_artifacts.py",
        {
            "MIGRATION_CHECKSUM_POSTCONDITION_SOURCE_SHA256",
            "FORWARD_APPLY_ARTIFACT_REVISION",
            "FORWARD_APPLY_MANIFESTS",
            "FORWARD_APPLY_SOURCE_SHA256",
            "POSTCONDITION_ARTIFACT_REVISION",
            "POSTCONDITION_SOURCE_SHA256",
        },
    )
    registry = _read_top_level_ast_literals(
        root,
        "migration_registry.py",
        {"_DESCRIPTORS", "_EXPECTED_CHECKSUMS"},
    )

    historical_checksums = artifact["MIGRATION_CHECKSUM_POSTCONDITION_SOURCE_SHA256"]
    baseline_checksums = baseline["metadata"]["MIGRATION_CHECKSUM_POSTCONDITION_SOURCE_SHA256"]
    historical_method_names = {
        f"_verify_migration_v{version}_postconditions" for version in range(1, 11)
    }
    assert {name: historical_checksums[name] for name in historical_method_names} == baseline_checksums

    baseline_descriptors = baseline["metadata"]["_DESCRIPTORS"]
    assert [descriptor[0] for descriptor in baseline_descriptors] == list(range(1, 11))
    assert json.loads(json.dumps(registry["_DESCRIPTORS"]))[: len(baseline_descriptors)] == baseline_descriptors

    baseline_expected_checksums = baseline["metadata"]["_EXPECTED_CHECKSUMS"]
    actual_historical_expected_checksums = {
        str(version): checksum
        for version, checksum in registry["_EXPECTED_CHECKSUMS"].items()
        if version <= 10
    }
    assert actual_historical_expected_checksums == baseline_expected_checksums

    fixture = evidence["v12_to_v13_fixture"]
    assert fixture["status"] == "PROVENANCE_BLOCKED"
    assert fixture["source_commit"] == "a1c4fc43e1e225b9131333f5c05ccdcc830af256"
    assert fixture["test"] == (
        "tests/security/test_scan_request_migration.py::"
        "test_genuine_frozen_pre_v13_source_upgrades_once_to_v13"
    )

    assert historical_checksums == current_live["MIGRATION_CHECKSUM_POSTCONDITION_SOURCE_SHA256"]
    assert artifact["FORWARD_APPLY_ARTIFACT_REVISION"] == current_live["FORWARD_APPLY_ARTIFACT_REVISION"]
    assert json.loads(json.dumps(artifact["FORWARD_APPLY_MANIFESTS"])) == current_live["FORWARD_APPLY_MANIFESTS"]
    assert json.loads(json.dumps(artifact["FORWARD_APPLY_SOURCE_SHA256"])) == current_live["FORWARD_APPLY_SOURCE_SHA256"]
    assert artifact["POSTCONDITION_ARTIFACT_REVISION"] == current_live["POSTCONDITION_ARTIFACT_REVISION"]
    assert artifact["POSTCONDITION_SOURCE_SHA256"] == current_live["POSTCONDITION_SOURCE_SHA256"]
    assert registry["_EXPECTED_CHECKSUMS"] == {
        int(version): checksum for version, checksum in current_live["_EXPECTED_CHECKSUMS"].items()
    }
    assert json.loads(json.dumps(registry["_DESCRIPTORS"])) == current_live["_DESCRIPTORS"]

    source = (CORE / "db.py").read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(CORE / "db.py"))
    manager = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "DatabaseManager"
    )
    methods = {
        node.name: node
        for node in manager.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    source_lines = source.splitlines(keepends=True)
    current_source_digests = {}
    for version in range(1, 14):
        name = f"_verify_migration_v{version}_postconditions"
        node = methods[name]
        actual_source = "".join(source_lines[node.lineno - 1:node.end_lineno])
        current_source_digests[name] = "sha256:" + hashlib.sha256(actual_source.encode()).hexdigest()
    assert current_source_digests == current_live["POSTCONDITION_SOURCE_SHA256"]
