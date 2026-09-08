"""Deterministic, server-owned scan authorization manifest construction.

The builder is deliberately independent of persistence and HTTP.  It derives
engine/tool ownership from the registered runtime engines and records policy
gaps as explicit exclusions instead of inventing an executable operation.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
import re
from typing import Any, Iterable, Mapping, Sequence

from app.core.models import (
    ScanAuthorizationManifest,
    ScanManifestEngineOperation,
    ScanFleetSnapshotEntry,
    ScanManifestOperation,
    Target,
    ValidatedTarget,
)
from app.core.tool_fleet import SUPPORTED_TOOL_IDS
from app.core.tool_operation_policy import (
    OPERATION_POLICY_REVISION,
    get_operation_policy,
    get_unresolved_tool_state,
)

MANIFEST_SCHEMA_VERSION = "scan-manifest-v2"
NATIVE_TOOLS = frozenset({"gtfobins"})
FLEET_ONLY_TOOLS = frozenset({"hydra"})

_TOOL_ENABLE_FIELDS: Mapping[str, str] = {
    "amass": "enable_amass",
    "bandit": "enable_bandit",
    "checkov": "enable_checkov",
    "dockle": "enable_dockle",
    "ffuf": "enable_ffuf",
    "gitleaks": "enable_gitleaks",
    "grype": "enable_grype",
    "gtfobins": "enable_gtfobins",
    "httpx": "enable_httpx",
    "hydra": "enable_hydra",
    "katana": "enable_katana",
    "kube-bench": "enable_kube_bench",
    "metasploit": "enable_metasploit",
    "nmap": "enable_nmap",
    "nuclei": "enable_nuclei",
    "osv-scanner": "enable_osv_scanner",
    "prowler": "enable_prowler",
    "retire": "enable_retirejs",
    "schemathesis": "enable_schemathesis",
    "semgrep": "enable_semgrep",
    "sqlmap": "enable_sqlmap",
    "sslyze": "enable_sslyze",
    "subfinder": "enable_subfinder",
    "syft": "enable_syft",
    "trivy": "enable_trivy",
    "trufflehog": "enable_trufflehog",
}

_SENSITIVE_HEADER_NAME = re.compile(
    r"(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|pwd|"
    r"token|secret|api[-_]?key|access[-_]?token|credential)",
    re.IGNORECASE,
)


def _config_mapping(scan_config: object | None) -> dict[str, Any]:
    if scan_config is None:
        return {}
    if hasattr(scan_config, "model_dump"):
        raw = scan_config.model_dump(mode="json")
    elif isinstance(scan_config, Mapping):
        raw = dict(scan_config)
    else:
        raise ValueError("scan configuration must be a serializable configuration model")
    if not isinstance(raw, dict):
        raise ValueError("scan configuration did not produce a mapping")
    return raw


def validate_durable_scan_config(scan_config: object | None) -> dict[str, Any]:
    """Validate and return only non-secret configuration material for a manifest.

    The application currently has a worker-only cloud credential envelope, but
    no generic tenant-scoped web credential reference/resolver.  Accepting
    inline web credentials here would create a durable request that cannot be
    safely reconstructed for execution.  Reject that state explicitly rather
    than persisting a redaction or an unusable digest.
    """
    raw = _config_mapping(scan_config)
    custom_headers = raw.get("custom_headers") or {}
    if not isinstance(custom_headers, Mapping):
        raise ValueError("custom_headers must be a mapping")
    if any(_SENSITIVE_HEADER_NAME.search(str(name)) for name in custom_headers):
        raise ValueError(
            "durable scan authorization does not accept inline credential-bearing headers; "
            "an approved tenant-scoped credential reference is required"
        )

    auth = raw.get("auth") or {}
    if not isinstance(auth, Mapping):
        raise ValueError("auth configuration must be a mapping")
    auth_type = str(auth.get("auth_type") or "NONE").upper()
    inline_fields = ("headers", "cookies", "password")
    if any(auth.get(field) for field in inline_fields):
        raise ValueError(
            "durable scan authorization does not accept inline authentication material; "
            "an approved tenant-scoped credential reference is required"
        )
    if any(_SENSITIVE_HEADER_NAME.search(str(name)) for name in (auth.get("headers") or {})):
        raise ValueError("durable scan authorization does not accept credential-bearing auth headers")
    if auth_type not in {"NONE", "NO_AUTH"}:
        raise ValueError(
            "durable web authentication is unavailable without a tenant-scoped credential resolver"
        )

    # Ensure secret-shaped fields are represented only as empty/null values in
    # the deterministic snapshot, even when a caller supplied explicit nulls.
    auth_snapshot = dict(auth)
    for field in inline_fields:
        auth_snapshot[field] = {} if field != "password" else None
    raw["auth"] = auth_snapshot
    return raw


def _tool_enabled(scan_config: object | None, tool_id: str) -> bool:
    if scan_config is None:
        return True
    adapters = getattr(scan_config, "adapters", None)
    if adapters is None and isinstance(scan_config, Mapping):
        adapters = (scan_config.get("adapters") or {})
    field = _TOOL_ENABLE_FIELDS.get(tool_id)
    if field is None:
        raise ValueError(f"tool {tool_id!r} has no canonical enable flag")
    if isinstance(adapters, Mapping):
        return bool(adapters.get(field, True))
    return bool(getattr(adapters, field, True))


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _engine_snapshot(engines: Sequence[object]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    rows: list[tuple[str, tuple[str, ...]]] = []
    for engine in engines:
        name = str(engine.name).strip()
        if not name:
            raise ValueError("registered engine identity cannot be blank")
        declared = getattr(engine, "allowed_tool_ids", None)
        if declared is None:
            raise ValueError(f"engine {name!r} has no canonical tool declaration")
        tools = tuple(sorted(str(tool) for tool in declared))
        if len(tools) != len(set(tools)) or any(tool not in SUPPORTED_TOOL_IDS for tool in tools):
            raise ValueError(f"engine {name!r} declares invalid or duplicate tool identity")
        rows.append((name, tools))
    names = [name for name, _ in rows]
    if len(names) != len(set(names)):
        raise ValueError("registered engine identities are not unique")
    return tuple(sorted(rows))


def build_scan_manifest(
    *,
    organization_id: str,
    project_id: str | None,
    asset_id: str,
    asset_owner: str | None = None,
    asset_lifecycle_status: str | None = None,
    validated_target: ValidatedTarget,
    profile: str,
    selected_engine_ids: Iterable[str],
    engines: Sequence[object],
    requested_expiry: datetime,
    scan_config: object | None = None,
    resource_budget: Mapping[str, int] | None = None,
    account_impact_budget: Mapping[str, int] | None = None,
    credential_scope: Mapping[str, str] | None = None,
    emergency_stop_reference: str,
) -> ScanAuthorizationManifest:
    """Build one canonical manifest from server-owned engine declarations."""
    if validated_target.organization_id != organization_id or validated_target.asset_id != asset_id:
        raise ValueError("validated target is outside the requested tenant/asset binding")
    snapshot = _engine_snapshot(engines)
    by_name = dict(snapshot)
    raw_selected = tuple(selected_engine_ids)
    if not raw_selected:
        raise ValueError("at least one registered engine must be selected")
    if any(not isinstance(item, str) or not item.strip() for item in raw_selected):
        raise ValueError("selected engine identities must be non-blank strings")
    normalized_selected = tuple(item.strip() for item in raw_selected)
    if len(normalized_selected) != len(set(normalized_selected)):
        raise ValueError("selected engine identities must be unique")
    selected = tuple(sorted(normalized_selected))
    if not selected or any(name not in by_name for name in selected):
        raise ValueError("selected engine set is not a registered canonical engine set")

    effective_config = validate_durable_scan_config(scan_config)

    ownership: dict[str, list[str]] = {}
    for engine_name, tools in snapshot:
        for tool in tools:
            ownership.setdefault(tool, []).append(engine_name)

    operations: list[ScanManifestOperation] = []
    engine_operations: list[ScanManifestEngineOperation] = []
    fleet: list[ScanFleetSnapshotEntry] = []
    for tool_id in sorted(SUPPORTED_TOOL_IDS):
        owners = tuple(ownership.get(tool_id, ()))
        selected_owners = tuple(name for name in owners if name in selected)
        unresolved_state = get_unresolved_tool_state(tool_id)
        if not _tool_enabled(scan_config, tool_id):
            fleet.append(ScanFleetSnapshotEntry(
                tool_id=tool_id,
                owner_engine_id=selected_owners[0] if len(selected_owners) == 1 else None,
                status="DISABLED",
                reason="disabled_by_scan_configuration",
            ))
            for engine_id in selected_owners:
                policy_family = "cloud_audit" if tool_id == "prowler" else f"{engine_id}_assessment"
                policy = get_operation_policy(tool_id, policy_family)
                if policy is None:
                    operations.append(ScanManifestOperation(
                        operation_id=f"{engine_id}:{tool_id}",
                        tool_id=tool_id,
                        engine_id=engine_id,
                        operation_family="UNREPRESENTED_POLICY",
                        classification="UNAUTHORIZED_UNTIL_POLICY_DEFINED",
                        operation_policy_revision=OPERATION_POLICY_REVISION,
                        target_id=validated_target.target_id,
                        authorization_decision_id=validated_target.authorization_decision_id,
                        capability_state="POLICY_GAP",
                        selection_state="EXCLUDED",
                        exclusion_reason="disabled_by_scan_configuration",
                    ))
                else:
                    operations.append(ScanManifestOperation(
                        operation_id=f"{engine_id}:{tool_id}",
                        tool_id=tool_id,
                        engine_id=engine_id,
                        operation_family=str(policy["operation_family"]),
                        classification=str(policy.get("approval_level", "ADMINISTRATOR_APPROVAL_REQUIRED")),
                        operation_options=tuple(sorted(dict(policy.get("required_options", {})).items())),
                        operation_policy_revision=OPERATION_POLICY_REVISION,
                        target_id=validated_target.target_id,
                        authorization_decision_id=validated_target.authorization_decision_id,
                        resource_budget=tuple(sorted(dict(policy.get("resource_budget", {})).items())),
                        account_impact_budget=tuple(sorted(dict(policy.get("account_impact_budget", {})).items())),
                        credential_scope=tuple(sorted(dict(policy.get("credential_scope", {})).items())),
                        capability_state=str(policy.get("capability_state", "UNAVAILABLE")),
                        selection_state="EXCLUDED",
                        exclusion_reason="disabled_by_scan_configuration",
                    ))
            continue
        if tool_id in FLEET_ONLY_TOOLS:
            fleet.append(ScanFleetSnapshotEntry(
                tool_id=tool_id,
                owner_engine_id=None,
                status=str(unresolved_state["capability_state"] if unresolved_state else "DEFERRED"),
                reason=str(unresolved_state["reason"] if unresolved_state else "fleet_only_tool_without_registered_engine"),
            ))
            continue
        if not selected_owners and unresolved_state is not None:
            fleet.append(ScanFleetSnapshotEntry(
                tool_id=tool_id,
                owner_engine_id=None,
                status=str(unresolved_state["capability_state"]),
                reason=str(unresolved_state["reason"]),
            ))
            continue
        if len(selected_owners) > 1:
            # Keep one canonical fleet row while retaining one authority
            # operation per selected engine below.  The row must not claim a
            # single owner for a multi-engine tool identity.
            fleet_status = "SELECTED_MULTI_ENGINE"
            fleet_reason = "selected_engine_operations"
        elif not selected_owners:
            fleet_status = "NOT_SELECTED"
            fleet_reason = "owning_engine_not_selected"
        elif tool_id in NATIVE_TOOLS:
            fleet_status = "SELECTED_NATIVE"
            fleet_reason = None
        else:
            fleet_status = "SELECTED"
            fleet_reason = None
        fleet.append(ScanFleetSnapshotEntry(
            tool_id=tool_id,
            owner_engine_id=selected_owners[0] if len(selected_owners) == 1 else None,
            status=fleet_status,
            reason=fleet_reason,
        ))
        if not selected_owners:
            continue
        for engine_id in selected_owners:
            policy_family = "cloud_audit" if tool_id == "prowler" else f"{engine_id}_assessment"
            policy = get_operation_policy(tool_id, policy_family)
            if policy is None:
                operations.append(ScanManifestOperation(
                    operation_id=f"{engine_id}:{tool_id}",
                    tool_id=tool_id,
                    engine_id=engine_id,
                    operation_family="UNREPRESENTED_POLICY",
                    classification="UNAUTHORIZED_UNTIL_POLICY_DEFINED",
                    operation_policy_revision=OPERATION_POLICY_REVISION,
                    target_id=validated_target.target_id,
                    authorization_decision_id=validated_target.authorization_decision_id,
                    capability_state="POLICY_GAP",
                    selection_state="EXCLUDED",
                    exclusion_reason="canonical_operation_policy_missing",
                ))
                continue
            options = dict(policy.get("required_options", {}))
            operations.append(ScanManifestOperation(
                operation_id=f"{engine_id}:{tool_id}",
                tool_id=tool_id,
                engine_id=engine_id,
                operation_family=str(policy["operation_family"]),
                classification=str(policy.get("approval_level", "ADMINISTRATOR_APPROVAL_REQUIRED")),
                operation_options=tuple(sorted(options.items())),
                operation_policy_revision=OPERATION_POLICY_REVISION,
                target_id=validated_target.target_id,
                authorization_decision_id=validated_target.authorization_decision_id,
                resource_budget=tuple(sorted(dict(policy.get("resource_budget", {})).items())),
                account_impact_budget=tuple(sorted(dict(policy.get("account_impact_budget", {})).items())),
                credential_scope=tuple(sorted(dict(policy.get("credential_scope", {})).items())),
                capability_state=str(policy.get("capability_state", "UNAVAILABLE")),
                selection_state="SELECTED",
            ))

    if "cicd_audit" in selected:
        engine_operations.append(ScanManifestEngineOperation(
            operation_id="engine:cicd_audit:native-assessment",
            engine_id="cicd_audit",
            operation_family="ci_cd_repository_assessment",
            classification="ADMINISTRATOR_APPROVAL_REQUIRED",
            operation_options=(("provider_mode", "provider-aware"),),
            operation_policy_revision=OPERATION_POLICY_REVISION,
            target_id=validated_target.target_id,
            authorization_decision_id=validated_target.authorization_decision_id,
            resource_budget=(("timeout_seconds", 300),),
            capability_state="DEFERRED_UNVERIFIED",
            selection_state="EXCLUDED",
            exclusion_reason="native_engine_policy_and_provider_evidence_not_defined",
        ))

    engine_revision = _canonical_digest([[name, list(tools)] for name, tools in snapshot])
    values = dict(
        schema_version=MANIFEST_SCHEMA_VERSION,
        manifest_hash="0" * 64,
        organization_id=organization_id,
        project_id=project_id,
        asset_id=asset_id,
        asset_owner=asset_owner,
        asset_lifecycle_status=asset_lifecycle_status,
        target_id=validated_target.target_id,
        authorization_decision_id=validated_target.authorization_decision_id,
        target_integrity_seal=validated_target.integrity_seal,
        target_policy_version=validated_target.policy_version,
        target_type=validated_target.target_type.value if hasattr(validated_target.target_type, "value") else str(validated_target.target_type),
        target_raw_value=validated_target.raw_value,
        target_canonical_value=validated_target.canonical_value,
        target_selected_destination=validated_target.selected_destination,
        target_resolved_addresses=tuple(validated_target.resolved_addresses),
        target_authorized_scope=tuple(validated_target.authorized_scope),
        target_port=validated_target.port,
        target_scheme=validated_target.scheme,
        target_authorization_context=tuple(sorted(dict(validated_target.authorization_context).items())),
        profile=str(profile),
        selected_engine_ids=selected,
        engine_revision=engine_revision,
        policy_revision=OPERATION_POLICY_REVISION,
        operations=tuple(operations),
        engine_operations=tuple(engine_operations),
        fleet_snapshot=tuple(fleet),
        requested_expiry=requested_expiry,
        resource_budget=tuple(sorted(dict(resource_budget or {}).items())),
        account_impact_budget=tuple(sorted(dict(account_impact_budget or {}).items())),
        credential_scope=tuple(sorted(dict(credential_scope or {}).items())),
        emergency_stop_reference=emergency_stop_reference,
        effective_scan_config=tuple(sorted(effective_config.items())),
    )
    digest_material = ScanAuthorizationManifest._trusted_digest_preimage(values)
    digest = _canonical_digest(digest_material)
    return ScanAuthorizationManifest(**{**values, "manifest_hash": digest})


__all__ = ["MANIFEST_SCHEMA_VERSION", "build_scan_manifest"]
