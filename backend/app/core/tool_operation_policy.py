"""Canonical operation-policy revision and validation boundary.

This module is the only source of truth for the revision carried by an
authorized execution request.  Callers may supply a revision value, but they
cannot define or register policy at runtime.
"""

from __future__ import annotations

import hashlib
import json
from types import MappingProxyType
from typing import Any, Mapping


_ENGINE_TOOL_IDS: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "network": ("amass", "httpx", "metasploit", "nmap", "sslyze", "subfinder"),
    "web_dast": ("ffuf", "katana", "nuclei", "schemathesis", "sqlmap"),
    "code_sast": ("bandit", "gitleaks", "grype", "osv-scanner", "retire", "semgrep", "syft", "trivy", "trufflehog"),
    "infra_iac": ("checkov", "dockle", "gtfobins", "kube-bench", "prowler", "trivy"),
    "manual": ("hydra",),
})


def _policy_row(tool_id: str, engine_id: str) -> Mapping[str, Any]:
    """Create one immutable, administrator-approved operation policy row."""
    family = "cloud_audit" if tool_id == "prowler" else (
        "manual_authentication" if tool_id == "hydra" else f"{engine_id}_assessment"
    )
    options = {"provider": "aws", "output_format": "json-asff", "quiet": True} if tool_id == "prowler" else {}
    credentials = {"provider": "aws"} if tool_id == "prowler" else {}
    capability = "NATIVE" if tool_id == "gtfobins" else "DEFERRED" if tool_id == "hydra" else "AVAILABLE"
    return MappingProxyType({
        "tool_id": tool_id,
        "engine_id": engine_id,
        "operation_family": family,
        "option_or_module_class": "canonical_tool_operation",
        "required_options": MappingProxyType(options),
        "capability_state": capability,
        "default_profile_behavior": "EXPLICIT_ADMINISTRATOR_APPROVAL_REQUIRED",
        "approval_level": "ADMINISTRATOR_APPROVAL_REQUIRED",
        "worker_class": "isolated-tool-worker",
        "target_rules": "gateway-issued target bound to tenant, project, and inventory asset",
        "credential_requirements": "typed tenant-scoped credential envelope" if credentials else "no credential material",
        "resource_budget": MappingProxyType({"timeout_seconds": 300, "max_output_bytes": 10485760}),
        "account_impact_budget": MappingProxyType({"max_operations": 1}),
        "credential_scope": MappingProxyType(credentials),
        "stop_conditions": "authorization revocation, expiry, cancellation, timeout, output limit",
        "evidence_requirements": "bounded tool output and normalized findings",
        "audit_requirements": "tenant, asset, authorization decision, request, policy revision, and worker identity",
    })


_POLICY_RECORDS = tuple(
    _policy_row(tool_id, engine_id)
    for engine_id, tool_ids in _ENGINE_TOOL_IDS.items()
    for tool_id in tool_ids
)

_POLICY_DOCUMENT: Mapping[str, Any] = MappingProxyType({
    "schema_version": 2,
    "records": _POLICY_RECORDS,
})

# An unresolved capability is not a permanent platform exclusion.  Keep this
# state separate from authorization and from the toolbox execution-mode enum.
_UNRESOLVED_TOOL_STATES: Mapping[str, Mapping[str, str]] = MappingProxyType({
    "hydra": MappingProxyType({
        "capability_state": "DEFERRED",
        "reason": "full_capability_automation_deferred",
    }),
})


def _canonical_json(document: Mapping[str, Any]) -> bytes:
    def thaw(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {key: thaw(item) for key, item in value.items()}
        if isinstance(value, tuple):
            return [thaw(item) for item in value]
        return value

    return json.dumps(thaw(document), sort_keys=True, separators=(",", ":")).encode("utf-8")


OPERATION_POLICY_REVISION = hashlib.sha256(_canonical_json(_POLICY_DOCUMENT)).hexdigest()


def is_canonical_operation_policy_revision(value: str) -> bool:
    """Return true only for the revision computed from this immutable artifact."""
    return isinstance(value, str) and value == OPERATION_POLICY_REVISION


def get_operation_policy(tool_id: str, operation_family: str) -> Mapping[str, Any] | None:
    """Return the exact policy row for a tool and operation family."""
    for row in _POLICY_DOCUMENT["records"]:
        if row["tool_id"] == tool_id and row["operation_family"] == operation_family:
            return row
    return None


def operation_policy_document() -> Mapping[str, Any]:
    """Expose an immutable policy view for diagnostics and audit evidence."""
    return _POLICY_DOCUMENT


def get_unresolved_tool_state(tool_id: str) -> Mapping[str, str] | None:
    """Return the explicit deferred/unresolved state for a fleet tool."""
    return _UNRESOLVED_TOOL_STATES.get(tool_id)
