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


_POLICY_DOCUMENT: Mapping[str, Any] = MappingProxyType({
    "schema_version": 1,
    "records": (
        MappingProxyType({
            "tool_id": "prowler",
            "operation_family": "cloud_audit",
            "option_or_module_class": "provider_audit",
            "required_options": MappingProxyType({"provider": "aws", "output_format": "json-asff", "quiet": True}),
            "capability_state": "AVAILABLE",
            "default_profile_behavior": "EXPLICIT_AUTHORIZATION_REQUIRED",
            "approval_level": "ELEVATED_APPROVAL_REQUIRED",
            "worker_class": "isolated-tool-worker",
            "target_rules": "gateway-issued cloud target bound to tenant and asset",
            "credential_requirements": "typed tenant-scoped AWS credential envelope",
            "resource_budget": MappingProxyType({"timeout_seconds": 120, "max_output_bytes": 10485760}),
            "account_impact_budget": "read-only posture assessment",
            "stop_conditions": "authorization revocation, expiry, cancellation, timeout, output limit",
            "evidence_requirements": "bounded ASFF report",
            "audit_requirements": "tenant, asset, authorization decision, request, and policy revision",
        }),
    ),
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
