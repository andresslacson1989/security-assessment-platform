"""Authoritative database-migration identity registry.

Migration numbers are database-transition numbers and are intentionally
separate from the contract/model version in :mod:`app.core.version`.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import inspect
import json
from typing import Callable, Optional, Protocol

from app.core.version import CONTRACT_VERSION, SCHEMA_VERSION
from app.core.migration_artifacts import (
    FORWARD_APPLY_ARTIFACT_REVISION,
    FORWARD_APPLY_SOURCE_SHA256,
    POSTCONDITION_ARTIFACT_REVISION,
    POSTCONDITION_SOURCE_SHA256,
)

REGISTRY_REVISION = "migration-registry-v1"


class MigrationManagerProtocol(Protocol):
    def _apply_migration_version(self, version: int) -> None: ...
    def _verify_migration_v1_postconditions(self, conn) -> None: ...
    def _verify_migration_v2_postconditions(self, conn) -> None: ...
    def _verify_migration_v3_postconditions(self, conn) -> None: ...
    def _verify_migration_v4_postconditions(self, conn) -> None: ...
    def _verify_migration_v5_postconditions(self, conn) -> None: ...
    def _verify_migration_v6_postconditions(self, conn) -> None: ...
    def _verify_migration_v7_postconditions(self, conn) -> None: ...
    def _verify_migration_v8_postconditions(self, conn) -> None: ...
    def _verify_migration_v9_postconditions(self, conn) -> None: ...


@dataclass(frozen=True)
class MigrationSpec:
    version: int
    migration_id: str
    name: str
    previous_version: Optional[int]
    target_version: int
    contract_schema_version: str
    contract_version: str
    registry_revision: str
    checksum: str
    apply_artifact: str
    apply: Optional[Callable] = None
    verify: Optional[Callable] = None
    reconcile: Optional[Callable] = None
    backend_policy: str = "SQLITE_AND_POSTGRESQL"


def _checksum(material: dict) -> str:
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


_DESCRIPTORS = (
    (1, "execution-runs-tenant-binding", "Execution runs tenant binding", None, "execution_runs tenant composite request binding"),
    (2, "execution-runs-tenant-binding-remediation", "Execution runs tenant binding remediation", 1, "execution_runs legacy binding remediation"),
    (3, "execution-runs-snapshot-metadata", "Execution runs snapshot metadata", 2, "execution_runs immutable snapshot columns"),
    (4, "execution-authority-tenant-binding", "Execution authority tenant binding", 3, "execution_runs decision composite binding"),
    (5, "execution-authority-parent-key-cleanup", "Execution authority parent-key cleanup", 4, "migration-owned duplicate parent cleanup"),
    (6, "execution-compatibility-columns", "Execution compatibility columns", 5, "decision/request compatibility columns"),
    (7, "execution-dispatch-intents", "Execution dispatch intents", 6, "durable execution dispatch intent table"),
    (8, "execution-dispatch-tenant-binding", "Execution dispatch tenant binding", 7, "tenant-bound dispatch lease columns and foreign keys"),
    (9, "execution-parent-index-repair", "Execution parent index repair", 8, "remove only the proven migration-owned duplicate parent index"),
)


def _verify_v1(manager: MigrationManagerProtocol, conn) -> None:
    manager._verify_migration_v1_postconditions(conn)


def _apply_version(version: int):
    def apply(manager: MigrationManagerProtocol) -> None:
        manager._apply_migration_version(version)
    return apply


def _reconcile_version(version: int):
    def reconcile(manager: MigrationManagerProtocol, conn) -> None:
        verifier = getattr(manager, f"_verify_migration_v{version}_postconditions")
        verifier(conn)
    return reconcile


def _verify_v2(manager: MigrationManagerProtocol, conn) -> None:
    manager._verify_migration_v2_postconditions(conn)


def _verify_v3(manager: MigrationManagerProtocol, conn) -> None:
    manager._verify_migration_v3_postconditions(conn)


def _verify_v4(manager: MigrationManagerProtocol, conn) -> None:
    manager._verify_migration_v4_postconditions(conn)


def _verify_v5(manager: MigrationManagerProtocol, conn) -> None:
    manager._verify_migration_v5_postconditions(conn)


def _verify_v6(manager: MigrationManagerProtocol, conn) -> None:
    manager._verify_migration_v6_postconditions(conn)


def _verify_v7(manager: MigrationManagerProtocol, conn) -> None:
    manager._verify_migration_v7_postconditions(conn)


def _verify_v8(manager: MigrationManagerProtocol, conn) -> None:
    manager._verify_migration_v8_postconditions(conn)


def _verify_v9(manager: MigrationManagerProtocol, conn) -> None:
    manager._verify_migration_v9_postconditions(conn)


_VERIFIERS = (_verify_v1, _verify_v2, _verify_v3, _verify_v4, _verify_v5, _verify_v6, _verify_v7, _verify_v8, _verify_v9)
_VERIFIER_METHODS = (
    "_verify_migration_v1_postconditions",
    "_verify_migration_v2_postconditions",
    "_verify_migration_v3_postconditions",
    "_verify_migration_v4_postconditions",
    "_verify_migration_v5_postconditions",
    "_verify_migration_v6_postconditions",
    "_verify_migration_v7_postconditions",
    "_verify_migration_v8_postconditions",
    "_verify_migration_v9_postconditions",
)


def _make_spec(version: int, migration_id: str, name: str, previous: Optional[int], manifest: str) -> MigrationSpec:
    material = {
        "version": version,
        "migration_id": migration_id,
        "name": name,
        "previous_version": previous,
        "target_version": version,
        "contract_schema_version": SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "registry_revision": REGISTRY_REVISION,
        "canonical_manifest": manifest,
        "postcondition_manifest_revision": POSTCONDITION_ARTIFACT_REVISION,
        "verifier_method": _VERIFIER_METHODS[version - 1],
        "verifier_artifact": POSTCONDITION_SOURCE_SHA256[_VERIFIER_METHODS[version - 1]],
        "forward_apply_artifact_revision": FORWARD_APPLY_ARTIFACT_REVISION,
        "forward_apply_artifact": FORWARD_APPLY_SOURCE_SHA256[version],
    }
    return MigrationSpec(
        version=version, migration_id=migration_id, name=name,
        previous_version=previous, target_version=version,
        contract_schema_version=SCHEMA_VERSION, contract_version=CONTRACT_VERSION,
        registry_revision=REGISTRY_REVISION, checksum=_checksum(material),
        apply_artifact=FORWARD_APPLY_SOURCE_SHA256[version],
        apply=_apply_version(version), verify=_VERIFIERS[version - 1],
        reconcile=_reconcile_version(version),
    )


MIGRATION_REGISTRY = tuple(_make_spec(*descriptor) for descriptor in _DESCRIPTORS)

_EXPECTED_CHECKSUMS = {
    1: "sha256:e65ded9b0468bb31c98a76cbe0030e19486ec9c88d612f10e133b120bc8d9df3",
    2: "sha256:6830c8f003211bd4aa5374c009984bb3ef5450325053a48c73281228a98bbe0f",
    3: "sha256:eba4efac761fa91507631934da54ae418312c931dc28836bce061c0ca6880053",
    4: "sha256:d22460620d54cd86d2701e331cd30bcd3bc7440b4b34ffff0bc5199159b4a951",
    5: "sha256:140e2f61fce0cb87b32bd4f43bb1a88878b3a06dc12d1346263579ac64344d89",
    6: "sha256:46654fba995de8fea1ad4e76a03f59ac6209c13abcfcede12cefbc0a768e8abb",
    7: "sha256:0bd2b3d23af189971c6e54e283e4929b3587ac869ba1287ec1a17f46140a0b98",
    8: "sha256:5b0a9b7d55f73fd3c0701ac0c66f69944e73d7a5d5631dd2c39ab97d707a36f6",
    9: "sha256:f5cfa4cfd9cf7fad4d8e4ab720dd7273f92e8f9de39a745cb2f053b52d460a25",
}


def validate_registry() -> None:
    versions = [spec.version for spec in MIGRATION_REGISTRY]
    ids = [spec.migration_id for spec in MIGRATION_REGISTRY]
    if versions != sorted(set(versions)) or any(spec.target_version != spec.version for spec in MIGRATION_REGISTRY):
        raise RuntimeError("migration registry versions are not strictly ordered and unique")
    if len(ids) != len(set(ids)):
        raise RuntimeError("migration registry migration_id values are not unique")
    for spec, expected_previous in zip(MIGRATION_REGISTRY, [None, 1, 2, 3, 4, 5, 6, 7, 8]):
        if spec.previous_version != expected_previous or not spec.checksum.startswith("sha256:") or len(spec.checksum) != 71 or spec.checksum != _EXPECTED_CHECKSUMS.get(spec.version):
            raise RuntimeError(f"migration registry linkage/checksum invalid for version {spec.version}")
        if spec.apply is None or spec.verify is None or spec.reconcile is None or spec.apply_artifact != FORWARD_APPLY_SOURCE_SHA256.get(spec.version):
            raise RuntimeError(f"migration registry operation missing for version {spec.version}")


validate_registry()
