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
from app.core.migration_artifacts import POSTCONDITION_ARTIFACT_REVISION, POSTCONDITION_SOURCE_SHA256

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
    }
    return MigrationSpec(
        version=version, migration_id=migration_id, name=name,
        previous_version=previous, target_version=version,
        contract_schema_version=SCHEMA_VERSION, contract_version=CONTRACT_VERSION,
        registry_revision=REGISTRY_REVISION, checksum=_checksum(material),
        apply=_apply_version(version), verify=_VERIFIERS[version - 1],
        reconcile=_reconcile_version(version),
    )


MIGRATION_REGISTRY = tuple(_make_spec(*descriptor) for descriptor in _DESCRIPTORS)

_EXPECTED_CHECKSUMS = {
    1: "sha256:d67b1f1dd9149120504c946f5d514b155f0b685ff0983b058c97a169bc0ceb1c",
    2: "sha256:cb581847722adabb6b9fbdfa38f962790e0842dfa10eb0d1cd8c89f58c5eac64",
    3: "sha256:cd6e1b03a386049a28e2a9c1d8b33db6ec4f302d0d27e9a438629a63160e14e2",
    4: "sha256:245a6167393211c34f6963b3f2b1d78098fb5b5c7a47750ef446801e35e5d97a",
    5: "sha256:bdc72fda90958fd58509c0e4afdcfc2079c82689db98abe49aeb0e41d0f8f869",
    6: "sha256:85cb5bbf7ffe327bd97633dc72e107f31470be4ef28f50527adad3f481a53f18",
    7: "sha256:fb0be1cafc6be8f45ff0e9237e5b375ea29fa657d2fa9768204fd2174695609f",
    8: "sha256:34b28b5ea61df1d3fab89d000b871040858deb9cc5b923c0d8e32f776428ee6f",
    9: "sha256:f6967da3ce7cf80ddd1531f0922c7bf3398cccb0d89a0b61909427bbafe42765",
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
        if spec.apply is None or spec.verify is None or spec.reconcile is None:
            raise RuntimeError(f"migration registry operation missing for version {spec.version}")


validate_registry()
