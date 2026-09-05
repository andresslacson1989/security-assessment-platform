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

REGISTRY_REVISION = "migration-registry-v1"


class MigrationManagerProtocol(Protocol):
    def _verify_migration_v1_postconditions(self, conn) -> None: ...
    def _verify_migration_v2_postconditions(self, conn) -> None: ...
    def _verify_migration_v3_postconditions(self, conn) -> None: ...
    def _verify_migration_v4_postconditions(self, conn) -> None: ...
    def _verify_migration_v5_postconditions(self, conn) -> None: ...
    def _verify_migration_v6_postconditions(self, conn) -> None: ...
    def _verify_migration_v7_postconditions(self, conn) -> None: ...
    def _verify_migration_v8_postconditions(self, conn) -> None: ...


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
)


def _verify_v1(manager: MigrationManagerProtocol, conn) -> None:
    manager._verify_migration_v1_postconditions(conn)


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


_VERIFIERS = (_verify_v1, _verify_v2, _verify_v3, _verify_v4, _verify_v5, _verify_v6, _verify_v7, _verify_v8)
_VERIFIER_METHODS = (
    "_verify_migration_v1_postconditions",
    "_verify_migration_v2_postconditions",
    "_verify_migration_v3_postconditions",
    "_verify_migration_v4_postconditions",
    "_verify_migration_v5_postconditions",
    "_verify_migration_v6_postconditions",
    "_verify_migration_v7_postconditions",
    "_verify_migration_v8_postconditions",
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
        "postcondition_manifest_revision": "execution-postconditions-v2",
        "verifier_method": _VERIFIER_METHODS[version - 1],
        "verifier_artifact": inspect.getsource(_VERIFIERS[version - 1]),
    }
    return MigrationSpec(
        version=version, migration_id=migration_id, name=name,
        previous_version=previous, target_version=version,
        contract_schema_version=SCHEMA_VERSION, contract_version=CONTRACT_VERSION,
        registry_revision=REGISTRY_REVISION, checksum=_checksum(material),
        verify=_VERIFIERS[version - 1],
    )


MIGRATION_REGISTRY = tuple(_make_spec(*descriptor) for descriptor in _DESCRIPTORS)

_EXPECTED_CHECKSUMS = {
    1: "sha256:0c36e6c5488b142ccf4f74da0475aa834dcb6e386e10dfb7768e89303ed88654",
    2: "sha256:1ccecb87f29e43d88d80aaa1b04c0c51b3d6d0c51e470304a7d45b53c0f12f6d",
    3: "sha256:4a12b127f5094bfdbf6480964afdfa07ad2703c6b5384af1d27a3ceaac50432a",
    4: "sha256:a16fad4273e77b4befb6ecbb179801b9aeb3ecb31508a121e734d44a8dd87f0a",
    5: "sha256:71694628c476c7be89ac879be8b42fd6d61d9404cf7c6adc7c785521075e8c01",
    6: "sha256:cb7d52bea96f013b396eee7f1f25e8a8a7045231518877f9696afa8ebc85569f",
    7: "sha256:dd0feb2e5160ddd7625628cbabef51a98afbff648652a7bd87c1a0bc1ce1ba70",
    8: "sha256:6d7c6fcb0af93ddccdd185c8fa486631cde40ab1ca0800e78946c52471ec520f",
}


def validate_registry() -> None:
    versions = [spec.version for spec in MIGRATION_REGISTRY]
    ids = [spec.migration_id for spec in MIGRATION_REGISTRY]
    if versions != sorted(set(versions)) or any(spec.target_version != spec.version for spec in MIGRATION_REGISTRY):
        raise RuntimeError("migration registry versions are not strictly ordered and unique")
    if len(ids) != len(set(ids)):
        raise RuntimeError("migration registry migration_id values are not unique")
    for spec, expected_previous in zip(MIGRATION_REGISTRY, [None, 1, 2, 3, 4, 5, 6, 7]):
        if spec.previous_version != expected_previous or not spec.checksum.startswith("sha256:") or len(spec.checksum) != 71 or spec.checksum != _EXPECTED_CHECKSUMS.get(spec.version):
            raise RuntimeError(f"migration registry linkage/checksum invalid for version {spec.version}")
        if spec.verify is None:
            raise RuntimeError(f"migration registry verifier missing for version {spec.version}")


validate_registry()
