"""
Contract 01 §5 & Contract 08 §12:
Global Scan Execution Queue, Concurrency Governance & Worker Pool.
Guarantees resource isolation, preventing server resource exhaustion or unconstrained process spawning.
"""

from __future__ import annotations
import asyncio
import hashlib
import inspect
import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Callable, Awaitable, Protocol, Sequence

from app.core.models import CloudCredentialEnvelope
from app.core.credential_handoff import encrypt_credential_envelope, decrypt_credential_envelope

MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))
MAX_CONCURRENT_SCANS_PER_TENANT = int(os.getenv("MAX_CONCURRENT_SCANS_PER_TENANT", "2"))
GLOBAL_SCAN_TIMEOUT_SECONDS = float(os.getenv("GLOBAL_SCAN_TIMEOUT_SECONDS", "300.0"))
EXECUTION_QUEUE_URL = os.getenv("EXECUTION_QUEUE_URL", "").strip()

# The parent scan authorization currently has a bounded 15-minute lifetime.
# Retain a queue publication identity substantially longer than that lifetime so
# an exact approval replay after an API/worker restart cannot create a second
# Redis Stream entry.  The value is deliberately bounded and can only be
# increased within the reviewed operational range.
_QUEUE_DEDUPE_TTL_SECONDS = int(os.getenv("EXECUTION_QUEUE_DEDUPE_TTL_SECONDS", "86400"))
if not 900 <= _QUEUE_DEDUPE_TTL_SECONDS <= 604800:
    raise RuntimeError("EXECUTION_QUEUE_DEDUPE_TTL_SECONDS must be between 900 and 604800 seconds")

_QUEUE_MAX_DELIVERY_ATTEMPTS = int(os.getenv("EXECUTION_QUEUE_MAX_DELIVERY_ATTEMPTS", "5"))
if not 1 <= _QUEUE_MAX_DELIVERY_ATTEMPTS <= 100:
    raise RuntimeError("EXECUTION_QUEUE_MAX_DELIVERY_ATTEMPTS must be between 1 and 100")

_QUEUE_QUARANTINE_TTL_SECONDS = int(os.getenv("EXECUTION_QUEUE_QUARANTINE_TTL_SECONDS", "86400"))
if not 300 <= _QUEUE_QUARANTINE_TTL_SECONDS <= 2592000:
    raise RuntimeError("EXECUTION_QUEUE_QUARANTINE_TTL_SECONDS must be between 300 and 2592000 seconds")

_QUEUE_QUARANTINE_SCHEMA_VERSION = "queue-quarantine-v3"
_QUEUE_MESSAGE_KIND_AUTHORITATIVE = "AUTHORITATIVE_EXECUTION"
_QUEUE_MESSAGE_KIND_LEGACY = "LEGACY_DIAGNOSTIC"
_QUEUE_MESSAGE_KIND_AMBIGUOUS = "AMBIGUOUS_UNCLASSIFIED"
_QUEUE_MESSAGE_KINDS = frozenset({
    _QUEUE_MESSAGE_KIND_AUTHORITATIVE,
    _QUEUE_MESSAGE_KIND_LEGACY,
    _QUEUE_MESSAGE_KIND_AMBIGUOUS,
})
# These are the only malformed-wire outcomes that an authenticated tenant
# operator may explicitly close. The recovery operation acknowledges the
# pending stream entry for evidence cleanup; it never reclassifies the wire
# payload or permits handler entry.
_QUEUE_AMBIGUOUS_RECOVERY_REASONS = frozenset({
    "QUEUE_MESSAGE_CLASSIFICATION_REJECTED",
    "QUEUE_BINDING_REJECTED",
})
_QUEUE_WIRE_FIELDS = frozenset({
    "message_kind",
    "scan_id",
    "organization_id",
    "enqueued_at",
    "authorization_request_id",
    "credential_envelope",
    "queue_binding_digest",
    "manifest_hash",
    "execution_ids_json",
    "operation_ids_json",
    "queue_binding_schema_version",
})
_QUEUE_FAILURE_EVIDENCE_FIELDS = frozenset({
    "message_id",
    "dispatch_message_id",
    "error_code",
    "failure_category",
    "failure_observed_at",
    "requeue_required",
    "escalated",
    "quarantined",
    "scan_id",
    "organization_id",
    "authorization_request_id",
    "queue_binding_digest",
    "manifest_hash",
    "execution_ids_json",
    "operation_ids_json",
    "queue_binding_schema_version",
    "attempt_count",
    "max_attempts",
    "message_kind",
})
_QUEUE_REQUIRED_FAILURE_EVIDENCE_FIELDS = frozenset({
    "message_id",
    "dispatch_message_id",
    "error_code",
    "failure_category",
    "failure_observed_at",
    "requeue_required",
    "escalated",
    "quarantined",
    "message_kind",
})
_QUEUE_SAFE_TEXT_PATTERN = re.compile(r"[\x21-\x7e]{1,256}")
_QUEUE_FAILURE_EVIDENCE_MAX_LENGTHS = {
    "execution_ids_json": 131072,
    "operation_ids_json": 131072,
}
_QUEUE_QUARANTINE_STATE_FIELDS = frozenset({
    "schema_version",
    "status",
    "message_id",
    "reason",
    "quarantined_at",
    "failure_evidence",
    "failure_evidence_digest",
    "quarantine_state_digest",
    "message_kind",
    "scan_id",
    "organization_id",
    "authorization_request_id",
    "queue_binding_digest",
    "manifest_hash",
    "execution_ids",
    "operation_ids",
    "attempt_count",
    "max_attempts",
})


def _safe_queue_text(value: object, *, maximum: int = 256) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= maximum
        and _QUEUE_SAFE_TEXT_PATTERN.fullmatch(value) is not None
    )


def _validate_identity_json_fields(fields: dict[str, str]) -> None:
    identity_fields = {
        "queue_binding_digest",
        "manifest_hash",
        "execution_ids_json",
        "operation_ids_json",
        "queue_binding_schema_version",
    }
    present = identity_fields.intersection(fields)
    if not present:
        return
    if present != identity_fields:
        raise ValueError("queue binding identity fields must be complete")
    QueueDispatchBinding.from_payload(fields)


def _canonical_failure_evidence(
    message_id: str,
    failure_fields: dict[str, str],
    *,
    require_quarantined: bool = True,
) -> dict[str, str]:
    """Return the exact non-secret failure evidence retained by quarantine.

    Quarantine is an authoritative safety state.  Its durable record must carry
    the original sanitized failure evidence, rather than relying on a separate
    stream entry that may later expire or become operationally unavailable.
    Unknown fields are rejected so callers cannot persist credentials or
    ambient payload data by smuggling them through the failure record.
    """
    if not isinstance(failure_fields, dict):
        raise ValueError("queue failure evidence must be a mapping")
    unknown_fields = set(failure_fields).difference(_QUEUE_FAILURE_EVIDENCE_FIELDS)
    if unknown_fields:
        raise ValueError("queue failure evidence contains unsupported fields")
    evidence: dict[str, str] = {}
    for field_name, value in failure_fields.items():
        maximum_length = _QUEUE_FAILURE_EVIDENCE_MAX_LENGTHS.get(field_name, 256)
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= maximum_length
            or not re.fullmatch(r"[\x21-\x7e]+", value)
        ):
            raise ValueError(f"queue failure evidence field {field_name} is invalid")
        evidence[field_name] = value
    if not _QUEUE_REQUIRED_FAILURE_EVIDENCE_FIELDS.issubset(evidence):
        raise ValueError("queue failure evidence is incomplete")
    if evidence["message_id"] != message_id or evidence["dispatch_message_id"] != message_id:
        raise ValueError("queue failure evidence message identity does not match")
    if evidence["quarantined"] not in {"0", "1"}:
        raise ValueError("queue failure evidence quarantine state is invalid")
    if require_quarantined and evidence["quarantined"] != "1":
        raise ValueError("authoritative quarantine evidence must be marked quarantined")
    if evidence["message_kind"] not in _QUEUE_MESSAGE_KINDS:
        raise ValueError("queue failure evidence message kind is invalid")
    if evidence["message_kind"] == _QUEUE_MESSAGE_KIND_LEGACY and require_quarantined:
        raise ValueError("legacy diagnostic evidence cannot be authoritative quarantine evidence")
    for field_name in ("organization_id", "authorization_request_id"):
        if field_name in evidence and not _safe_queue_text(evidence[field_name]):
            raise ValueError(f"queue failure evidence field {field_name} is invalid")
    if "authorization_request_id" in evidence and "organization_id" not in evidence:
        raise ValueError("queue failure authorization identity requires a tenant")
    _validate_identity_json_fields(evidence)
    for field_name in ("attempt_count", "max_attempts"):
        if field_name in evidence:
            if not evidence[field_name].isdigit() or int(evidence[field_name]) < 1:
                raise ValueError(f"queue failure evidence field {field_name} is invalid")
    if "attempt_count" in evidence and "max_attempts" in evidence:
        if int(evidence["attempt_count"]) > int(evidence["max_attempts"]):
            raise ValueError("queue failure delivery count exceeds its declared bound")
    return dict(sorted(evidence.items()))


def _failure_evidence_digest(evidence: dict[str, str]) -> str:
    return hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _quarantine_state_digest(state: dict[str, Any]) -> str:
    material = {key: value for key, value in state.items() if key != "quarantine_state_digest"}
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


class DurableQueueIdentityConflict(RuntimeError):
    """Raised when a request identity is already bound to different content."""


_QUEUE_IDENTITY_CONFLICT_PREFIX = "__CYBERASSESS_QUEUE_IDENTITY_CONFLICT__:"


def _queue_binding_digest(
    scan_id: str,
    organization_id: str,
    authorization_request_id: str,
    manifest_hash: str,
    execution_ids: Sequence[str],
    operation_ids: Sequence[str],
) -> str:
    canonical = {
        "schema_version": "queue-dispatch-binding-v1",
        "scan_id": scan_id,
        "organization_id": organization_id,
        "authorization_request_id": authorization_request_id,
        "manifest_hash": manifest_hash,
        "execution_ids": list(execution_ids),
        "operation_ids": list(operation_ids),
    }
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class QueueDispatchBinding:
    """Immutable, typed binding for one consumed worker handoff.

    The envelope is serialized into an authoritative Redis publication and
    passed through the worker handoff.  The worker must still compare it with
    the authoritative database rows before deciding whether a delivery is an
    exact terminal replay.
    """

    scan_id: str
    organization_id: str
    authorization_request_id: str
    manifest_hash: str
    execution_ids: tuple[str, ...]
    operation_ids: tuple[str, ...]
    queue_binding_digest: str
    schema_version: str = "queue-dispatch-binding-v1"

    def __post_init__(self) -> None:
        for field_name, value in (
            ("scan_id", self.scan_id),
            ("organization_id", self.organization_id),
            ("authorization_request_id", self.authorization_request_id),
            ("manifest_hash", self.manifest_hash),
            ("queue_binding_digest", self.queue_binding_digest),
        ):
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"queue binding {field_name} is invalid")
        if self.schema_version != "queue-dispatch-binding-v1":
            raise ValueError("queue binding schema version is unsupported")
        if (
            len(self.manifest_hash) != 64
            or any(character not in "0123456789abcdef" for character in self.manifest_hash)
        ):
            raise ValueError("queue binding manifest hash is invalid")
        if (
            len(self.queue_binding_digest) != 64
            or any(character not in "0123456789abcdef" for character in self.queue_binding_digest)
        ):
            raise ValueError("queue binding digest is invalid")
        if not isinstance(self.execution_ids, tuple) or not isinstance(self.operation_ids, tuple):
            raise ValueError("queue binding identity lists must be tuples")
        if not self.execution_ids or len(self.execution_ids) != len(self.operation_ids):
            raise ValueError("queue binding operation/execution set is incomplete")
        for label, values in (("execution", self.execution_ids), ("operation", self.operation_ids)):
            if any(not isinstance(value, str) or not value.strip() or len(value) > 256 for value in values):
                raise ValueError(f"queue binding {label} identity is invalid")
            if len(set(values)) != len(values):
                raise ValueError(f"queue binding {label} identities are duplicated")
        expected = _queue_binding_digest(
            self.scan_id,
            self.organization_id,
            self.authorization_request_id,
            self.manifest_hash,
            self.execution_ids,
            self.operation_ids,
        )
        if self.queue_binding_digest != expected:
            raise ValueError("queue binding digest does not match canonical content")

    @classmethod
    def create(
        cls,
        *,
        scan_id: str,
        organization_id: str,
        authorization_request_id: str,
        manifest_hash: str,
        execution_ids: Sequence[str],
        operation_ids: Sequence[str],
    ) -> "QueueDispatchBinding":
        if isinstance(execution_ids, (str, bytes)) or isinstance(operation_ids, (str, bytes)):
            raise ValueError("queue binding identity lists are not sequences of identities")
        if len(operation_ids) != len(execution_ids):
            raise ValueError("queue binding operation/execution set is incomplete")
        pairs = sorted(zip(operation_ids, execution_ids), key=lambda pair: pair[0])
        ordered_operations = tuple(pair[0] for pair in pairs)
        ordered_executions = tuple(pair[1] for pair in pairs)
        return cls(
            scan_id=scan_id,
            organization_id=organization_id,
            authorization_request_id=authorization_request_id,
            manifest_hash=manifest_hash,
            execution_ids=ordered_executions,
            operation_ids=ordered_operations,
            queue_binding_digest=_queue_binding_digest(
                scan_id,
                organization_id,
                authorization_request_id,
                manifest_hash,
                ordered_executions,
                ordered_operations,
            ),
        )

    @classmethod
    def from_payload(cls, fields: Dict[str, Any]) -> "QueueDispatchBinding":
        if not isinstance(fields, dict):
            raise ValueError("queue binding payload must be an object")
        required_fields = {
            "scan_id",
            "organization_id",
            "authorization_request_id",
            "manifest_hash",
            "execution_ids_json",
            "operation_ids_json",
            "queue_binding_digest",
            "queue_binding_schema_version",
        }
        if not required_fields.issubset(fields):
            raise ValueError("queue binding payload is incomplete")
        if any(
            not isinstance(fields[field_name], str)
            for field_name in required_fields
        ):
            raise ValueError("queue binding payload contains non-string identity material")
        try:
            execution_ids = json.loads(fields["execution_ids_json"])
            operation_ids = json.loads(fields["operation_ids_json"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("queue binding identity lists are malformed") from exc
        if not isinstance(execution_ids, list) or not isinstance(operation_ids, list):
            raise ValueError("queue binding identity lists are malformed")
        binding = cls(
            scan_id=fields["scan_id"],
            organization_id=fields["organization_id"],
            authorization_request_id=fields["authorization_request_id"],
            manifest_hash=fields["manifest_hash"],
            execution_ids=tuple(execution_ids),
            operation_ids=tuple(operation_ids),
            queue_binding_digest=fields["queue_binding_digest"],
            schema_version=fields["queue_binding_schema_version"],
        )
        # ``create`` is the sole canonicalization boundary. A digest-valid
        # payload with reordered operation/execution tuples is still an
        # invalid wire representation and must fail before worker dispatch.
        canonical = cls.create(
            scan_id=binding.scan_id,
            organization_id=binding.organization_id,
            authorization_request_id=binding.authorization_request_id,
            manifest_hash=binding.manifest_hash,
            execution_ids=binding.execution_ids,
            operation_ids=binding.operation_ids,
        )
        if binding != canonical:
            raise ValueError("queue binding payload is not canonically ordered")
        return binding

    @property
    def execution_ids_json(self) -> str:
        return json.dumps(list(self.execution_ids), separators=(",", ":"), ensure_ascii=True)

    @property
    def operation_ids_json(self) -> str:
        return json.dumps(list(self.operation_ids), separators=(",", ":"), ensure_ascii=True)


_QUEUE_OPERATOR_ISSUER = object()


class QueueQuarantineOperatorAuthorization:
    """Opaque handoff issued only after the application auth boundary verifies a session.

    This is deliberately not a data-only dataclass.  The queue primitive can
    accept only an instance produced by the private authenticated-service
    factory below.  The factory is called by an API dependency that has already
    validated the signed session, durable revocation state, tenant, role, and
    recovery permission.
    """

    __slots__ = ("actor_id", "organization_id", "session_binding", "permission", "_issued")

    def __init__(self, *, actor_id: str, organization_id: str, session_binding: str, permission: str, _issuer: object):
        if _issuer is not _QUEUE_OPERATOR_ISSUER:
            raise TypeError("quarantine authorization must be issued by the authenticated service boundary")
        for field_name, value in (
            ("actor_id", actor_id),
            ("organization_id", organization_id),
            ("session_binding", session_binding),
        ):
            if not _safe_queue_text(value):
                raise ValueError(f"quarantine operator {field_name} is invalid")
        if permission != "execution:recovery":
            raise ValueError("quarantine operator permission is invalid")
        self.actor_id = actor_id
        self.organization_id = organization_id
        self.session_binding = session_binding
        self.permission = permission
        self._issued = True


def _issue_authenticated_quarantine_authorization(
    *, actor_id: str, organization_id: str, session_binding: str, permission: str = "execution:recovery"
) -> QueueQuarantineOperatorAuthorization:
    """Private auth-to-queue handoff; callers must first pass app auth guards."""
    return QueueQuarantineOperatorAuthorization(
        actor_id=actor_id,
        organization_id=organization_id,
        session_binding=session_binding,
        permission=permission,
        _issuer=_QUEUE_OPERATOR_ISSUER,
    )


_IDEMPOTENT_ENQUEUE_SCRIPT = """
local existing = redis.call('GET', KEYS[1])
if existing then
    local entries = redis.call('XRANGE', KEYS[2], existing, existing)
    if #entries == 0 then
        return '__CYBERASSESS_QUEUE_IDENTITY_CONFLICT__:MISSING_ENTRY'
    end
    local fields = entries[1][2]
    local queued_scan = nil
    local queued_organization = nil
    local queued_request = nil
    local queued_digest = nil
    local queued_manifest_hash = nil
    local queued_execution_ids = nil
    local queued_operation_ids = nil
    local queued_schema_version = nil
    local queued_message_kind = nil
    for index = 1, #fields, 2 do
        if fields[index] == 'scan_id' then
            queued_scan = fields[index + 1]
        elseif fields[index] == 'organization_id' then
            queued_organization = fields[index + 1]
        elseif fields[index] == 'authorization_request_id' then
            queued_request = fields[index + 1]
        elseif fields[index] == 'queue_binding_digest' then
            queued_digest = fields[index + 1]
        elseif fields[index] == 'manifest_hash' then
            queued_manifest_hash = fields[index + 1]
        elseif fields[index] == 'execution_ids_json' then
            queued_execution_ids = fields[index + 1]
        elseif fields[index] == 'operation_ids_json' then
            queued_operation_ids = fields[index + 1]
        elseif fields[index] == 'queue_binding_schema_version' then
            queued_schema_version = fields[index + 1]
        elseif fields[index] == 'message_kind' then
            queued_message_kind = fields[index + 1]
        end
    end
    if queued_scan ~= ARGV[1]
        or queued_organization ~= ARGV[2]
        or queued_request ~= ARGV[4]
        or queued_digest ~= ARGV[7]
        or queued_manifest_hash ~= ARGV[8]
        or queued_execution_ids ~= ARGV[9]
        or queued_operation_ids ~= ARGV[10]
        or queued_schema_version ~= ARGV[11]
        or queued_message_kind ~= ARGV[12] then
        return '__CYBERASSESS_QUEUE_IDENTITY_CONFLICT__:MISMATCH'
    end
    return existing
end
local message_id = redis.call(
    'XADD', KEYS[2], '*',
    'scan_id', ARGV[1],
    'organization_id', ARGV[2],
    'enqueued_at', ARGV[3],
    'authorization_request_id', ARGV[4],
    'credential_envelope', ARGV[5],
    'queue_binding_digest', ARGV[7],
    'manifest_hash', ARGV[8],
    'execution_ids_json', ARGV[9],
    'operation_ids_json', ARGV[10],
    'queue_binding_schema_version', ARGV[11],
    'message_kind', ARGV[12]
)
redis.call('SET', KEYS[1], message_id, 'EX', ARGV[6])
return message_id
"""

_ACK_QUARANTINE_SCRIPT = """
if redis.call('GET', KEYS[1]) ~= ARGV[1] then
    return 0
end
local acknowledged = redis.call('XACK', KEYS[4], ARGV[2], ARGV[3])
if acknowledged ~= 1 then
    return 0
end
local event_fields = {}
for index = 4, #ARGV do
    event_fields[index - 3] = ARGV[index]
end
redis.call('XADD', KEYS[3], '*', unpack(event_fields))
redis.call('DEL', KEYS[1], KEYS[2])
return 1
"""


class DurableQueueBackend(Protocol):
    async def enqueue(
        self,
        scan_id: str,
        organization_id: Optional[str],
        credential_envelope: Optional[CloudCredentialEnvelope] = None,
        authorization_request_id: Optional[str] = None,
        *,
        queue_binding: Optional[QueueDispatchBinding] = None,
    ) -> str: ...
    async def complete(self, message_id: str) -> None: ...
    async def fail(
        self,
        message_id: str,
        error_code: str,
        *,
        acknowledge: bool = True,
        scan_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        authorization_request_id: Optional[str] = None,
        queue_binding_digest: Optional[str] = None,
        manifest_hash: Optional[str] = None,
        execution_ids: Optional[Sequence[str]] = None,
        operation_ids: Optional[Sequence[str]] = None,
        message_kind: Optional[str] = None,
        attempt_count: Optional[int] = None,
        max_attempts: Optional[int] = None,
        escalated: bool = False,
        quarantined: bool = False,
    ) -> None: ...


class DurableQueueConsumer(Protocol):
    async def consume_once(
        self,
        handler: Callable[..., Awaitable[None]],
        *,
        block_ms: int = 5000,
        reclaim_idle_ms: int = 60000,
    ) -> bool: ...


class RedisDurableQueue:
    """Redis Streams-backed execution intent queue for enterprise deployments."""

    stream_name = "cyberassess:scan-execution"
    consumer_group = "cyberassess-workers"

    def __init__(self, redis_url: str):
        try:
            import redis.asyncio as redis
        except ImportError as exc:
            raise RuntimeError("EXECUTION_QUEUE_URL requires the redis package") from exc
        # The queue uses XAUTOCLAIM, so the service baseline is Redis 6.2+
        # (the deployment workflow uses Redis 7). Explicit RESP2 keeps the
        # client compatible with that baseline and newer redis-py releases;
        # the queue's Lua/Streams protocol does not require RESP3 semantics.
        self._redis = redis.from_url(redis_url, decode_responses=True, protocol=2)
        self._consumer_name = f"worker-{uuid.uuid4().hex}"
        self._group_ready = False
        self._group_lock = asyncio.Lock()

    async def _ensure_group(self) -> None:
        if self._group_ready:
            return
        async with self._group_lock:
            if self._group_ready:
                return
            try:
                await self._redis.xgroup_create(
                    self.stream_name, self.consumer_group, id="0", mkstream=True
                )
            except Exception as exc:
                if "BUSYGROUP" not in str(exc):
                    raise
            self._group_ready = True

    def _quarantine_key(self, message_id: str) -> str:
        digest = hashlib.sha256(str(message_id).encode("utf-8")).hexdigest()
        return f"{self.stream_name}:quarantine:{digest}"

    def _quarantine_state_key(self, message_id: str) -> str:
        digest = hashlib.sha256(str(message_id).encode("utf-8")).hexdigest()
        return f"{self.stream_name}:quarantine-state:{digest}"

    async def _delivery_attempts(self, message_id: str) -> int:
        """Read the Redis Streams delivery counter for one claimed message."""
        inspector = getattr(self._redis, "xpending_range", None)
        if not callable(inspector):
            # Redis 7 exposes XPENDING range inspection. An authoritative
            # worker must not guess a delivery count when that inspection is
            # unavailable, because doing so could re-enter a poisoned message
            # after its retry bound.
            raise RuntimeError("authoritative Redis delivery counter is unavailable")
        entries = await inspector(
            self.stream_name,
            self.consumer_group,
            min=message_id,
            max=message_id,
            count=1,
        )
        if not entries:
            raise RuntimeError("authoritative Redis delivery counter is unavailable for the pending message")
        entry = entries[0]
        if isinstance(entry, dict):
            if "times_delivered" not in entry:
                raise ValueError("Redis delivery counter is malformed")
            value = entry["times_delivered"]
        elif isinstance(entry, (list, tuple)) and len(entry) >= 4:
            value = entry[3]
        else:
            raise ValueError("Redis delivery counter is malformed")
        if type(value) is not int or value < 1:
            raise ValueError("Redis delivery counter is invalid")
        return value

    async def _is_quarantined(self, message_id: str) -> bool:
        state = await self._redis.get(self._quarantine_state_key(message_id))
        if state is not None:
            return True
        return bool(await self._redis.get(self._quarantine_key(message_id)))

    async def _get_quarantine_state(self, message_id: str) -> Optional[dict[str, Any]]:
        raw_state = await self._redis.get(self._quarantine_state_key(message_id))
        if raw_state is None:
            raw_state = await self._redis.get(self._quarantine_key(message_id))
        if raw_state is None:
            return None
        try:
            state = json.loads(raw_state)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        if (
            not isinstance(state, dict)
            or set(state) - _QUEUE_QUARANTINE_STATE_FIELDS
            or state.get("schema_version") != _QUEUE_QUARANTINE_SCHEMA_VERSION
            or state.get("status") != "QUARANTINED"
            or state.get("message_id") != message_id
        ):
            return None
        evidence = state.get("failure_evidence")
        digest = state.get("failure_evidence_digest")
        try:
            canonical_evidence = _canonical_failure_evidence(message_id, evidence)
        except (TypeError, ValueError):
            return None
        if not isinstance(digest, str) or digest != _failure_evidence_digest(canonical_evidence):
            return None
        if state.get("message_kind") != canonical_evidence.get("message_kind"):
            return None
        for field_name in (
            "scan_id", "organization_id", "authorization_request_id",
            "queue_binding_digest", "manifest_hash",
        ):
            if field_name in canonical_evidence and state.get(field_name) != canonical_evidence[field_name]:
                return None
            if field_name not in canonical_evidence and field_name in state:
                return None
        for field_name in ("execution_ids", "operation_ids"):
            evidence_field = f"{field_name}_json"
            if evidence_field in canonical_evidence:
                try:
                    expected = json.loads(canonical_evidence[evidence_field])
                except (TypeError, ValueError, json.JSONDecodeError):
                    return None
                if state.get(field_name) != expected:
                    return None
            elif field_name in state:
                return None
        for field_name in ("attempt_count", "max_attempts"):
            if field_name in canonical_evidence and state.get(field_name) != int(canonical_evidence[field_name]):
                return None
            if field_name not in canonical_evidence and field_name in state:
                return None
        if not isinstance(state.get("quarantine_state_digest"), str):
            return None
        if state["quarantine_state_digest"] != _quarantine_state_digest(state):
            return None
        state["failure_evidence"] = canonical_evidence
        return state

    async def _quarantine(
        self,
        message_id: str,
        *,
        reason: str,
        scan_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        authorization_request_id: Optional[str] = None,
        queue_binding_digest: Optional[str] = None,
        manifest_hash: Optional[str] = None,
        execution_ids: Optional[Sequence[str]] = None,
        operation_ids: Optional[Sequence[str]] = None,
        attempt_count: Optional[int] = None,
        max_attempts: Optional[int] = None,
        failure_fields: Optional[dict[str, str]] = None,
        acknowledge: bool = False,
    ) -> None:
        """Atomically persist one authoritative quarantine outcome.

        The durable state, expiring review marker, and original sanitized
        failure event are one governed Redis transaction.  Authoritative
        quarantine must fail closed when the transport cannot provide a
        transaction; sequential writes could otherwise expose a failure event
        without the quarantine safety gate (or the reverse).
        """
        evidence = _canonical_failure_evidence(message_id, failure_fields or {})
        safe_reason = reason if _QUEUE_SAFE_TEXT_PATTERN.fullmatch(str(reason)[:256]) else "QUEUE_FAILURE"
        state: dict[str, Any] = {
            "schema_version": _QUEUE_QUARANTINE_SCHEMA_VERSION,
            "status": "QUARANTINED",
            "message_id": message_id,
            "reason": safe_reason[:128],
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "failure_evidence": evidence,
            "failure_evidence_digest": _failure_evidence_digest(evidence),
            "message_kind": evidence["message_kind"],
        }
        for field_name, value in (
            ("scan_id", scan_id),
            ("organization_id", organization_id),
            ("authorization_request_id", authorization_request_id),
            ("queue_binding_digest", queue_binding_digest),
            ("manifest_hash", manifest_hash),
        ):
            if value is not None:
                if evidence.get(field_name) != value:
                    raise ValueError(f"quarantine identity does not match failure evidence: {field_name}")
                state[field_name] = value
        for field_name, values in (
            ("execution_ids", execution_ids),
            ("operation_ids", operation_ids),
        ):
            if values is not None:
                normalized = list(values)
                encoded = json.dumps(normalized, separators=(",", ":"), ensure_ascii=True)
                if evidence.get(f"{field_name}_json") != encoded:
                    raise ValueError(f"quarantine identity list does not match failure evidence: {field_name}")
                state[field_name] = normalized
        if type(attempt_count) is int and attempt_count >= 1:
            if evidence.get("attempt_count") != str(attempt_count):
                raise ValueError("quarantine attempt count does not match failure evidence")
            state["attempt_count"] = attempt_count
        if type(max_attempts) is int and max_attempts >= 1:
            if evidence.get("max_attempts") != str(max_attempts):
                raise ValueError("quarantine delivery bound does not match failure evidence")
            state["max_attempts"] = max_attempts
        state["quarantine_state_digest"] = _quarantine_state_digest(state)
        serialized = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

        # The persistent state is the safety gate. The review marker retains
        # its bounded TTL for operational visibility, but expiry can never
        # re-enable handler entry because the state key has no expiration.
        pipeline_factory = getattr(self._redis, "pipeline", None)
        if not callable(pipeline_factory):
            raise RuntimeError("authoritative quarantine transaction is unavailable")
        try:
            pipeline = pipeline_factory(transaction=True)
            pipeline.set(self._quarantine_state_key(message_id), serialized)
            pipeline.set(self._quarantine_key(message_id), serialized, ex=_QUEUE_QUARANTINE_TTL_SECONDS)
            pipeline.xadd(f"{self.stream_name}:failures", evidence)
            if acknowledge:
                pipeline.xack(self.stream_name, self.consumer_group, message_id)
            await pipeline.execute()
        except Exception as exc:
            raise RuntimeError("authoritative quarantine transaction could not be committed") from exc

    async def enqueue(
        self,
        scan_id: str,
        organization_id: Optional[str],
        credential_envelope: Optional[CloudCredentialEnvelope] = None,
        authorization_request_id: Optional[str] = None,
        *,
        queue_binding: Optional[QueueDispatchBinding] = None,
    ) -> str:
        if not isinstance(scan_id, str) or not scan_id.strip():
            raise ValueError("execution intent requires a scan identity")
        if authorization_request_id is not None and (
            not isinstance(authorization_request_id, str)
            or not authorization_request_id.strip()
            or len(authorization_request_id) > 256
        ):
            raise ValueError("execution intent authorization request identity is invalid")
        if authorization_request_id and not organization_id:
            raise ValueError("execution intent authorization request requires a tenant")
        if authorization_request_id:
            if type(queue_binding) is not QueueDispatchBinding:
                raise ValueError("authoritative execution intent requires a typed queue binding")
            try:
                expected_binding = QueueDispatchBinding.create(
                    scan_id=scan_id,
                    organization_id=organization_id or "",
                    authorization_request_id=authorization_request_id.strip(),
                    manifest_hash=queue_binding.manifest_hash,
                    execution_ids=queue_binding.execution_ids,
                    operation_ids=queue_binding.operation_ids,
                )
            except (TypeError, ValueError) as exc:
                raise ValueError("authoritative queue binding is malformed") from exc
            if queue_binding != expected_binding:
                raise ValueError("authoritative queue binding does not match its canonical digest")
        elif queue_binding is not None:
            raise ValueError("a queue binding requires an authoritative authorization request")
        if credential_envelope is not None and not authorization_request_id:
            # A credential is an execution intent, not a diagnostic payload.
            # Refuse it before encryption so an unauthorised caller cannot
            # downgrade credentialed work into the legacy ACK path.
            raise ValueError(
                "credential handoff requires an authoritative authorization request and typed queue binding"
            )
        await self._ensure_group()
        enqueued_at = datetime.now(timezone.utc).isoformat()
        fields = {
            "message_kind": (
                _QUEUE_MESSAGE_KIND_AUTHORITATIVE
                if authorization_request_id
                else _QUEUE_MESSAGE_KIND_LEGACY
            ),
            "scan_id": scan_id,
            "organization_id": organization_id or "",
            "enqueued_at": enqueued_at,
        }
        if authorization_request_id:
            fields["authorization_request_id"] = authorization_request_id.strip()
        if credential_envelope is not None:
            if not organization_id:
                raise ValueError("credential handoff requires a queue tenant")
            fields["credential_envelope"] = encrypt_credential_envelope(
                credential_envelope,
                scan_id=scan_id,
                organization_id=organization_id,
            )
        if authorization_request_id:
            # The key contains only a one-way digest of the tenant and durable
            # request identity.  The Lua transaction makes the GET/XADD/SET
            # sequence atomic across multiple API processes and workers.
            dedupe_material = f"{organization_id}\x00{authorization_request_id.strip()}".encode("utf-8")
            dedupe_key = f"{self.stream_name}:dedupe:{hashlib.sha256(dedupe_material).hexdigest()}"
            message_id = await self._redis.eval(
                _IDEMPOTENT_ENQUEUE_SCRIPT,
                2,
                dedupe_key,
                self.stream_name,
                scan_id,
                organization_id or "",
                enqueued_at,
                authorization_request_id.strip(),
                fields.get("credential_envelope", ""),
                str(_QUEUE_DEDUPE_TTL_SECONDS),
                queue_binding.queue_binding_digest,
                queue_binding.manifest_hash,
                queue_binding.execution_ids_json,
                queue_binding.operation_ids_json,
                queue_binding.schema_version,
                _QUEUE_MESSAGE_KIND_AUTHORITATIVE,
            )
            if isinstance(message_id, str) and message_id.startswith(_QUEUE_IDENTITY_CONFLICT_PREFIX):
                raise DurableQueueIdentityConflict(message_id)
        else:
            # Preserve the legacy non-scan/diagnostic queue contract for calls
            # that have no authoritative approval identity.  Governed scan
            # dispatches always take the idempotent branch above.
            message_id = await self._redis.xadd(self.stream_name, fields)
        return str(message_id)

    async def complete(self, message_id: str) -> None:
        await self._ensure_group()
        await self._redis.xack(self.stream_name, self.consumer_group, message_id)

    async def fail(
        self,
        message_id: str,
        error_code: str,
        *,
        acknowledge: bool = True,
        scan_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        authorization_request_id: Optional[str] = None,
        queue_binding_digest: Optional[str] = None,
        manifest_hash: Optional[str] = None,
        execution_ids: Optional[Sequence[str]] = None,
        operation_ids: Optional[Sequence[str]] = None,
        message_kind: Optional[str] = None,
        attempt_count: Optional[int] = None,
        max_attempts: Optional[int] = None,
        escalated: bool = False,
        quarantined: bool = False,
    ) -> None:
        """Record sanitized failure evidence and optionally ACK a message.

        Authoritative dispatch callers pass ``acknowledge=False``. The
        message then remains in the consumer group's PEL for bounded reclaim;
        only an explicit quarantine recovery acknowledgement may remove it.
        Legacy diagnostic messages retain the historical ACK behavior.
        """
        await self._ensure_group()
        if not isinstance(message_id, str) or not message_id.strip() or len(message_id) > 256:
            raise ValueError("queue failure message identity is invalid")
        if scan_id is not None and (
            not isinstance(scan_id, str) or not scan_id.strip() or len(scan_id) > 256
        ):
            raise ValueError("queue failure scan identity is invalid")
        if not isinstance(error_code, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", error_code.strip()):
            raise ValueError("queue failure error code is invalid")
        safe_error_code = error_code.strip()
        if attempt_count is not None and (type(attempt_count) is not int or attempt_count < 1):
            raise ValueError("queue failure delivery count is invalid")
        if max_attempts is not None and (type(max_attempts) is not int or max_attempts < 1):
            raise ValueError("queue failure delivery bound is invalid")
        if not isinstance(message_kind, str) or message_kind not in _QUEUE_MESSAGE_KINDS:
            raise ValueError("queue failure message kind is invalid")
        resolved_message_kind = message_kind
        authoritative_fields_present = any(
            value is not None
            for value in (
                authorization_request_id,
                queue_binding_digest,
                manifest_hash,
                execution_ids,
                operation_ids,
            )
        )
        if resolved_message_kind == _QUEUE_MESSAGE_KIND_AUTHORITATIVE:
            if acknowledge:
                raise ValueError("authoritative queue failures must remain pending until explicit recovery")
            if not all(
                value is not None
                for value in (
                    scan_id,
                    organization_id,
                    authorization_request_id,
                    queue_binding_digest,
                    manifest_hash,
                    execution_ids,
                    operation_ids,
                )
            ):
                raise ValueError("authoritative queue failure binding is incomplete")
            QueueDispatchBinding.from_payload({
                "scan_id": scan_id,
                "organization_id": organization_id,
                "authorization_request_id": authorization_request_id,
                "manifest_hash": manifest_hash,
                "execution_ids_json": json.dumps(list(execution_ids), separators=(",", ":"), ensure_ascii=True),
                "operation_ids_json": json.dumps(list(operation_ids), separators=(",", ":"), ensure_ascii=True),
                "queue_binding_digest": queue_binding_digest,
                "queue_binding_schema_version": "queue-dispatch-binding-v1",
            })
        elif resolved_message_kind == _QUEUE_MESSAGE_KIND_LEGACY and authoritative_fields_present:
            raise ValueError("legacy queue failure cannot carry authoritative binding fields")
        elif resolved_message_kind == _QUEUE_MESSAGE_KIND_AMBIGUOUS:
            if not quarantined or acknowledge:
                raise ValueError("ambiguous queue failure must remain quarantined and pending")
        failure_fields: dict[str, str] = {
            "message_id": message_id,
            "dispatch_message_id": message_id,
            "error_code": safe_error_code,
            "failure_category": (
                "AUTHORITATIVE_DISPATCH"
                if resolved_message_kind == _QUEUE_MESSAGE_KIND_AUTHORITATIVE
                else (
                    "AMBIGUOUS_QUEUE_MESSAGE"
                    if resolved_message_kind == _QUEUE_MESSAGE_KIND_AMBIGUOUS
                    else "LEGACY_QUEUE"
                )
            ),
            "failure_observed_at": datetime.now(timezone.utc).isoformat(),
            "requeue_required": "1" if not acknowledge else "0",
            "escalated": "1" if escalated else "0",
            "quarantined": "1" if quarantined else "0",
            "message_kind": resolved_message_kind,
        }
        if scan_id:
            failure_fields["scan_id"] = scan_id
        if organization_id:
            failure_fields["organization_id"] = organization_id
        if authorization_request_id:
            failure_fields["authorization_request_id"] = authorization_request_id
        if queue_binding_digest:
            failure_fields["queue_binding_digest"] = queue_binding_digest
        if manifest_hash:
            failure_fields["manifest_hash"] = manifest_hash
        if execution_ids is not None:
            failure_fields["execution_ids_json"] = json.dumps(
                list(execution_ids), separators=(",", ":"), ensure_ascii=True,
            )
        if operation_ids is not None:
            failure_fields["operation_ids_json"] = json.dumps(
                list(operation_ids), separators=(",", ":"), ensure_ascii=True,
            )
        if {
            "queue_binding_digest",
            "manifest_hash",
            "execution_ids_json",
            "operation_ids_json",
        }.intersection(failure_fields):
            failure_fields["queue_binding_schema_version"] = "queue-dispatch-binding-v1"
        if attempt_count is not None:
            failure_fields["attempt_count"] = str(attempt_count)
        if max_attempts is not None:
            failure_fields["max_attempts"] = str(max_attempts)
        if resolved_message_kind != _QUEUE_MESSAGE_KIND_LEGACY and quarantined:
            await self._quarantine(
                message_id,
                reason=safe_error_code,
                scan_id=scan_id,
                organization_id=organization_id,
                authorization_request_id=authorization_request_id,
                queue_binding_digest=queue_binding_digest,
                manifest_hash=manifest_hash,
                execution_ids=execution_ids,
                operation_ids=operation_ids,
                attempt_count=attempt_count,
                max_attempts=max_attempts,
                failure_fields=failure_fields,
                acknowledge=acknowledge,
            )
            return
        evidence = _canonical_failure_evidence(
            message_id,
            failure_fields,
            require_quarantined=False,
        )
        await self._redis.xadd(f"{self.stream_name}:failures", evidence)
        if acknowledge:
            await self._redis.xack(self.stream_name, self.consumer_group, message_id)

    async def acknowledge_quarantined(
        self,
        message_id: str,
        *,
        operator: QueueQuarantineOperatorAuthorization,
        authorization_request_id: Optional[str] = None,
    ) -> bool:
        """Explicitly acknowledge one quarantined message after review."""
        if not isinstance(message_id, str) or not message_id.strip() or len(message_id) > 256:
            raise ValueError("quarantine acknowledgement identity is invalid")
        if type(operator) is not QueueQuarantineOperatorAuthorization:
            raise ValueError("quarantine acknowledgement requires an authenticated operator assertion")
        if (
            not getattr(operator, "_issued", False)
            or operator.permission != "execution:recovery"
            or not _safe_queue_text(operator.actor_id)
            or not _safe_queue_text(operator.organization_id)
            or not _safe_queue_text(operator.session_binding)
        ):
            raise ValueError("quarantine acknowledgement authorization is invalid")
        await self._ensure_group()
        if not isinstance(authorization_request_id, str) or not authorization_request_id.strip():
            return False
        if operator.organization_id != operator.organization_id.strip():
            return False
        state_key = self._quarantine_state_key(message_id)
        marker_key = self._quarantine_key(message_id)
        raw_state = await self._redis.get(state_key)
        state = await self._get_quarantine_state(message_id)
        state_message_kind = state.get("message_kind") if state else None
        ambiguous_recovery = (
            state_message_kind == _QUEUE_MESSAGE_KIND_AMBIGUOUS
            and state.get("reason") in _QUEUE_AMBIGUOUS_RECOVERY_REASONS
            and not any(
                field_name in state
                for field_name in (
                    "queue_binding_digest",
                    "manifest_hash",
                    "execution_ids",
                    "operation_ids",
                )
            )
        ) if state else False
        acknowledgeable = (
            state_message_kind == _QUEUE_MESSAGE_KIND_AUTHORITATIVE
            or ambiguous_recovery
        )
        if (
            not state
            or raw_state is None
            or state.get("organization_id") != operator.organization_id
            or state.get("authorization_request_id") != authorization_request_id.strip()
            or not acknowledgeable
        ):
            # A legacy/expired marker without durable tenant/request context,
            # or an ambiguous state outside the two reviewed malformed-wire
            # outcomes, cannot be safely acknowledged through recovery.
            return False
        fields: dict[str, str] = {
            "message_id": message_id,
            "dispatch_message_id": message_id,
            "failure_category": "AUTHORITATIVE_DISPATCH_RECOVERY",
            "recovery_action": "ACKNOWLEDGED_AFTER_QUARANTINE",
            "recovery_actor": operator.actor_id,
            "recovery_observed_at": datetime.now(timezone.utc).isoformat(),
            "quarantine_reason": str(state.get("reason", "QUEUE_FAILURE"))[:128],
            "scan_id": str(state.get("scan_id", "")),
            "queue_binding_digest": str(state.get("queue_binding_digest", "")),
            "manifest_hash": str(state.get("manifest_hash", "")),
            "original_failure_evidence_digest": str(state["failure_evidence_digest"]),
        }
        fields["organization_id"] = operator.organization_id
        fields["authorization_request_id"] = authorization_request_id.strip()
        for field_name in ("execution_ids", "operation_ids"):
            values = state.get(field_name)
            if isinstance(values, list):
                fields[f"{field_name}_json"] = json.dumps(
                    values, separators=(",", ":"), ensure_ascii=True,
                )
        for field_name in ("attempt_count", "max_attempts"):
            if type(state.get(field_name)) is int:
                fields[field_name] = str(state[field_name])

        evaluator = getattr(self._redis, "eval", None)
        if not callable(evaluator):
            raise RuntimeError("quarantine acknowledgement compare-and-swap is unavailable")
        arguments: list[str] = [raw_state, self.consumer_group, message_id]
        for field_name, value in fields.items():
            arguments.extend((field_name, value))
        try:
            result = await evaluator(
                _ACK_QUARANTINE_SCRIPT,
                4,
                state_key,
                marker_key,
                f"{self.stream_name}:failures",
                self.stream_name,
                *arguments,
            )
        except Exception as exc:
            raise RuntimeError("quarantine acknowledgement transaction could not be committed") from exc
        if type(result) is not int or result not in {0, 1}:
            raise RuntimeError("quarantine acknowledgement transaction returned an invalid result")
        return result == 1

    async def _quarantine_invalid_wire_message(
        self,
        message_id: str,
        fields: object,
        error_code: str,
    ) -> None:
        """Retain bounded identity evidence without trusting the wire payload."""
        safe_fields = fields if isinstance(fields, dict) else {}

        def safe_value(name: str) -> Optional[str]:
            value = safe_fields.get(name)
            return value if _safe_queue_text(value) else None

        scan_id = safe_value("scan_id")
        organization_id = safe_value("organization_id")
        authorization_request_id = safe_value("authorization_request_id")
        if not authorization_request_id:
            organization_id = None
        attempt_count: Optional[int] = None
        try:
            attempt_count = await self._delivery_attempts(message_id)
        except Exception:
            pass
        await self.fail(
            message_id,
            error_code,
            acknowledge=False,
            scan_id=scan_id,
            organization_id=organization_id,
            authorization_request_id=authorization_request_id,
            attempt_count=attempt_count,
            max_attempts=_QUEUE_MAX_DELIVERY_ATTEMPTS,
            message_kind=_QUEUE_MESSAGE_KIND_AMBIGUOUS,
            escalated=True,
            quarantined=True,
        )

    @staticmethod
    def _validate_wire_message(fields: object) -> tuple[str, str, Optional[str], Optional[str]]:
        if not isinstance(fields, dict):
            raise ValueError("queue message fields are not an object")
        if set(fields).difference(_QUEUE_WIRE_FIELDS):
            raise ValueError("queue message contains unsupported fields")
        if any(not isinstance(key, str) for key in fields):
            raise ValueError("queue message field names are invalid")
        if any(not isinstance(value, str) for value in fields.values()):
            raise ValueError("queue message field values must be strings")
        if not {"message_kind", "scan_id", "organization_id", "enqueued_at"}.issubset(fields):
            raise ValueError("queue message envelope is incomplete")
        message_kind = fields.get("message_kind")
        if message_kind not in {_QUEUE_MESSAGE_KIND_AUTHORITATIVE, _QUEUE_MESSAGE_KIND_LEGACY}:
            raise ValueError("queue message classification is missing or invalid")
        scan_id = fields.get("scan_id", "")
        if not _safe_queue_text(scan_id):
            raise ValueError("execution intent scan identity is invalid")
        organization_id = fields.get("organization_id", "")
        if organization_id and not _safe_queue_text(organization_id):
            raise ValueError("execution intent tenant identity is invalid")
        if not _safe_queue_text(fields["enqueued_at"]):
            raise ValueError("execution intent enqueue timestamp is invalid")
        authorization_request_id = fields.get("authorization_request_id")
        binding_fields = {
            "queue_binding_digest",
            "manifest_hash",
            "execution_ids_json",
            "operation_ids_json",
            "queue_binding_schema_version",
        }
        present_binding = binding_fields.intersection(fields)
        if message_kind == _QUEUE_MESSAGE_KIND_AUTHORITATIVE:
            if not _safe_queue_text(organization_id) or not _safe_queue_text(authorization_request_id):
                raise ValueError("authoritative queue message identity is incomplete")
            if present_binding != binding_fields:
                raise ValueError("authoritative queue message binding is incomplete")
            QueueDispatchBinding.from_payload(fields)
        else:
            if authorization_request_id or present_binding:
                raise ValueError("legacy diagnostic message contains authoritative metadata")
            if "credential_envelope" in fields:
                raise ValueError(
                    "legacy diagnostic message cannot contain credential handoff"
                )
        return message_kind, scan_id, organization_id or None, authorization_request_id

    async def consume_once(
        self,
        handler: Callable[..., Awaitable[None]],
        *,
        block_ms: int = 5000,
        reclaim_idle_ms: int = 60000,
    ) -> bool:
        """Claim one pending/new execution intent and settle it after handling.

        Pending messages are reclaimed before reading new messages so a worker
        that dies mid-scan does not leave the execution intent permanently
        stranded in the consumer group's pending entries list.
        """
        await self._ensure_group()
        messages = []
        claimed = await self._redis.xautoclaim(
            self.stream_name,
            self.consumer_group,
            self._consumer_name,
            min_idle_time=reclaim_idle_ms,
            start_id="0-0",
            count=1,
        )
        if claimed and len(claimed) >= 2:
            messages = claimed[1] or []

        if not messages:
            response = await self._redis.xreadgroup(
                self.consumer_group,
                self._consumer_name,
                {self.stream_name: ">"},
                count=1,
                # Redis interprets BLOCK 0 as an infinite wait.  The
                # consume_once contract uses non-positive values for a
                # non-blocking poll, so omit BLOCK in that case.
                block=block_ms if block_ms > 0 else None,
            )
            if response:
                messages = response[0][1] or []

        if not messages:
            return False

        message_id, fields = messages[0]
        message_id = str(message_id)
        if await self._is_quarantined(message_id):
            # Durable quarantine state is checked before trusting or parsing
            # the wire payload, including malformed/redelivered messages.
            return True
        try:
            message_kind, scan_id, organization_id, authorization_request_id = self._validate_wire_message(fields)
        except Exception as exc:
            await self._quarantine_invalid_wire_message(
                message_id,
                fields,
                "QUEUE_MESSAGE_CLASSIFICATION_REJECTED",
            )
            return True
        authoritative_binding: Optional[QueueDispatchBinding] = None
        delivery_attempts: Optional[int] = None
        if authorization_request_id:
            try:
                authoritative_binding = QueueDispatchBinding.from_payload(fields)
                if (
                    authoritative_binding.scan_id != scan_id
                    or authoritative_binding.organization_id != organization_id
                    or authoritative_binding.authorization_request_id != authorization_request_id
                ):
                    raise ValueError("authoritative queue binding identity does not match the message")
            except Exception:
                await self._quarantine_invalid_wire_message(
                    message_id,
                    fields,
                    "QUEUE_BINDING_REJECTED",
                )
                return True
            try:
                delivery_attempts = await self._delivery_attempts(str(message_id))
            except Exception:
                # Transport inspection is part of the authoritative safety
                # decision. If it is unavailable, quarantine without guessing
                # a delivery count and keep the message pending.
                await self.fail(
                    message_id,
                    "QUEUE_DELIVERY_COUNTER_UNAVAILABLE",
                    acknowledge=False,
                    scan_id=scan_id,
                    organization_id=organization_id,
                    authorization_request_id=authorization_request_id,
                    # The message has not passed complete binding validation,
                    # so it cannot be recorded as authoritative evidence.
                    message_kind=_QUEUE_MESSAGE_KIND_AMBIGUOUS,
                    max_attempts=_QUEUE_MAX_DELIVERY_ATTEMPTS,
                    escalated=True,
                    quarantined=True,
                )
                return True
            if delivery_attempts > _QUEUE_MAX_DELIVERY_ATTEMPTS:
                await self.fail(
                    message_id,
                    "QUEUE_DELIVERY_ATTEMPTS_EXCEEDED",
                    acknowledge=False,
                    scan_id=scan_id,
                    organization_id=organization_id,
                    authorization_request_id=authorization_request_id,
                    message_kind=_QUEUE_MESSAGE_KIND_AUTHORITATIVE,
                    queue_binding_digest=authoritative_binding.queue_binding_digest,
                    manifest_hash=authoritative_binding.manifest_hash,
                    execution_ids=authoritative_binding.execution_ids,
                    operation_ids=authoritative_binding.operation_ids,
                    attempt_count=delivery_attempts,
                    max_attempts=_QUEUE_MAX_DELIVERY_ATTEMPTS,
                    escalated=True,
                    quarantined=True,
                )
                return True
        try:
            if authorization_request_id:
                assert authoritative_binding is not None
            envelope = None
            encrypted_envelope = fields.get("credential_envelope", "")
            if encrypted_envelope:
                if not organization_id:
                    raise ValueError("credential handoff is missing queue tenant")
                envelope = decrypt_credential_envelope(
                    encrypted_envelope,
                    scan_id=scan_id,
                    organization_id=organization_id,
                )
            signature = inspect.signature(handler)
            accepts_five = any(
                parameter.kind == inspect.Parameter.VAR_POSITIONAL
                or parameter.kind == inspect.Parameter.VAR_KEYWORD
                for parameter in signature.parameters.values()
            ) or len(signature.parameters) >= 5
            accepts_four = any(
                parameter.kind == inspect.Parameter.VAR_POSITIONAL
                or parameter.kind == inspect.Parameter.VAR_KEYWORD
                for parameter in signature.parameters.values()
            ) or len(signature.parameters) >= 4
            accepts_three = any(
                parameter.kind == inspect.Parameter.VAR_POSITIONAL
                or parameter.kind == inspect.Parameter.VAR_KEYWORD
                for parameter in signature.parameters.values()
            ) or len(signature.parameters) >= 3
            if authorization_request_id:
                if not accepts_five:
                    raise ValueError("authoritative worker handler must accept the typed queue binding")
                await handler(
                    scan_id,
                    organization_id,
                    authorization_request_id,
                    envelope,
                    authoritative_binding,
                )
            elif message_kind == _QUEUE_MESSAGE_KIND_LEGACY and accepts_four:
                await handler(scan_id, organization_id, authorization_request_id, envelope)
            elif authorization_request_id:
                raise ValueError("worker handler does not accept authoritative scan request identity")
            elif message_kind == _QUEUE_MESSAGE_KIND_LEGACY and accepts_three:
                await handler(scan_id, organization_id, envelope)
            else:
                if envelope is not None:
                    raise ValueError("worker handler does not accept credential handoff")
                await handler(scan_id, organization_id)
        except Exception as exc:
            if authorization_request_id:
                if delivery_attempts is None:
                    # The pre-handler authoritative delivery inspection must
                    # have succeeded; otherwise no safe handler outcome exists.
                    raise
                attempts = delivery_attempts
                escalated = attempts >= _QUEUE_MAX_DELIVERY_ATTEMPTS
                await self.fail(
                    message_id,
                    type(exc).__name__,
                    acknowledge=False,
                    scan_id=scan_id,
                    organization_id=organization_id,
                    authorization_request_id=authorization_request_id,
                    message_kind=message_kind,
                    queue_binding_digest=(
                        authoritative_binding.queue_binding_digest
                        if authoritative_binding is not None else None
                    ),
                    manifest_hash=(
                        authoritative_binding.manifest_hash
                        if authoritative_binding is not None else None
                    ),
                    execution_ids=(
                        authoritative_binding.execution_ids
                        if authoritative_binding is not None else None
                    ),
                    operation_ids=(
                        authoritative_binding.operation_ids
                        if authoritative_binding is not None else None
                    ),
                    attempt_count=attempts,
                    max_attempts=_QUEUE_MAX_DELIVERY_ATTEMPTS,
                    escalated=escalated,
                    quarantined=escalated,
                )
            else:
                # Preserve the legacy diagnostic queue ACK behavior.
                await self.fail(
                    message_id,
                    type(exc).__name__,
                    message_kind=message_kind,
                )
        else:
            await self.complete(message_id)
        return True

    async def close(self) -> None:
        await self._redis.aclose()


class ScanQueueManager:
    """
    Manages concurrent active scan execution with bounded worker concurrency and timeouts.
    """

    _instance: Optional[ScanQueueManager] = None

    def __init__(self, max_concurrent: int = MAX_CONCURRENT_SCANS, max_concurrent_per_tenant: int = MAX_CONCURRENT_SCANS_PER_TENANT, durable_backend: Optional[DurableQueueBackend] = None):
        self._max_concurrent = max_concurrent
        self._max_concurrent_per_tenant = max_concurrent_per_tenant
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._tenant_semaphores: Dict[str, asyncio.Semaphore] = {}
        self._tenant_lock = asyncio.Lock()
        self._active_count = 0
        self._durable_backend = durable_backend

    @classmethod
    def get_instance(cls) -> ScanQueueManager:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def active_scans_count(self) -> int:
        return self._active_count

    @property
    def max_concurrent(self) -> int:
        return self._max_concurrent

    @property
    def max_concurrent_per_tenant(self) -> int:
        return self._max_concurrent_per_tenant

    @property
    def durable_enabled(self) -> bool:
        return self._durable_backend is not None

    async def enqueue_only(
        self,
        scan_id: str,
        organization_id: Optional[str],
        credential_envelope: Optional[CloudCredentialEnvelope] = None,
        authorization_request_id: Optional[str] = None,
        *,
        queue_binding: Optional[QueueDispatchBinding] = None,
    ) -> str:
        """Persist an enterprise execution intent without running it locally."""
        if self._durable_backend is None:
            raise RuntimeError("enqueue_only requires a durable execution backend")
        if authorization_request_id is None and queue_binding is not None:
            raise ValueError("a queue binding requires an authoritative authorization request")
        if credential_envelope is not None and authorization_request_id is None:
            raise ValueError(
                "credential handoff requires an authoritative authorization request and typed queue binding"
            )
        if credential_envelope is None and authorization_request_id is None:
            return await self._durable_backend.enqueue(scan_id, organization_id)
        return await self._durable_backend.enqueue(
            scan_id,
            organization_id,
            credential_envelope,
            authorization_request_id,
            queue_binding=queue_binding,
        )

    async def _tenant_semaphore(self, organization_id: Optional[str]) -> Optional[asyncio.Semaphore]:
        if not organization_id:
            return None
        async with self._tenant_lock:
            return self._tenant_semaphores.setdefault(
                organization_id,
                asyncio.Semaphore(self._max_concurrent_per_tenant),
            )

    async def execute_bounded(
        self,
        scan_id: str,
        task_fn: Callable[..., Awaitable[Any]],
        *args,
        timeout_seconds: float = GLOBAL_SCAN_TIMEOUT_SECONDS,
        organization_id: Optional[str] = None,
        authorization_request_id: Optional[str] = None,
        queue_binding: Optional[QueueDispatchBinding] = None,
        **kwargs,
    ) -> Any:
        """
        Executes a scan job task within the concurrency semaphore and execution timeout boundary.
        """
        tenant_semaphore = await self._tenant_semaphore(organization_id)
        message_id = None
        if self._durable_backend is not None:
            if authorization_request_id is None:
                if queue_binding is not None:
                    raise ValueError("a queue binding requires an authoritative authorization request")
                message_id = await self._durable_backend.enqueue(scan_id, organization_id)
            else:
                if queue_binding is None:
                    raise ValueError("authoritative durable execution requires a typed queue binding")
                message_id = await self._durable_backend.enqueue(
                    scan_id,
                    organization_id,
                    None,
                    authorization_request_id,
                    queue_binding=queue_binding,
                )
        try:
            async with self._semaphore:
                if tenant_semaphore is None:
                    result = await self._execute_with_accounting(task_fn, args, kwargs, timeout_seconds)
                else:
                    async with tenant_semaphore:
                        result = await self._execute_with_accounting(task_fn, args, kwargs, timeout_seconds)
            if message_id is not None:
                await self._durable_backend.complete(message_id)
            return result
        except Exception as exc:
            if message_id is not None:
                if authorization_request_id:
                    await self._durable_backend.fail(
                        message_id,
                        type(exc).__name__,
                        acknowledge=False,
                        scan_id=scan_id,
                        organization_id=organization_id,
                        authorization_request_id=authorization_request_id,
                        queue_binding_digest=(
                            queue_binding.queue_binding_digest
                            if queue_binding is not None else None
                        ),
                        manifest_hash=queue_binding.manifest_hash if queue_binding else None,
                        execution_ids=queue_binding.execution_ids if queue_binding else None,
                        operation_ids=queue_binding.operation_ids if queue_binding else None,
                        attempt_count=1,
                        max_attempts=_QUEUE_MAX_DELIVERY_ATTEMPTS,
                    )
                else:
                    # Preserve the legacy diagnostic queue ACK behavior.
                    await self._durable_backend.fail(
                        message_id,
                        type(exc).__name__,
                        message_kind=_QUEUE_MESSAGE_KIND_LEGACY,
                    )
            raise

    async def _execute_with_accounting(self, task_fn, args, kwargs, timeout_seconds):
        self._active_count += 1
        try:
            return await asyncio.wait_for(task_fn(*args, **kwargs), timeout=timeout_seconds)
        finally:
            self._active_count = max(0, self._active_count - 1)


if EXECUTION_QUEUE_URL and not EXECUTION_QUEUE_URL.lower().startswith("redis://"):
    raise RuntimeError("EXECUTION_QUEUE_URL must use redis:// for the enterprise queue backend")

queue_manager = ScanQueueManager(
    durable_backend=RedisDurableQueue(EXECUTION_QUEUE_URL) if EXECUTION_QUEUE_URL else None
)
