"""Typed authority contexts for governed and non-scan process launches."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import base64
import hashlib
import hmac
import json
import re
import uuid
from collections.abc import Mapping
from typing import Any, Dict, Optional, Tuple, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)


class ExecutionContextError(ValueError):
    """Base error for invalid launch-context use."""


class MissingExecutionContextError(ExecutionContextError):
    pass


class ExecutionContextMismatchError(ExecutionContextError):
    pass


class ExecutionContextExpiredError(ExecutionContextError):
    pass


class ExecutionContextTenantError(ExecutionContextError):
    pass


class ExecutionContextCommandError(ExecutionContextError):
    pass


class UnsupportedNonScanContextError(ExecutionContextError):
    pass


# Runtime-issued contexts are registered by identity outside the serializable
# Pydantic payload.  This prevents a caller from reconstructing a payload and
# making it authoritative by changing a private model attribute.  The bounded
# registry is process-local by design; durable authorization remains in the
# database and is revalidated at launch.
_ISSUED_CONTEXTS: Dict[int, object] = {}
_ISSUER_TOKEN = object()


def _register_issued_context(context: object) -> None:
    if len(_ISSUED_CONTEXTS) >= 4096:
        for context_id, candidate in list(_ISSUED_CONTEXTS.items()):
            expiry = getattr(candidate, "expires_at", None)
            if expiry is not None and expiry <= datetime.now(timezone.utc):
                _ISSUED_CONTEXTS.pop(context_id, None)
        if len(_ISSUED_CONTEXTS) >= 4096:
            raise UnsupportedNonScanContextError("execution context issuer registry is at capacity")
    _ISSUED_CONTEXTS[id(context)] = context


def _is_registered_context(context: object) -> bool:
    """Return whether this exact in-memory object was issued by this process."""
    return _ISSUED_CONTEXTS.get(id(context)) is context


def _reject_duplicate_json_keys(pairs):
    values = {}
    for key, value in pairs:
        if key in values:
            raise ValueError("attestation JSON contains a duplicate field")
        values[key] = value
    return values


def _reject_nonfinite_json(value):
    raise ValueError(f"attestation JSON contains unsupported constant {value!r}")


def _load_strict_attestation_json(json_data: str | bytes | bytearray) -> dict[str, Any]:
    if not isinstance(json_data, (str, bytes, bytearray)):
        raise TypeError("attestation JSON must be text or bytes")
    try:
        payload = json.loads(
            json_data,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("attestation JSON is invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError("attestation JSON root must be an object")
    return payload


def _canonical_attestation_timestamp(value: Any) -> datetime:
    """Require one UTC ISO-8601 representation instead of accepting coercions."""
    if type(value) is datetime:
        parsed = value
    elif type(value) is str:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("attestation timestamp is not valid ISO-8601") from exc
    else:
        raise TypeError("attestation timestamp must be a datetime or canonical string")

    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("attestation timestamps must use UTC")
    normalized = parsed.astimezone(timezone.utc)
    canonical_text = normalized.isoformat().replace("+00:00", "Z")
    if type(value) is str and value != canonical_text:
        raise ValueError("attestation timestamp is not in canonical UTC form")
    return normalized


class _StrictAttestationModel(BaseModel):
    """Base codec for identity proofs; JSON parsing must preserve field types."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        extra: str | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ):
        # Identity proofs never permit a caller to opt into coercive parsing or
        # an alternate extra-field policy.  The raw object is parsed first so
        # duplicate fields cannot be normalized by a last-value-wins decoder.
        if strict is False or (extra is not None and extra != "forbid"):
            raise TypeError("identity attestation parsing is always strict and extra-forbidden")
        payload = _load_strict_attestation_json(json_data)
        # JSON has no tuple type.  The versioned wire representation uses an
        # ordered array for tuple-backed identity collections; convert only
        # those explicitly documented fields after raw JSON type validation.
        for field in ("initial_members", "member_snapshot"):
            if isinstance(payload.get(field), list):
                payload[field] = tuple(payload[field])
        return cls.model_validate(
            payload,
            strict=True,
            extra="forbid",
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )


class PosixProcessMemberAttestation(_StrictAttestationModel):
    """One bounded, start-token-bound member of a governed POSIX session."""

    pid: StrictInt = Field(ge=2)
    process_group_id: StrictInt = Field(ge=2)
    session_id: StrictInt = Field(ge=0)
    start_token: StrictStr = Field(min_length=10, max_length=256)


class PosixProcessAttestation(_StrictAttestationModel):
    """Canonical, bounded POSIX identity proof; a PID alone is never authority."""

    schema_version: Literal["posix-process-attestation-v1"]
    proof_type: Literal["PROC_START_TICKS_SESSION_GROUP"]
    boot_id: StrictStr
    root_start_ticks: StrictInt = Field(ge=0)
    session_id: StrictInt = Field(ge=0)
    process_group_id: StrictInt = Field(ge=0)
    pidfd_supported: StrictBool
    pidfd_verified: StrictBool
    worker_generation: StrictStr
    captured_at: datetime
    expires_at: datetime
    verification_result: Literal["VERIFIED", "UNVERIFIED", "FAILED"]
    # Older durable records may not contain a snapshot.  They remain valid for
    # live-root checks but cannot authorize recovery after the root disappears.
    member_snapshot: Optional[Tuple[PosixProcessMemberAttestation, ...]] = None
    digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("captured_at", "expires_at", mode="before")
    @classmethod
    def _canonical_timestamps(cls, value: Any) -> datetime:
        return _canonical_attestation_timestamp(value)

    @model_validator(mode="after")
    def _valid_window(self) -> "PosixProcessAttestation":
        if self.captured_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ExecutionContextExpiredError("process attestation timestamps must be timezone-aware")
        if self.expires_at <= self.captured_at:
            raise ExecutionContextExpiredError("process attestation expiry must follow capture")
        if self.pidfd_verified and not self.pidfd_supported:
            raise ValueError("pidfd verification cannot be asserted when unsupported")
        if self.member_snapshot is not None and not self.member_snapshot:
            raise ValueError("POSIX member snapshot cannot be empty when present")
        if self.digest != canonical_binding_digest(
            self.model_dump(exclude={"digest"}, exclude_none=True)
        ):
            raise ValueError("POSIX process attestation digest does not match canonical fields")
        return self


class WindowsJobAttestation(_StrictAttestationModel):
    """Durable binding; kernel verification is separately required at use."""

    schema_version: Literal["windows-job-attestation-v1"]
    proof_type: Literal["JOB_OBJECT"]
    job_identity: StrictStr = Field(pattern=r"^Local\\CyberAssess-[0-9a-f]{64}$")
    job_nonce: StrictStr = Field(pattern=r"^[0-9a-f]{32}$")
    execution_id: StrictStr = Field(min_length=1, max_length=256)
    organization_id: StrictStr = Field(min_length=1, max_length=256)
    worker_identity: StrictStr = Field(min_length=1, max_length=256)
    root_process_id: StrictInt = Field(ge=2)
    root_process_start_token: StrictStr = Field(pattern=r"^windows:[1-9][0-9]*$")
    worker_generation: StrictStr = Field(min_length=1, max_length=256)
    initial_members: Tuple[StrictInt, ...]
    captured_at: datetime
    expires_at: datetime
    verification_result: Literal["VERIFIED", "UNVERIFIED", "FAILED"]
    digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("captured_at", "expires_at", mode="before")
    @classmethod
    def _canonical_timestamps(cls, value: Any) -> datetime:
        return _canonical_attestation_timestamp(value)

    @model_validator(mode="after")
    def _valid_window(self) -> "WindowsJobAttestation":
        if self.captured_at.tzinfo is None or self.expires_at.tzinfo is None or self.expires_at <= self.captured_at:
            raise ExecutionContextExpiredError("Windows job attestation window is invalid")
        if self.initial_members != (self.root_process_id,):
            raise ValueError("Windows launch must attest exactly the suspended root")
        if self.job_identity != windows_job_name(
            self.execution_id,
            self.organization_id,
            self.worker_identity,
            self.worker_generation,
            self.job_nonce,
        ):
            raise ValueError("Windows job name is not bound to the execution authority")
        if self.digest != canonical_windows_job_attestation_digest(self.model_dump(exclude={"digest"})):
            raise ValueError("Windows job attestation digest does not match canonical fields")
        return self


class WindowsNonScanJobAttestation(_StrictAttestationModel):
    """Typed Job Object proof for installer/observation launches only.

    This proof is intentionally not accepted by the durable scan ownership
    validators.  It proves containment for a non-scan capability without
    creating an execution or tenant authorization claim.
    """

    schema_version: Literal["windows-non-scan-job-attestation-v1"]
    proof_type: Literal["JOB_OBJECT"]
    job_identity: StrictStr = Field(pattern=r"^Local\\CyberAssess-[0-9a-f]{64}$")
    job_nonce: StrictStr = Field(pattern=r"^[0-9a-f]{32}$")
    purpose: StrictStr = Field(min_length=1, max_length=160)
    worker_identity: StrictStr = Field(min_length=1, max_length=256)
    worker_generation: StrictStr = Field(min_length=1, max_length=256)
    root_process_id: StrictInt = Field(ge=2)
    root_process_start_token: StrictStr = Field(pattern=r"^windows:[1-9][0-9]*$")
    initial_members: Tuple[StrictInt, ...]
    captured_at: datetime
    expires_at: datetime
    verification_result: Literal["VERIFIED", "UNVERIFIED", "FAILED"]
    digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("captured_at", "expires_at", mode="before")
    @classmethod
    def _canonical_timestamps(cls, value: Any) -> datetime:
        return _canonical_attestation_timestamp(value)

    @model_validator(mode="after")
    def _valid_window(self) -> "WindowsNonScanJobAttestation":
        if self.expires_at <= self.captured_at:
            raise ExecutionContextExpiredError("Windows non-scan job attestation window is invalid")
        if not (self.purpose.startswith("installer:") or self.purpose.startswith("observation:")):
            raise UnsupportedNonScanContextError("Windows non-scan job purpose is outside the approved registry")
        if self.initial_members != (self.root_process_id,):
            raise ValueError("Windows launch must attest exactly the suspended root")
        if self.job_identity != windows_non_scan_job_name(
            self.purpose,
            self.worker_identity,
            self.worker_generation,
            self.job_nonce,
        ):
            raise ValueError("Windows non-scan job name is not bound to its capability")
        if self.digest != canonical_windows_non_scan_job_attestation_digest(
            self.model_dump(exclude={"digest"})
        ):
            raise ValueError("Windows non-scan job attestation digest does not match canonical fields")
        return self


def parse_windows_attestation_json(
    json_data: str | bytes | bytearray,
) -> WindowsJobAttestation | WindowsNonScanJobAttestation:
    """Parse one of the two explicit Windows proof types without coercion."""
    payload = _load_strict_attestation_json(json_data)
    for field in ("initial_members", "member_snapshot"):
        if isinstance(payload.get(field), list):
            payload[field] = tuple(payload[field])
    model = {
        "windows-job-attestation-v1": WindowsJobAttestation,
        "windows-non-scan-job-attestation-v1": WindowsNonScanJobAttestation,
    }.get(payload.get("schema_version"))
    if model is None:
        raise ValueError("unknown Windows attestation schema")
    return model.model_validate(payload, strict=True, extra="forbid")


def windows_job_name(
    execution_id: str,
    organization_id: str,
    worker_identity: str,
    worker_generation: str,
    nonce: str,
) -> str:
    """Create the opaque named-kernel-object identity for one execution."""
    return "Local\\CyberAssess-" + canonical_binding_digest({
        "execution_id": execution_id,
        "organization_id": organization_id,
        "worker_identity": worker_identity,
        "worker_generation": worker_generation,
        "nonce": nonce,
    })


def windows_non_scan_job_name(
    purpose: str,
    worker_identity: str,
    worker_generation: str,
    nonce: str,
) -> str:
    """Create an opaque Job Object name for a non-scan capability."""
    return "Local\\CyberAssess-" + canonical_binding_digest({
        "purpose": purpose,
        "worker_identity": worker_identity,
        "worker_generation": worker_generation,
        "nonce": nonce,
    })


_WINDOWS_JOB_ATTESTATION_FIELDS = (
    "schema_version", "proof_type", "job_identity", "job_nonce", "execution_id",
    "organization_id", "worker_identity", "root_process_id", "root_process_start_token",
    "worker_generation", "initial_members", "captured_at", "expires_at", "verification_result",
)
_WINDOWS_NON_SCAN_ATTESTATION_FIELDS = (
    "schema_version", "proof_type", "job_identity", "job_nonce", "purpose",
    "worker_identity", "worker_generation", "root_process_id", "root_process_start_token",
    "initial_members", "captured_at", "expires_at", "verification_result",
)


def _canonical_windows_attestation_payload(
    value: Mapping[str, Any],
    fields: tuple[str, ...],
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise ValueError("Windows attestation fields do not match the versioned schema")
    normalized: dict[str, Any] = {}
    for field in fields:
        item = value[field]
        if field in {"captured_at", "expires_at"}:
            normalized[field] = _canonical_attestation_timestamp(item).isoformat().replace("+00:00", "Z")
        elif field == "initial_members":
            if (
                not isinstance(item, (tuple, list))
                or not item
                or len(item) > 512
                or any(type(member) is not int or member < 2 for member in item)
            ):
                raise ValueError("Windows attestation member collection is invalid")
            # JSON has no tuple type; the documented canonical representation
            # is an ordered array, so changing member order changes the digest.
            normalized[field] = list(item)
        elif field == "root_process_id":
            if type(item) is not int or item < 2:
                raise ValueError("Windows attestation root PID is invalid")
            normalized[field] = item
        else:
            if type(item) is not str:
                raise TypeError(f"Windows attestation field {field} must be a string")
            normalized[field] = item
    return normalized


def _canonical_windows_attestation_digest(value: Mapping[str, Any], fields: tuple[str, ...]) -> str:
    payload = _canonical_windows_attestation_payload(value, fields)
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def canonical_windows_job_attestation_digest(value: Mapping[str, Any]) -> str:
    """Digest the exact documented governed Windows attestation payload."""
    return _canonical_windows_attestation_digest(value, _WINDOWS_JOB_ATTESTATION_FIELDS)


def canonical_windows_non_scan_job_attestation_digest(value: Mapping[str, Any]) -> str:
    """Digest the exact documented non-scan Windows attestation payload."""
    return _canonical_windows_attestation_digest(value, _WINDOWS_NON_SCAN_ATTESTATION_FIELDS)


def validate_windows_ownership(ownership, *, worker_identity=None, historical=False):
    """Validate the complete durable binding without mistaking a digest for OS proof."""
    row = dict(ownership)
    attestation = WindowsJobAttestation.model_validate_json(row["identity_attestation"])
    if (
        row.get("container_type") != "WINDOWS_JOB"
        or row.get("process_group_id") is not None
        or row.get("session_id") is not None
        or attestation.verification_result != "VERIFIED"
        or attestation.job_identity != row.get("container_identity")
        or attestation.execution_id != row.get("execution_id")
        or attestation.organization_id != row.get("organization_id")
        or attestation.root_process_id != row.get("root_process_id")
        or attestation.root_process_start_token != row.get("root_process_start_token")
        or attestation.worker_generation != row.get("worker_generation")
        or (worker_identity is not None and attestation.worker_identity != worker_identity)
    ):
        raise ExecutionContextMismatchError("Windows job ownership binding mismatch")
    now = datetime.now(timezone.utc)
    if attestation.captured_at > now or (not historical and attestation.expires_at <= now):
        raise ExecutionContextExpiredError("Windows job attestation is not current")
    return attestation


def canonical_command_digest(command: Tuple[str, ...]) -> str:
    if not command or any(not isinstance(item, str) or not item for item in command):
        raise ExecutionContextCommandError("exact command vector is required")
    return hashlib.sha256(
        json.dumps(list(command), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _freeze_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, dict):
        if any(not isinstance(key, str) or not key.strip() for key in value):
            raise ExecutionContextCommandError("binding-map keys must be nonblank strings")
        return tuple((key, _freeze_value(value[key])) for key in sorted(value))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise ExecutionContextCommandError("binding-map contains unsupported value")


def canonical_binding_digest(value: Any) -> str:
    frozen = _freeze_value(value)
    return hashlib.sha256(json.dumps(frozen, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


_EXECUTION_PROOF_SCHEMA_VERSION = "execution-proof-v2"
_EXECUTION_PROOF_TYPES = frozenset({"NO_EXTERNAL_PROCESS", "TERMINATION_CONFIRMED"})
_EXECUTION_PROOF_MAX_LENGTH = 16_384
_EXECUTION_PROOF_RE = re.compile(
    r"^(NO_EXTERNAL_PROCESS|TERMINATION_CONFIRMED):v2:([0-9a-f]{64}):([A-Za-z0-9_-]+)$"
)

# These key sets define the versioned durable proof contract.  The codec below
# validates the envelope and canonical digest; the database and authority
# layers additionally require one of these exact payload shapes before a proof
# can affect lifecycle handling.
EXECUTION_PROOF_COMMON_KEYS = frozenset({
    "schema_version", "proof_type", "execution_id", "organization_id",
    "request_id", "decision_id", "terminal_state", "dispatch_state",
    "ownership_state", "container_type", "launch_commit_state",
    "worker_identity", "worker_generation", "correlation_id",
    "claim_identity_digest", "dispatch_identity_digest", "reason_code",
    "observed_at", "recovery_status", "recovery_attempt_number",
    "recovery_attempt_id",
})
EXECUTION_PROOF_NO_PROCESS_KEYS = EXECUTION_PROOF_COMMON_KEYS | {"proof_code"}
EXECUTION_PROOF_TERMINATION_KEYS = EXECUTION_PROOF_COMMON_KEYS | {
    "termination_status", "process_id", "process_group_id",
    "process_start_token", "session_id", "identity_attestation",
    "identity_attestation_digest",
}


def execution_claim_digest(token: str) -> str:
    """Return a non-secret fingerprint for one ephemeral execution claim."""
    if not isinstance(token, str) or not token.strip() or len(token) > 512:
        raise ExecutionContextMismatchError("execution claim token is invalid")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _canonical_execution_proof_bytes(payload: Dict[str, Any]) -> bytes:
    if not isinstance(payload, dict):
        raise ExecutionContextMismatchError("execution proof payload must be an object")
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ExecutionContextMismatchError("execution proof payload is not canonical JSON") from exc


def encode_execution_proof(proof_type: str, payload: Dict[str, Any]) -> str:
    """Encode one self-contained, digest-bound terminal execution proof.

    The payload is intentionally stored in the existing ownership proof TEXT
    column.  It contains no live claim token; ephemeral claims are represented
    only by one-way digests.  The strict envelope makes altered payloads,
    unsupported versions, and alternate JSON encodings fail closed.
    """
    if proof_type not in _EXECUTION_PROOF_TYPES:
        raise ExecutionContextMismatchError("execution proof type is unsupported")
    if not isinstance(payload, dict):
        raise ExecutionContextMismatchError("execution proof payload must be an object")
    if payload.get("schema_version") != _EXECUTION_PROOF_SCHEMA_VERSION:
        raise ExecutionContextMismatchError("execution proof schema version is unsupported")
    if payload.get("proof_type") != proof_type:
        raise ExecutionContextMismatchError("execution proof type does not match its payload")
    canonical = _canonical_execution_proof_bytes(payload)
    encoded_payload = base64.urlsafe_b64encode(canonical).decode("ascii").rstrip("=")
    digest = hashlib.sha256(canonical).hexdigest()
    proof = f"{proof_type}:v2:{digest}:{encoded_payload}"
    if len(proof) > _EXECUTION_PROOF_MAX_LENGTH:
        raise ExecutionContextMismatchError("execution proof exceeds the bounded storage limit")
    return proof


def decode_execution_proof(
    proof: str,
    *,
    expected_proof_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Strictly decode and verify one terminal execution proof envelope."""
    if not isinstance(proof, str) or len(proof) > _EXECUTION_PROOF_MAX_LENGTH:
        raise ExecutionContextMismatchError("execution proof is missing or oversized")
    match = _EXECUTION_PROOF_RE.fullmatch(proof)
    if match is None:
        raise ExecutionContextMismatchError("execution proof grammar or version is invalid")
    proof_type, supplied_digest, encoded_payload = match.groups()
    if expected_proof_type is not None and proof_type != expected_proof_type:
        raise ExecutionContextMismatchError("execution proof type is not the expected terminal proof")
    padding = "=" * ((4 - len(encoded_payload) % 4) % 4)
    try:
        canonical = base64.b64decode(
            (encoded_payload + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
        if base64.urlsafe_b64encode(canonical).decode("ascii").rstrip("=") != encoded_payload:
            raise ValueError("noncanonical base64")
        payload = json.loads(
            canonical.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_pairs,
        )
    except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ExecutionContextMismatchError("execution proof payload encoding is invalid") from exc
    if not isinstance(payload, dict):
        raise ExecutionContextMismatchError("execution proof payload is not an object")
    if _canonical_execution_proof_bytes(payload) != canonical:
        raise ExecutionContextMismatchError("execution proof payload is not canonically encoded")
    expected_digest = hashlib.sha256(canonical).hexdigest()
    if not hmac.compare_digest(supplied_digest, expected_digest):
        raise ExecutionContextMismatchError("execution proof digest does not match its payload")
    if payload.get("schema_version") != _EXECUTION_PROOF_SCHEMA_VERSION:
        raise ExecutionContextMismatchError("execution proof payload version is unsupported")
    if payload.get("proof_type") != proof_type:
        raise ExecutionContextMismatchError("execution proof payload type is inconsistent")
    return payload


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate execution proof payload key")
        result[key] = value
    return result


class GovernedExecutionContext(BaseModel):
    """Verifier-issued immutable context for one exact authorized launch."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    execution_id: str
    request_id: str
    organization_id: str
    project_id: Optional[str] = None
    asset_id: str
    target_id: str
    target_integrity_seal: str
    authorization_decision_id: str
    request_fingerprint: str
    target_policy_version: str
    operation_policy_revision: str
    tool_id: str
    operation_family: str
    operation_options: Tuple[Tuple[str, Any], ...] = Field(default_factory=tuple)
    resource_budget: Tuple[Tuple[str, int], ...] = Field(default_factory=tuple)
    account_impact_budget: Tuple[Tuple[str, int], ...] = Field(default_factory=tuple)
    credential_scope: Tuple[Tuple[str, str], ...] = Field(default_factory=tuple)
    operation_options_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    resource_budget_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    account_impact_budget_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    credential_scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    revocation_check_reference: str
    worker_identity: str
    worker_generation: str
    session_jti: str
    expires_at: datetime
    correlation_id: str
    exact_command: Tuple[str, ...]
    command_digest: str
    authority_token: str = Field(repr=False)

    @field_validator(
        "execution_id", "request_id", "organization_id", "asset_id", "target_id",
        "authorization_decision_id", "request_fingerprint", "target_integrity_seal", "target_policy_version",
        "operation_policy_revision", "tool_id", "operation_family", "worker_identity",
        "worker_generation", "session_jti", "correlation_id", "authority_token",
        mode="before",
    )
    @classmethod
    def _require_nonblank(cls, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise MissingExecutionContextError("required execution-context field is blank or missing")
        return value.strip()

    @field_validator("expires_at")
    @classmethod
    def _require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ExecutionContextExpiredError("execution context expiry must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _validate_command_binding(self) -> "GovernedExecutionContext":
        expected = canonical_command_digest(tuple(self.exact_command))
        if self.command_digest != expected:
            raise ExecutionContextCommandError("command digest does not match exact command vector")
        if self.operation_options_digest != canonical_binding_digest(self.operation_options):
            raise ExecutionContextCommandError("operation options digest does not match immutable binding")
        if self.resource_budget_digest != canonical_binding_digest(self.resource_budget):
            raise ExecutionContextCommandError("resource budget digest does not match immutable binding")
        if self.account_impact_budget_digest != canonical_binding_digest(self.account_impact_budget):
            raise ExecutionContextCommandError("account impact digest does not match immutable binding")
        if self.credential_scope_digest != canonical_binding_digest(self.credential_scope):
            raise ExecutionContextCommandError("credential scope digest does not match immutable binding")
        if self.expires_at <= datetime.now(timezone.utc):
            raise ExecutionContextExpiredError("execution context is expired")
        return self

    def assert_issued(self) -> None:
        if _ISSUED_CONTEXTS.get(id(self)) is not self:
            raise MissingExecutionContextError("execution context was not issued by the authority verifier")

    def assert_live(self, now: Optional[datetime] = None) -> None:
        self.assert_issued()
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if self.expires_at <= current:
            raise ExecutionContextExpiredError("execution context is expired")

    def assert_launch(self, *, execution_id: str, organization_id: str, command: list[str]) -> None:
        self.assert_live()
        if execution_id != self.execution_id or organization_id != self.organization_id:
            raise ExecutionContextMismatchError("launch identity does not match execution context")
        if canonical_command_digest(tuple(command)) != self.command_digest:
            raise ExecutionContextCommandError("launch command does not match execution context")

    def assert_bound_to_capability(self, capability: Any) -> None:
        """Compare the complete typed context/capability authority boundary."""
        self.assert_issued()
        decision = getattr(capability, "decision", None)
        if decision is None or getattr(capability, "execution_id", None) != self.execution_id:
            raise ExecutionContextMismatchError("execution context is not bound to the capability")
        if any((
            self.organization_id != decision.organization_id,
            self.project_id != decision.project_id,
            self.asset_id != decision.asset_id,
            self.target_integrity_seal != getattr(capability.target, "integrity_seal", None),
            self.authorization_decision_id != decision.authorization_decision_id,
            self.target_policy_version != decision.target_policy_version,
            self.tool_id != capability.tool_id,
            self.operation_family != capability.operation_family,
            self.operation_options_digest != canonical_binding_digest(decision.operation_options),
            self.resource_budget_digest != canonical_binding_digest(decision.resource_budget),
            self.account_impact_budget_digest != canonical_binding_digest(decision.account_impact_budget),
            self.credential_scope_digest != canonical_binding_digest(decision.credential_scope),
            self.operation_policy_revision != decision.operation_policy_revision,
            self.worker_identity != capability.worker_identity,
            self.worker_generation != getattr(capability, "worker_generation", None),
            self.session_jti != decision.session_jti,
            self.authority_token != getattr(capability, "dispatch_claim_token", None),
            self.revocation_check_reference != f"session-jti:{decision.session_jti}",
        )):
            raise ExecutionContextMismatchError("execution context binding does not match durable capability")


class NonScanExecutionContext(BaseModel):
    """Explicit installer/observation capability that cannot authorize a scan."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    purpose: str
    worker_identity: str
    worker_generation: str
    expires_at: datetime
    capability_token: str = Field(repr=False)
    @classmethod
    def _from_verified_values(cls, issuer: object, **values: Any) -> "NonScanExecutionContext":
        if issuer is not _ISSUER_TOKEN:
            raise UnsupportedNonScanContextError("non-scan capability issuer is not authoritative")
        context = cls(**values)
        _register_issued_context(context)
        return context

    @model_validator(mode="after")
    def _validate(self) -> "NonScanExecutionContext":
        if not self.purpose.strip() or not self.worker_identity.strip() or not self.worker_generation.strip():
            raise MissingExecutionContextError("non-scan capability fields are incomplete")
        if self.expires_at.tzinfo is None or self.expires_at <= datetime.now(timezone.utc):
            raise ExecutionContextExpiredError("non-scan capability is expired or timezone-naive")
        return self

    def assert_issued(self) -> None:
        if _ISSUED_CONTEXTS.get(id(self)) is not self:
            raise UnsupportedNonScanContextError("non-scan capability was not issued by the verifier")

    def assert_live(self, now: Optional[datetime] = None) -> None:
        self.assert_issued()
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if self.expires_at <= current:
            raise ExecutionContextExpiredError("non-scan capability is expired")


__all__ = [
    "ExecutionContextError", "MissingExecutionContextError", "ExecutionContextMismatchError",
    "ExecutionContextExpiredError", "ExecutionContextTenantError", "ExecutionContextCommandError",
    "UnsupportedNonScanContextError", "GovernedExecutionContext", "NonScanExecutionContext",
    "PosixProcessMemberAttestation", "PosixProcessAttestation", "WindowsJobAttestation",
    "WindowsNonScanJobAttestation",
    "canonical_command_digest",
    "canonical_binding_digest",
    "canonical_windows_job_attestation_digest",
    "canonical_windows_non_scan_job_attestation_digest",
    "windows_job_name", "windows_non_scan_job_name", "parse_windows_attestation_json",
    "execution_claim_digest",
    "EXECUTION_PROOF_COMMON_KEYS",
    "EXECUTION_PROOF_NO_PROCESS_KEYS",
    "EXECUTION_PROOF_TERMINATION_KEYS",
    "encode_execution_proof",
    "decode_execution_proof",
    "PosixProcessAttestation", "WindowsJobAttestation", "WindowsNonScanJobAttestation",
    "_issue_non_scan_execution_context",
    "_register_issued_context",
    "_is_registered_context",
]

# Resolve postponed self-references explicitly so the models also work when
# loaded by migration/test tooling outside the normal package importer.
GovernedExecutionContext.model_rebuild()
NonScanExecutionContext.model_rebuild()


def _issue_non_scan_execution_context(
    purpose: str,
    *,
    ttl_seconds: int = 300,
    issuer: object,
    worker_identity: str,
    worker_generation: str,
) -> NonScanExecutionContext:
    """Issue a capability only for the service-owned installation boundary."""
    if (
        not isinstance(purpose, str)
        or not purpose.strip()
        or not (purpose.startswith("installer:") or purpose.startswith("observation:"))
        or len(purpose) > 160
        or not isinstance(ttl_seconds, int)
        or not 1 <= ttl_seconds <= 900
    ):
        raise UnsupportedNonScanContextError("non-scan capability purpose or lifetime is outside the approved registry")
    if issuer is not _ISSUER_TOKEN:
        raise UnsupportedNonScanContextError("non-scan capability issuance is service-owned")
    now = datetime.now(timezone.utc)
    return NonScanExecutionContext._from_verified_values(
        _ISSUER_TOKEN, purpose=purpose, worker_identity=worker_identity,
        worker_generation=worker_generation,
        expires_at=now + timedelta(seconds=ttl_seconds), capability_token=f"non-scan-{uuid.uuid4().hex}",
    )
