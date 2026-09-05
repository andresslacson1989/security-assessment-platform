"""Typed authority contexts for governed and non-scan process launches."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
import uuid
from typing import Any, Dict, Optional, Tuple, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator


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


_ISSUER = object()


class PosixProcessAttestation(BaseModel):
    """Canonical, bounded POSIX identity proof; a PID alone is never authority."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: Literal["posix-process-attestation-v1"]
    proof_type: Literal["PROC_START_TICKS_SESSION_GROUP"]
    boot_id: str
    root_start_ticks: int = Field(ge=0)
    session_id: int = Field(ge=0)
    process_group_id: int = Field(ge=0)
    pidfd_supported: bool
    pidfd_verified: bool
    worker_generation: str
    captured_at: datetime
    expires_at: datetime
    verification_result: Literal["VERIFIED", "UNVERIFIED", "FAILED"]
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _valid_window(self) -> "PosixProcessAttestation":
        if self.captured_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ExecutionContextExpiredError("process attestation timestamps must be timezone-aware")
        if self.expires_at <= self.captured_at:
            raise ExecutionContextExpiredError("process attestation expiry must follow capture")
        if self.pidfd_verified and not self.pidfd_supported:
            raise ValueError("pidfd verification cannot be asserted when unsupported")
        if self.digest != canonical_binding_digest(self.model_dump(exclude={"digest"})):
            raise ValueError("POSIX process attestation digest does not match canonical fields")
        return self


class WindowsJobAttestation(BaseModel):
    """Canonical Windows job identity proof; unsupported proof is explicit."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: Literal["windows-job-attestation-v1"]
    proof_type: Literal["JOB_OBJECT"]
    job_identity: str
    root_process_start_token: str
    worker_generation: str
    captured_at: datetime
    expires_at: datetime
    verification_result: Literal["VERIFIED", "UNVERIFIED", "FAILED"]
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _valid_window(self) -> "WindowsJobAttestation":
        if self.captured_at.tzinfo is None or self.expires_at.tzinfo is None or self.expires_at <= self.captured_at:
            raise ExecutionContextExpiredError("Windows job attestation window is invalid")
        if self.digest != canonical_binding_digest(self.model_dump(exclude={"digest"})):
            raise ValueError("Windows job attestation digest does not match canonical fields")
        return self


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


class GovernedExecutionContext(BaseModel):
    """Verifier-issued immutable context for one exact authorized launch."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    execution_id: str
    request_id: str
    organization_id: str
    project_id: Optional[str] = None
    asset_id: str
    target_id: str
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
    _issued_by: object = PrivateAttr(default=None)

    @field_validator(
        "execution_id", "request_id", "organization_id", "asset_id", "target_id",
        "authorization_decision_id", "request_fingerprint", "target_policy_version",
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

    @classmethod
    def _from_verified_values(cls, issuer: object, **values: Any) -> "GovernedExecutionContext":
        """Internal construction hook; only the decision verifier has the handle."""
        if issuer is not _ISSUER:
            raise MissingExecutionContextError("execution context issuer is not authoritative")
        for field in ("operation_options", "resource_budget", "account_impact_budget", "credential_scope"):
            values[field] = _freeze_value(values.get(field, {}))
        for field in ("operation_options", "resource_budget", "account_impact_budget", "credential_scope"):
            values[f"{field}_digest"] = canonical_binding_digest(values[field])
        values.setdefault("revocation_check_reference", f"session-jti:{values.get('session_jti', '')}")
        context = cls(**values)
        context._issued_by = _ISSUER
        return context

    def assert_issued(self) -> None:
        if self._issued_by is not _ISSUER:
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


class NonScanExecutionContext(BaseModel):
    """Explicit installer/observation capability that cannot authorize a scan."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    purpose: str
    worker_identity: str
    worker_generation: str
    expires_at: datetime
    capability_token: str = Field(repr=False)
    _issued_by: object = PrivateAttr(default=None)

    @classmethod
    def _from_verified_values(cls, issuer: object, **values: Any) -> "NonScanExecutionContext":
        if issuer is not _ISSUER:
            raise UnsupportedNonScanContextError("non-scan capability issuer is not authoritative")
        context = cls(**values)
        context._issued_by = _ISSUER
        return context

    @model_validator(mode="after")
    def _validate(self) -> "NonScanExecutionContext":
        if not self.purpose.strip() or not self.worker_identity.strip() or not self.worker_generation.strip():
            raise MissingExecutionContextError("non-scan capability fields are incomplete")
        if self.expires_at.tzinfo is None or self.expires_at <= datetime.now(timezone.utc):
            raise ExecutionContextExpiredError("non-scan capability is expired or timezone-naive")
        if self._issued_by is not _ISSUER:
            # The issuer marker is assigned immediately after model creation;
            # validation here only checks field shape and expiry.
            pass
        return self

    def assert_issued(self) -> None:
        if self._issued_by is not _ISSUER:
            raise UnsupportedNonScanContextError("non-scan capability was not issued by the verifier")


__all__ = [
    "ExecutionContextError", "MissingExecutionContextError", "ExecutionContextMismatchError",
    "ExecutionContextExpiredError", "ExecutionContextTenantError", "ExecutionContextCommandError",
    "UnsupportedNonScanContextError", "GovernedExecutionContext", "NonScanExecutionContext",
    "canonical_command_digest",
    "canonical_binding_digest",
    "PosixProcessAttestation", "WindowsJobAttestation",
    "issue_non_scan_execution_context",
]

# Resolve postponed self-references explicitly so the models also work when
# loaded by migration/test tooling outside the normal package importer.
GovernedExecutionContext.model_rebuild()
NonScanExecutionContext.model_rebuild()


def _issue_verified_context(**values: Any) -> GovernedExecutionContext:
    """Private verifier bridge; only the decision verifier calls this path."""
    return GovernedExecutionContext._from_verified_values(_ISSUER, **values)


def issue_non_scan_execution_context(purpose: str, *, ttl_seconds: int = 300) -> NonScanExecutionContext:
    """Issue a short-lived capability for explicitly classified non-scan work."""
    now = datetime.now(timezone.utc)
    return NonScanExecutionContext._from_verified_values(
        _ISSUER, purpose=purpose, worker_identity=os.environ.get("CYBERASSESS_WORKER_IDENTITY", "local-worker"),
        worker_generation=os.environ.get("CYBERASSESS_WORKER_GENERATION", "local-generation"),
        expires_at=now + timedelta(seconds=ttl_seconds), capability_token=f"non-scan-{uuid.uuid4().hex}",
    )
