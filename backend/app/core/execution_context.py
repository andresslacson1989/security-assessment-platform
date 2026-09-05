"""Typed authority contexts for governed and non-scan process launches."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
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
        return self


def canonical_command_digest(command: Tuple[str, ...]) -> str:
    if not command or any(not isinstance(item, str) or not item for item in command):
        raise ExecutionContextCommandError("exact command vector is required")
    return hashlib.sha256(
        json.dumps(list(command), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


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
    operation_options: Dict[str, Any] = Field(default_factory=dict)
    resource_budget: Dict[str, int] = Field(default_factory=dict)
    account_impact_budget: Dict[str, int] = Field(default_factory=dict)
    credential_scope: Dict[str, str] = Field(default_factory=dict)
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
        if self.expires_at <= datetime.now(timezone.utc):
            raise ExecutionContextExpiredError("execution context is expired")
        return self

    @classmethod
    def _issue(cls, issuer: object, **values: Any) -> "GovernedExecutionContext":
        """Issue only from an internal verifier; callers cannot forge issuer state."""
        if issuer is not _ISSUER:
            raise MissingExecutionContextError("execution context issuer is not authoritative")
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
    def _issue(cls, issuer: object, **values: Any) -> "NonScanExecutionContext":
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
    "PosixProcessAttestation", "WindowsJobAttestation",
]

# Imported only by trusted verifier modules; callers must not construct a
# governed context with a public constructor.
_AUTHORITY_ISSUER = _ISSUER

# Resolve postponed self-references explicitly so the models also work when
# loaded by migration/test tooling outside the normal package importer.
GovernedExecutionContext.model_rebuild()
NonScanExecutionContext.model_rebuild()
