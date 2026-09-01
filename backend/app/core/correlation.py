"""Request correlation context shared by API, persistence, and scan tasks."""

from __future__ import annotations

from contextvars import ContextVar
from typing import Optional


_correlation_id: ContextVar[Optional[str]] = ContextVar(
    "cyberassess_correlation_id",
    default=None,
)


def set_correlation_id(value: str):
    """Set the current request correlation ID and return its reset token."""
    return _correlation_id.set(value)


def reset_correlation_id(token) -> None:
    """Restore the previous correlation context."""
    _correlation_id.reset(token)


def get_correlation_id() -> Optional[str]:
    """Return the correlation ID for the current request/task, if present."""
    return _correlation_id.get()
