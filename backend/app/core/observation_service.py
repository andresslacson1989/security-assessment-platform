"""Lifecycle-managed backend observation of the 26-tool fleet.

Observations are deliberately separate from authentication and execution
authorization.  The service refreshes process-local snapshots only; every
execution path retains its own live trust and version checks.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from app.adapters import get_cached_system_capabilities
from app.installers.manager import ToolInstallationManager

logger = logging.getLogger("cyberassess.observation")

DEFAULT_INTERVAL_SECONDS = 60.0
DEFAULT_REFRESH_TIMEOUT_SECONDS = 120.0


def _bounded_env_float(name: str, default: float, *, minimum: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("Ignoring invalid observation setting %s", name)
        return default
    return value if value >= minimum else default


@dataclass(frozen=True)
class ObservationState:
    last_started_at: Optional[datetime] = None
    last_completed_at: Optional[datetime] = None
    last_error: Optional[str] = None


class BackendObservationService:
    """Refreshes backend-owned capability and toolbox snapshots periodically."""

    def __init__(
        self,
        *,
        interval_seconds: Optional[float] = None,
        refresh_timeout_seconds: Optional[float] = None,
    ) -> None:
        self.interval_seconds = interval_seconds or _bounded_env_float(
            "CYBERASSESS_OBSERVATION_INTERVAL_SECONDS",
            DEFAULT_INTERVAL_SECONDS,
            minimum=1.0,
        )
        self.refresh_timeout_seconds = refresh_timeout_seconds or _bounded_env_float(
            "CYBERASSESS_OBSERVATION_TIMEOUT_SECONDS",
            DEFAULT_REFRESH_TIMEOUT_SECONDS,
            minimum=1.0,
        )
        self._refresh_lock = asyncio.Lock()
        self._task: Optional[asyncio.Task[None]] = None
        self._state = ObservationState()

    @property
    def state(self) -> ObservationState:
        return self._state

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def refresh_once(self) -> bool:
        """Refresh both snapshots once, with single-flight and an aggregate bound."""
        if self._refresh_lock.locked():
            return False
        async with self._refresh_lock:
            started = datetime.now(timezone.utc)
            self._state = ObservationState(
                last_started_at=started,
                last_completed_at=self._state.last_completed_at,
                last_error=None,
            )
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        get_cached_system_capabilities(force_refresh=True),
                        ToolInstallationManager.get_instance().get_all_tools_info(force_refresh=True),
                    ),
                    timeout=self.refresh_timeout_seconds,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"[:512]
                self._state = ObservationState(
                    last_started_at=started,
                    last_completed_at=self._state.last_completed_at,
                    last_error=message,
                )
                logger.warning("Backend tool observation failed: error=%s", message)
                return False

            self._state = ObservationState(
                last_started_at=started,
                last_completed_at=datetime.now(timezone.utc),
                last_error=None,
            )
            return True

    async def _run(self) -> None:
        try:
            while True:
                await self.refresh_once()
                await asyncio.sleep(self.interval_seconds)
        except asyncio.CancelledError:
            raise

    def start(self) -> asyncio.Task[None]:
        """Start exactly one task for the current event loop."""
        if self.running:
            return self._task  # type: ignore[return-value]
        self._task = asyncio.create_task(self._run(), name="cyberassess-tool-observation")
        return self._task

    async def stop(self) -> None:
        task = self._task
        self._task = None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


__all__ = ["BackendObservationService", "ObservationState"]
