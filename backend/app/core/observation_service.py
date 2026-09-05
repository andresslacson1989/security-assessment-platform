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
    last_recovery_error: Optional[str] = None
    last_recovered_count: int = 0


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
        self._recovery_lock = asyncio.Lock()
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
                last_recovery_error=self._state.last_recovery_error,
                last_recovered_count=self._state.last_recovered_count,
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
                    last_recovery_error=self._state.last_recovery_error,
                    last_recovered_count=self._state.last_recovered_count,
                )
                logger.warning("Backend tool observation failed: error=%s", message)
                return False

            self._state = ObservationState(
                last_started_at=started,
                last_completed_at=datetime.now(timezone.utc),
                last_error=None,
                last_recovery_error=self._state.last_recovery_error,
                last_recovered_count=self._state.last_recovered_count,
            )
            return True

    async def reap_execution_authority_once(self) -> int:
        if self._recovery_lock.locked():
            return 0
        async with self._recovery_lock:
            return await self._reap_execution_authority_once()

    async def _reap_execution_authority_once(self) -> int:
        """Terminate and durably close authority-lost executions by exact ID."""
        from app.core.db import db_manager
        from app.core.process_supervisor import process_supervisor

        try:
            candidates = await asyncio.wait_for(
                asyncio.to_thread(db_manager.list_execution_recovery_candidates),
                timeout=self.refresh_timeout_seconds,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"[:512]
            self._state = ObservationState(
                last_started_at=self._state.last_started_at,
                last_completed_at=self._state.last_completed_at,
                last_error=self._state.last_error,
                last_recovery_error=message,
                last_recovered_count=0,
            )
            logger.warning("Execution authority recovery enumeration failed: error=%s", message)
            return 0
        reaped = 0
        for candidate in candidates:
            execution_id = candidate["execution_id"]
            # The supervisor registry is keyed by the durable execution ID;
            # cancellation cannot target an arbitrary PID or a sibling job.
            try:
                cancellation = process_supervisor.cancel_execution(execution_id)
                confirmed = getattr(cancellation, "confirmed", bool(cancellation))
                if (
                    candidate.get("process_id") is not None
                    or candidate.get("run_state") == "RUNNING"
                ) and not confirmed:
                    logger.warning(
                        "Execution recovery deferred: termination not confirmed execution_id=%s status=%s",
                        execution_id, getattr(cancellation, "status", "UNKNOWN"),
                    )
                    continue
                closed = await asyncio.wait_for(
                    asyncio.to_thread(
                        db_manager.reap_execution_dispatch,
                        execution_id,
                        candidate["organization_id"],
                        terminal_state=candidate["terminal_state"],
                        reason_code=candidate["reason_code"],
                        actor="execution-reaper",
                    ),
                    timeout=self.refresh_timeout_seconds,
                )
                if closed:
                    reaped += 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"[:512]
                logger.warning(
                    "Execution authority recovery candidate failed: execution_id=%s error=%s",
                    execution_id, message,
                )
                self._state = ObservationState(
                    last_started_at=self._state.last_started_at,
                    last_completed_at=self._state.last_completed_at,
                    last_error=self._state.last_error,
                    last_recovery_error=message,
                    last_recovered_count=reaped,
                )
        self._state = ObservationState(
            last_started_at=self._state.last_started_at,
            last_completed_at=self._state.last_completed_at,
            last_error=self._state.last_error,
            last_recovery_error=self._state.last_recovery_error,
            last_recovered_count=reaped,
        )
        return reaped

    async def _run(self) -> None:
        try:
            while True:
                await self.refresh_once()
                await self.reap_execution_authority_once()
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
