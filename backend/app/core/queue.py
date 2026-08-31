"""
Contract 01 §5 & Contract 08 §12:
Global Scan Execution Queue, Concurrency Governance & Worker Pool.
Guarantees resource isolation, preventing server resource exhaustion or unconstrained process spawning.
"""

from __future__ import annotations
import asyncio
import os
from typing import Optional, Dict, Any, Callable, Awaitable

MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))
GLOBAL_SCAN_TIMEOUT_SECONDS = float(os.getenv("GLOBAL_SCAN_TIMEOUT_SECONDS", "300.0"))


class ScanQueueManager:
    """
    Manages concurrent active scan execution with bounded worker concurrency and timeouts.
    """

    _instance: Optional[ScanQueueManager] = None

    def __init__(self, max_concurrent: int = MAX_CONCURRENT_SCANS):
        self._max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._active_count = 0

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

    async def execute_bounded(
        self,
        scan_id: str,
        task_fn: Callable[..., Awaitable[Any]],
        *args,
        timeout_seconds: float = GLOBAL_SCAN_TIMEOUT_SECONDS,
        **kwargs,
    ) -> Any:
        """
        Executes a scan job task within the concurrency semaphore and execution timeout boundary.
        """
        async with self._semaphore:
            self._active_count += 1
            try:
                return await asyncio.wait_for(task_fn(*args, **kwargs), timeout=timeout_seconds)
            finally:
                self._active_count = max(0, self._active_count - 1)


queue_manager = ScanQueueManager.get_instance()
