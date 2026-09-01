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
MAX_CONCURRENT_SCANS_PER_TENANT = int(os.getenv("MAX_CONCURRENT_SCANS_PER_TENANT", "2"))
GLOBAL_SCAN_TIMEOUT_SECONDS = float(os.getenv("GLOBAL_SCAN_TIMEOUT_SECONDS", "300.0"))


class ScanQueueManager:
    """
    Manages concurrent active scan execution with bounded worker concurrency and timeouts.
    """

    _instance: Optional[ScanQueueManager] = None

    def __init__(self, max_concurrent: int = MAX_CONCURRENT_SCANS, max_concurrent_per_tenant: int = MAX_CONCURRENT_SCANS_PER_TENANT):
        self._max_concurrent = max_concurrent
        self._max_concurrent_per_tenant = max_concurrent_per_tenant
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._tenant_semaphores: Dict[str, asyncio.Semaphore] = {}
        self._tenant_lock = asyncio.Lock()
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

    @property
    def max_concurrent_per_tenant(self) -> int:
        return self._max_concurrent_per_tenant

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
        **kwargs,
    ) -> Any:
        """
        Executes a scan job task within the concurrency semaphore and execution timeout boundary.
        """
        tenant_semaphore = await self._tenant_semaphore(organization_id)
        async with self._semaphore:
            if tenant_semaphore is None:
                return await self._execute_with_accounting(task_fn, args, kwargs, timeout_seconds)
            async with tenant_semaphore:
                return await self._execute_with_accounting(task_fn, args, kwargs, timeout_seconds)

    async def _execute_with_accounting(self, task_fn, args, kwargs, timeout_seconds):
        self._active_count += 1
        try:
            return await asyncio.wait_for(task_fn(*args, **kwargs), timeout=timeout_seconds)
        finally:
            self._active_count = max(0, self._active_count - 1)


queue_manager = ScanQueueManager.get_instance()
