"""
Contract 01 §5 & Contract 08 §12:
Global Scan Execution Queue, Concurrency Governance & Worker Pool.
Guarantees resource isolation, preventing server resource exhaustion or unconstrained process spawning.
"""

from __future__ import annotations
import asyncio
import os
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Callable, Awaitable, Protocol

MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))
MAX_CONCURRENT_SCANS_PER_TENANT = int(os.getenv("MAX_CONCURRENT_SCANS_PER_TENANT", "2"))
GLOBAL_SCAN_TIMEOUT_SECONDS = float(os.getenv("GLOBAL_SCAN_TIMEOUT_SECONDS", "300.0"))
EXECUTION_QUEUE_URL = os.getenv("EXECUTION_QUEUE_URL", "").strip()


class DurableQueueBackend(Protocol):
    async def enqueue(self, scan_id: str, organization_id: Optional[str]) -> str: ...
    async def complete(self, message_id: str) -> None: ...
    async def fail(self, message_id: str, error_code: str) -> None: ...


class DurableQueueConsumer(Protocol):
    async def consume_once(
        self,
        handler: Callable[[str, Optional[str]], Awaitable[None]],
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
        self._redis = redis.from_url(redis_url, decode_responses=True)
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

    async def enqueue(self, scan_id: str, organization_id: Optional[str]) -> str:
        await self._ensure_group()
        message_id = await self._redis.xadd(
            self.stream_name,
            {
                "scan_id": scan_id,
                "organization_id": organization_id or "",
                "enqueued_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        return str(message_id)

    async def complete(self, message_id: str) -> None:
        await self._ensure_group()
        await self._redis.xack(self.stream_name, self.consumer_group, message_id)

    async def fail(self, message_id: str, error_code: str) -> None:
        await self._ensure_group()
        await self._redis.xadd(
            f"{self.stream_name}:failures",
            {"message_id": message_id, "error_code": error_code},
        )
        await self._redis.xack(self.stream_name, self.consumer_group, message_id)

    async def consume_once(
        self,
        handler: Callable[[str, Optional[str]], Awaitable[None]],
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
                block=block_ms,
            )
            if response:
                messages = response[0][1] or []

        if not messages:
            return False

        message_id, fields = messages[0]
        scan_id = str(fields.get("scan_id", "")).strip()
        organization_id = str(fields.get("organization_id", "")).strip() or None
        try:
            if not scan_id:
                raise ValueError("execution intent is missing scan_id")
            await handler(scan_id, organization_id)
        except Exception as exc:
            await self.fail(str(message_id), type(exc).__name__)
        else:
            await self.complete(str(message_id))
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

    async def enqueue_only(self, scan_id: str, organization_id: Optional[str]) -> str:
        """Persist an enterprise execution intent without running it locally."""
        if self._durable_backend is None:
            raise RuntimeError("enqueue_only requires a durable execution backend")
        return await self._durable_backend.enqueue(scan_id, organization_id)

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
        message_id = None
        if self._durable_backend is not None:
            message_id = await self._durable_backend.enqueue(scan_id, organization_id)
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
                await self._durable_backend.fail(message_id, type(exc).__name__)
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
