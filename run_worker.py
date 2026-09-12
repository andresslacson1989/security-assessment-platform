#!/usr/bin/env python3
"""CyberAssess enterprise execution-plane worker."""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def should_process_scan(status: object) -> bool:
    """Return whether a queued intent may still execute its scan.

    Redis Streams can redeliver an intent after a worker crash.  Terminal
    authoritative states are therefore idempotent no-ops at the worker
    boundary; only pending/running work may be handed to the executor.
    """
    from app.core.models import ScanStatus

    return status not in {
        ScanStatus.COMPLETED,
        ScanStatus.FAILED,
        ScanStatus.CANCELLED,
    }


def _install_shutdown_handlers(stop_event: asyncio.Event):
    """Arrange for container termination signals to stop the worker loop."""
    loop = asyncio.get_running_loop()
    installed: list[signal.Signals] = []
    for shutdown_signal in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(shutdown_signal, stop_event.set)
        except (NotImplementedError, RuntimeError, ValueError):
            # Windows event loops and non-main-thread loops may not expose
            # POSIX signal registration. The container production path is
            # Linux; unsupported loop implementations remain unchanged.
            continue
        installed.append(shutdown_signal)
    return loop, tuple(installed)


def _remove_shutdown_handlers(loop, installed: tuple[signal.Signals, ...]) -> None:
    """Remove worker-owned signal handlers before the event loop is closed."""
    for shutdown_signal in installed:
        try:
            loop.remove_signal_handler(shutdown_signal)
        except (RuntimeError, ValueError):
            # Cleanup must not mask the queue's terminal close path.
            continue


async def handle_consumed_scan(
    orchestrator: object,
    local_executor: object,
    scan_id: str,
    organization_id: str | None,
    authorization_request_id: str | None,
    cloud_credentials=None,
    queue_binding=None,
) -> None:
    """Apply the production post-consume authority handoff.

    Keeping this boundary module-level makes the exact worker callback
    independently testable while leaving Redis consumption and orchestration
    as the production implementations. No queue payload is allowed to bypass
    the typed binding requirement.
    """
    if not organization_id or not authorization_request_id:
        raise RuntimeError("queued scan is missing its authoritative tenant/request identity")
    from app.core.queue import QueueDispatchBinding

    if type(queue_binding) is not QueueDispatchBinding:
        raise RuntimeError("queued scan is missing its authoritative queue binding")
    await orchestrator.execute_dispatched_scan(
        scan_id,
        organization_id,
        authorization_request_id,
        cloud_credentials=cloud_credentials,
        executor=local_executor,
        queue_binding=queue_binding,
    )


async def run_worker() -> None:
    from app.core.orchestrator import ScanOrchestrator
    from app.core.queue import (
        EXECUTION_QUEUE_URL,
        QueueDispatchBinding,
        RedisDurableQueue,
        ScanQueueManager,
    )

    if not EXECUTION_QUEUE_URL:
        raise RuntimeError("EXECUTION_QUEUE_URL is required for the enterprise worker")
    if os.getenv("ENVIRONMENT", "").strip().lower() == "production":
        from app.core.credential_handoff import require_credential_handoff_key

        require_credential_handoff_key()

    from app.engines.network.engine import NetworkAssessmentEngine
    from app.engines.web_dast.engine import WebDastAssessmentEngine
    from app.engines.code_sast.engine import CodeSastAssessmentEngine
    from app.engines.infra_iac.engine import InfraIacAssessmentEngine
    from app.engines.cicd_audit.engine import CicdAuditAssessmentEngine

    orchestrator = ScanOrchestrator()
    for engine in (
        NetworkAssessmentEngine(),
        WebDastAssessmentEngine(),
        CodeSastAssessmentEngine(),
        InfraIacAssessmentEngine(),
        CicdAuditAssessmentEngine(),
    ):
        orchestrator.register_engine(engine)

    queue = RedisDurableQueue(EXECUTION_QUEUE_URL)
    local_executor = ScanQueueManager()
    stop_event = asyncio.Event()
    signal_loop, installed_signals = _install_shutdown_handlers(stop_event)

    async def handle(
        scan_id: str,
        organization_id: str | None,
        authorization_request_id: str | None,
        cloud_credentials=None,
        queue_binding: QueueDispatchBinding | None = None,
    ) -> None:
        # Redis has already consumed the durable intent. The orchestrator is
        # the sole post-consume authority boundary; it reloads all tenant and
        # child identities and invokes the private scan executor only through
        # this worker-owned bounded executor.
        await handle_consumed_scan(
            orchestrator,
            local_executor,
            scan_id,
            organization_id,
            authorization_request_id,
            cloud_credentials,
            queue_binding,
        )

    try:
        while not stop_event.is_set():
            await queue.consume_once(
                handle,
                block_ms=int(os.getenv("EXECUTION_QUEUE_BLOCK_MS", "5000")),
                reclaim_idle_ms=int(os.getenv("EXECUTION_QUEUE_RECLAIM_IDLE_MS", "60000")),
            )
    finally:
        _remove_shutdown_handlers(signal_loop, installed_signals)
        await queue.close()


if __name__ == "__main__":
    asyncio.run(run_worker())
