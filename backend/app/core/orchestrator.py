"""
Contract 03 & 04 Background Scan Orchestrator and Event Dispatcher.
"""

from __future__ import annotations
import asyncio
from datetime import datetime, timezone
import time
from typing import Dict, List, Optional, Set
from app.core.models import (
    ScanJob,
    ScanStatus,
    Finding,
    LogEntry,
    LogLevel,
    ScanJobSummary,
    utc_now,
    calculate_fingerprint,
)
from app.core.grading import calculate_scan_grade
from app.core.storage import save_scan, get_scan
from app.engines.base import BaseAssessmentEngine


class ScanOrchestrator:
    """
    Background orchestrator that manages engine registration, scan lifecycle,
    error isolation, progress tracking, and SSE event streaming.
    """

    def __init__(self):
        self._engines: Dict[str, BaseAssessmentEngine] = {}
        self._active_jobs: Dict[str, ScanJob] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._subscribers: Dict[str, Set[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()

    # --- Engine Registry ---

    def register_engine(self, engine: BaseAssessmentEngine) -> None:
        """
        Registers an assessment engine plugin.
        """
        self._engines[engine.name] = engine

    def get_engine(self, name: str) -> Optional[BaseAssessmentEngine]:
        """
        Retrieves a registered engine by its unique name.
        """
        return self._engines.get(name)

    def get_registered_engines(self) -> List[BaseAssessmentEngine]:
        """
        Returns a list of all registered engine instances.
        """
        return list(self._engines.values())

    # --- Active Scan Management ---

    def get_active_job(self, scan_id: str) -> Optional[ScanJob]:
        """
        Returns the in-memory active ScanJob or attempts to fetch it from disk.
        """
        if scan_id in self._active_jobs:
            return self._active_jobs[scan_id]
        return get_scan(scan_id)

    async def start_scan(self, scan_job: ScanJob) -> asyncio.Task:
        """
        Queues and launches background execution for a new scan job.
        """
        async with self._lock:
            self._active_jobs[scan_job.id] = scan_job
            save_scan(scan_job)

        task = asyncio.create_task(self._execute_scan(scan_job.id))
        self._tasks[scan_job.id] = task
        return task

    async def cancel_scan(self, scan_id: str) -> bool:
        """
        Gracefully cancels an active scan job.
        """
        task = self._tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            job = self._active_jobs.get(scan_id)
            if job:
                job.status = ScanStatus.CANCELLED
                job.completed_at = utc_now()
                job.current_stage = "Scan job cancelled by user."
                save_scan(job)
                await self.emit_log(scan_id, LogLevel.WARNING, "orchestrator", "Scan job cancelled by user.")
                await self.emit_progress(scan_id, job.progress_percent, "Scan cancelled.", ScanStatus.CANCELLED)
            return True
        return False

    # --- SSE Event Pub/Sub ---

    def subscribe_events(self, scan_id: str) -> asyncio.Queue:
        """
        Subscribes a client to real-time events for a scan job.
        """
        queue: asyncio.Queue = asyncio.Queue()
        if scan_id not in self._subscribers:
            self._subscribers[scan_id] = set()
        self._subscribers[scan_id].add(queue)
        return queue

    def unsubscribe_events(self, scan_id: str, queue: asyncio.Queue) -> None:
        """
        Unsubscribes a disconnected client queue.
        """
        if scan_id in self._subscribers:
            self._subscribers[scan_id].discard(queue)
            if not self._subscribers[scan_id]:
                del self._subscribers[scan_id]

    async def _broadcast(self, scan_id: str, event_type: str, data: dict | str) -> None:
        """
        Broadcasts an SSE event payload to all active subscribers.
        """
        if scan_id not in self._subscribers:
            return
        message = {"event": event_type, "data": data}
        for q in list(self._subscribers[scan_id]):
            try:
                q.put_nowait(message)
            except Exception:
                pass

    async def emit_progress(
        self,
        scan_id: str,
        percent: int,
        stage: str,
        status: ScanStatus = ScanStatus.RUNNING
    ) -> None:
        job = self._active_jobs.get(scan_id)
        if job:
            job.progress_percent = min(100, max(0, percent))
            job.current_stage = stage
            job.status = status

        await self._broadcast(scan_id, "progress", {
            "percent": percent,
            "stage": stage,
            "status": status.value,
        })

    async def emit_log(
        self,
        scan_id: str,
        level: LogLevel,
        engine: str,
        message: str
    ) -> None:
        entry = LogEntry(
            timestamp=utc_now(),
            level=level,
            engine=engine,
            message=message,
        )
        job = self._active_jobs.get(scan_id)
        if job:
            job.logs.append(entry)

        await self._broadcast(scan_id, "log", {
            "timestamp": entry.timestamp.isoformat(),
            "level": entry.level.value,
            "engine": engine,
            "message": message,
        })

    async def emit_finding(self, scan_id: str, finding: Finding) -> None:
        job = self._active_jobs.get(scan_id)
        if job:
            # Deduplicate by fingerprint
            existing_fps = {f.fingerprint for f in job.findings}
            if finding.fingerprint in existing_fps:
                return
            job.findings.append(finding)
            # Recompute intermediate summary
            job.summary = calculate_scan_grade(
                job.findings,
                duration_seconds=(utc_now() - (job.started_at or utc_now())).total_seconds()
            )

        await self._broadcast(scan_id, "finding", finding.model_dump(mode="json"))

    async def emit_completed(self, scan_id: str, summary: ScanJobSummary) -> None:
        await self._broadcast(scan_id, "completed", {
            "scan_id": scan_id,
            "status": ScanStatus.COMPLETED.value,
            "overall_security_grade": summary.overall_security_grade,
            "weighted_score": summary.weighted_score,
            "total_findings": summary.total_findings,
            "critical_count": summary.critical_count,
            "high_count": summary.high_count,
            "medium_count": summary.medium_count,
            "low_count": summary.low_count,
            "info_count": summary.info_count,
            "completed_at": utc_now().isoformat(),
        })

    async def emit_error(self, scan_id: str, error_message: str) -> None:
        await self._broadcast(scan_id, "error", {"message": error_message})

    # --- Background Execution Engine ---

    async def _execute_scan(self, scan_id: str) -> None:
        job = self._active_jobs.get(scan_id)
        if not job:
            return

        start_time = time.monotonic()
        job.started_at = utc_now()
        job.status = ScanStatus.RUNNING

        await self.emit_log(scan_id, LogLevel.INFO, "orchestrator", f"Starting security scan on target: {job.target.value}")
        await self.emit_progress(scan_id, 5, "Initializing engines...", ScanStatus.RUNNING)

        # Select and filter applicable engines
        applicable_engines: List[BaseAssessmentEngine] = []
        for engine_name in job.enabled_engines:
            engine = self._engines.get(engine_name)
            if engine and engine.is_applicable(job.target):
                applicable_engines.append(engine)

        if not applicable_engines:
            await self.emit_log(
                scan_id,
                LogLevel.WARNING,
                "orchestrator",
                f"No enabled engines are applicable for target type {job.target.type.value}."
            )
            job.status = ScanStatus.COMPLETED
            job.progress_percent = 100
            job.current_stage = "Completed (No applicable engines)."
            job.completed_at = utc_now()
            job.summary = calculate_scan_grade([], duration_seconds=0.0)
            save_scan(job)
            await self.emit_completed(scan_id, job.summary)
            return

        total_engines = len(applicable_engines)
        progress_per_engine = 90.0 / total_engines

        try:
            for idx, engine in enumerate(applicable_engines):
                engine_base_progress = int(5 + idx * progress_per_engine)
                stage_desc = f"Running {engine.display_name}..."
                await self.emit_progress(scan_id, engine_base_progress, stage_desc)
                await self.emit_log(scan_id, LogLevel.INFO, engine.name, f"Engine {engine.display_name} started.")

                # Callbacks bound to this engine and scan
                async def _log_cb(lvl: LogLevel, msg: str, eng_name=engine.name) -> None:
                    await self.emit_log(scan_id, lvl, eng_name, msg)

                async def _prog_cb(pct: int, stg: str, base_prog=engine_base_progress, step_alloc=progress_per_engine) -> None:
                    computed = int(base_prog + (pct / 100.0) * step_alloc)
                    await self.emit_progress(scan_id, computed, stg)

                async def _find_cb(f: Finding) -> None:
                    await self.emit_finding(scan_id, f)

                try:
                    engine_findings = await engine.run(
                        job.target,
                        job.config,
                        _log_cb,
                        _prog_cb,
                        _find_cb,
                    )
                    # Deduplicate and append
                    for finding in engine_findings:
                        existing_fps = {f.fingerprint for f in job.findings}
                        if finding.fingerprint not in existing_fps:
                            job.findings.append(finding)

                    await self.emit_log(scan_id, LogLevel.INFO, engine.name, f"Completed {engine.display_name}. Found {len(engine_findings)} findings.")
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    # Error isolation guarantee: single engine failure never crashes the scan
                    await self.emit_log(scan_id, LogLevel.ERROR, engine.name, f"Engine failed with error: {str(e)}")

            # Finalize scan
            duration = time.monotonic() - start_time
            job.status = ScanStatus.COMPLETED
            job.progress_percent = 100
            job.current_stage = "Assessment complete."
            job.completed_at = utc_now()
            job.summary = calculate_scan_grade(job.findings, duration_seconds=duration)

            save_scan(job)
            await self.emit_progress(scan_id, 100, "Assessment complete.", ScanStatus.COMPLETED)
            await self.emit_log(scan_id, LogLevel.INFO, "orchestrator", f"Scan finished with Grade {job.summary.overall_security_grade} (Score: {job.summary.weighted_score}).")
            await self.emit_completed(scan_id, job.summary)

        except asyncio.CancelledError:
            job.status = ScanStatus.CANCELLED
            job.completed_at = utc_now()
            job.current_stage = "Scan cancelled."
            save_scan(job)
            await self.emit_log(scan_id, LogLevel.WARNING, "orchestrator", "Scan task was cancelled.")
            await self.emit_progress(scan_id, job.progress_percent, "Scan cancelled.", ScanStatus.CANCELLED)
            raise
        except Exception as ex:
            job.status = ScanStatus.FAILED
            job.completed_at = utc_now()
            job.current_stage = f"Scan failed: {str(ex)}"
            save_scan(job)
            await self.emit_log(scan_id, LogLevel.ERROR, "orchestrator", f"Fatal scan error: {str(ex)}")
            await self.emit_error(scan_id, str(ex))


# Global Orchestrator Singleton
orchestrator = ScanOrchestrator()
