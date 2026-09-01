"""
Contract 03 & 04 Background Scan Orchestrator and Event Dispatcher (v3.1.0).
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
    DiscoveredEndpoint,
    DiscoveredSubdomain,
    RejectedDiscovery,
    utc_now,
    calculate_fingerprint,
)
from app.core.grading import calculate_scan_grade
from app.core.storage import save_scan, get_scan
from app.engines.base import BaseAssessmentEngine
from app.adapters import discover_system_capabilities, get_adapter_registry


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

    @staticmethod
    def _normalize_tool_state(state: str) -> str:
        """Convert only known adapter states into the canonical telemetry vocabulary."""
        state_map = {
            "EXECUTION_BLOCKED": "BLOCKED",
            "EXECUTION_TIMED_OUT": "TIMED_OUT",
            "EXECUTION_CANCELLED": "CANCELLED",
            "COMPLETED_WITH_FINDINGS": "COMPLETED_WITH_FINDINGS",
            "COMPLETED_NO_FINDINGS": "COMPLETED_NO_FINDINGS",
            "PARTIAL_RESULTS_WITH_WARNING": "PARTIAL_RESULTS_WITH_WARNING",
            "TOOL_EXECUTION_FAILED": "TOOL_EXECUTION_FAILED",
            "INVALID_VERSION": "INVALID_VERSION",
        }
        normalized = state_map.get(state)
        if normalized is None:
            raise ValueError(f"Unknown tool execution state: {state!r}")
        return normalized

    @staticmethod
    def _recalculate_summary(job: ScanJob, duration_seconds: float) -> None:
        """Refresh calculated metrics without discarding execution coverage evidence."""
        previous = job.summary
        summary = calculate_scan_grade(job.findings, duration_seconds=duration_seconds)
        summary.pages_crawled = previous.pages_crawled
        summary.subdomains_discovered = previous.subdomains_discovered
        summary.active_adapters = list(previous.active_adapters)
        summary.authenticated_session_active = previous.authenticated_session_active
        summary.coverage = previous.coverage.model_copy(deep=True)
        job.summary = summary

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
        Queues and launches background execution for a new scan job governed by ScanQueueManager.
        """
        async with self._lock:
            self._active_jobs[scan_job.id] = scan_job
            save_scan(scan_job)

        from app.core.queue import queue_manager
        task = asyncio.create_task(
            queue_manager.execute_bounded(
                scan_job.id,
                self._execute_scan,
                scan_job.id,
                organization_id=scan_job.organization_id,
            )
        )
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
                await self.emit_cancelled(scan_id, "Scan job cancelled by user.")
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
            # Attach authoritative tenant provenance before persistence or SSE
            # publication; adapters must not be able to invent ownership.
            finding.organization_id = job.organization_id
            if finding.engine == "code_sast":
                finding.workspace_id = job.target.value
            # Deduplicate by fingerprint
            existing_fps = {f.fingerprint for f in job.findings}
            if finding.fingerprint in existing_fps:
                return
            job.findings.append(finding)
            # Recompute intermediate summary
            self._recalculate_summary(
                job,
                (utc_now() - (job.started_at or utc_now())).total_seconds(),
            )

        await self._broadcast(scan_id, "finding", finding.model_dump(mode="json"))

    async def emit_auth_status(self, scan_id: str, data: dict) -> None:
        """
        Emits an authentication status event and records active session state.
        """
        job = self._active_jobs.get(scan_id)
        if job:
            job.summary.authenticated_session_active = bool(data.get("session_active", False))

        await self._broadcast(scan_id, "auth_status", data)

    async def emit_endpoint_discovered(self, scan_id: str, endpoint: DiscoveredEndpoint) -> None:
        """
        Emits a crawl discovery event and updates job discovered endpoints and pages count.
        """
        job = self._active_jobs.get(scan_id)
        if job:
            existing_urls = {ep.url for ep in job.discovered_endpoints}
            if endpoint.url not in existing_urls:
                job.discovered_endpoints.append(endpoint)
                job.summary.pages_crawled = max(1, len(job.discovered_endpoints))

        await self._broadcast(scan_id, "crawl_discovered", endpoint.model_dump(mode="json"))

    async def emit_subdomain_discovered(self, scan_id: str, subdomain: DiscoveredSubdomain) -> None:
        """
        Emits an OSINT subdomain discovery event and updates job discovered subdomains.
        """
        job = self._active_jobs.get(scan_id)
        if job:
            existing_domains = {sd.domain for sd in job.discovered_subdomains}
            if subdomain.domain not in existing_domains:
                job.discovered_subdomains.append(subdomain)
                job.summary.subdomains_discovered = len(job.discovered_subdomains)

        await self._broadcast(scan_id, "subdomain_discovered", subdomain.model_dump(mode="json"))

    async def emit_rejected_discovery(self, scan_id: str, rejection: RejectedDiscovery) -> None:
        job = self._active_jobs.get(scan_id)
        if job:
            job.rejected_discoveries.append(rejection)
        await self._broadcast(scan_id, "discovery_rejected", rejection.model_dump(mode="json"))

    async def emit_tool_execution_state(self, scan_id: str, tool_name: str, state: str) -> None:
        job = self._active_jobs.get(scan_id)
        try:
            state = self._normalize_tool_state(state)
        except ValueError:
            state = "TOOL_EXECUTION_FAILED"
            if job:
                limitation = f"{tool_name}: INVALID_STATE"
                job.summary.coverage.is_fully_assessed = False
                if limitation not in job.summary.coverage.coverage_limitations:
                    job.summary.coverage.coverage_limitations.append(limitation)
        if job:
            job.tool_execution_states[tool_name] = state
            if state in {"PARTIAL_RESULTS_WITH_WARNING", "TOOL_EXECUTION_FAILED", "BLOCKED", "TIMED_OUT", "CANCELLED", "INVALID_VERSION"}:
                job.summary.coverage.is_fully_assessed = False
                limitation = f"{tool_name}: {state}"
                if limitation not in job.summary.coverage.coverage_limitations:
                    job.summary.coverage.coverage_limitations.append(limitation)
        await self._broadcast(scan_id, "tool_execution_state", {"tool_name": tool_name, "state": state})

    async def emit_completed(self, scan_id: str, summary: ScanJobSummary) -> None:
        job = self._active_jobs.get(scan_id)
        active_adapters = getattr(job, "active_adapters", []) if job else []
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
            "pages_crawled": summary.pages_crawled,
            "subdomains_discovered": summary.subdomains_discovered,
            "authenticated_session_active": summary.authenticated_session_active,
            "active_adapters": active_adapters,
            "completed_at": utc_now().isoformat(),
        })

    async def emit_error(self, scan_id: str, error_message: str) -> None:
        await self._broadcast(scan_id, "failed", {"reason": error_message})
        await self._broadcast(scan_id, "error", {"message": error_message})

    async def emit_cancelled(self, scan_id: str, message: str = "Scan cancelled by user.") -> None:
        await self._broadcast(scan_id, "cancelled", {"message": message})

    async def emit_tool_status(self, scan_id: str, tool_name: str, available: bool, mode: str, version: Optional[str] = None) -> None:
        """
        Emits an event: tool_status SSE event per Contract 04 v4.1.0.
        """
        await self._broadcast(scan_id, "tool_status", {
            "tool": tool_name,
            "available": available,
            "mode": mode,
            "version": version,
        })

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

        # --- Adapter Discovery & tool_status SSE (Contract 04 v4.1.0) ---
        try:
            capabilities = await discover_system_capabilities(job.config.adapters)
            active_adapters: List[str] = []
            for tool_status in capabilities.tools:
                await self.emit_tool_status(
                    scan_id,
                    tool_name=tool_status.name,
                    available=tool_status.available,
                    mode=tool_status.execution_mode.value,
                    version=tool_status.version,
                )
                if tool_status.available:
                    active_adapters.append(tool_status.name)
            job.active_adapters = active_adapters
            job.summary.active_adapters = active_adapters
            if active_adapters:
                await self.emit_log(scan_id, LogLevel.INFO, "orchestrator", f"Active tool adapters: {', '.join(active_adapters)}")
            else:
                await self.emit_log(scan_id, LogLevel.INFO, "orchestrator", "No external tool adapters detected - native Python engines will be used for all assessments.")
        except Exception as e:
            await self.emit_log(scan_id, LogLevel.WARNING, "orchestrator", f"Adapter discovery error (non-fatal): {e}")
            job.active_adapters = []

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

                async def _ep_cb(ep: DiscoveredEndpoint) -> None:
                    await self.emit_endpoint_discovered(scan_id, ep)

                async def _auth_cb(data: dict) -> None:
                    await self.emit_auth_status(scan_id, data)

                async def _subdomain_cb(sd: DiscoveredSubdomain) -> None:
                    await self.emit_subdomain_discovered(scan_id, sd)

                async def _rejected_cb(rejection: RejectedDiscovery) -> None:
                    await self.emit_rejected_discovery(scan_id, rejection)

                async def _tool_state_cb(tool_name: str, state: str) -> None:
                    await self.emit_tool_execution_state(scan_id, tool_name, state)

                def _sbom_cb(sbom: SBOMReport) -> None:
                    if job:
                        job.sbom_report = sbom

                def _cis_cb(cis_res: CISBenchmarkResult) -> None:
                    if job:
                        job.cis_results.append(cis_res)

                try:
                    import inspect
                    sig = inspect.signature(engine.run)
                    run_kwargs = {}
                    accepts_var_keyword = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
                    if accepts_var_keyword:
                        run_kwargs["organization_id"] = job.organization_id
                    if "emit_auth_status" in sig.parameters or accepts_var_keyword:
                        run_kwargs["emit_auth_status"] = _auth_cb
                    if "emit_endpoint_discovered" in sig.parameters or accepts_var_keyword:
                        run_kwargs["emit_endpoint_discovered"] = _ep_cb
                    if "emit_subdomain_discovered" in sig.parameters or accepts_var_keyword:
                        run_kwargs["emit_subdomain_discovered"] = _subdomain_cb
                    if "emit_rejected_discovery" in sig.parameters or accepts_var_keyword:
                        run_kwargs["emit_rejected_discovery"] = _rejected_cb
                    if "emit_tool_execution_state" in sig.parameters or accepts_var_keyword:
                        run_kwargs["emit_tool_execution_state"] = _tool_state_cb
                    if "record_sbom_report" in sig.parameters or accepts_var_keyword:
                        run_kwargs["record_sbom_report"] = _sbom_cb
                    if "record_cis_result" in sig.parameters or accepts_var_keyword:
                        run_kwargs["record_cis_result"] = _cis_cb

                    engine_findings = await engine.run(
                        job.target,
                        job.config,
                        _log_cb,
                        _prog_cb,
                        _find_cb,
                        **run_kwargs,
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
            self._recalculate_summary(job, duration)
            job.summary.pages_crawled = max(1, len(job.discovered_endpoints))

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
            await self.emit_cancelled(scan_id, "Scan task was cancelled.")
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
