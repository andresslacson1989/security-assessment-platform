"""
Unit tests for Engine Plugin Interface, Token Bucket Rate Limiter, Circuit Breaker, and Async Orchestrator (v3.1.0).
"""

import asyncio
import time
import pytest
from typing import List

from app.core.models import (
    Target,
    TargetType,
    ScanJob,
    ScanProfile,
    ScanStatus,
    LogLevel,
    Finding,
    Evidence,
    Severity,
    calculate_fingerprint,
)
from app.engines.base import BaseAssessmentEngine, LogCallback, ProgressCallback, FindingCallback
from app.core.rate_limiter import TokenBucketRateLimiter, CircuitBreaker, CircuitState
from app.core.orchestrator import ScanOrchestrator


class MockSuccessfulEngine(BaseAssessmentEngine):
    @property
    def name(self) -> str:
        return "mock_success"

    @property
    def display_name(self) -> str:
        return "Mock Success Engine"

    @property
    def description(self) -> str:
        return "Mock engine for testing"

    def is_applicable(self, target: Target) -> bool:
        return target.type in (TargetType.URL, TargetType.DOMAIN)

    async def run(
        self,
        target: Target,
        config,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        emit_finding: FindingCallback,
        **kwargs,
    ) -> List[Finding]:
        await emit_log(LogLevel.INFO, "Mock starting...")
        await emit_progress(50, "Halfway done...")
        
        finding = Finding(
            scan_id="mock-scan-id",
            engine=self.name,
            check_id="MOCK-001",
            category="Testing",
            title="Mock Security Flaw",
            severity=Severity.MEDIUM,
            cvss_score=5.0,
            description="Mock description",
            impact="Mock impact",
            remediation="Mock remediation",
            evidence=Evidence(location=target.value, observed_value="Mock value", expected_value="Safe"),
            fingerprint=calculate_fingerprint("MOCK-001", target.value, "Mock value"),
        )
        await emit_finding(finding)
        await emit_progress(100, "Done.")
        return [finding]


class MockFailingEngine(BaseAssessmentEngine):
    @property
    def name(self) -> str:
        return "mock_fail"

    @property
    def display_name(self) -> str:
        return "Mock Failing Engine"

    @property
    def description(self) -> str:
        return "Mock engine that raises an exception"

    def is_applicable(self, target: Target) -> bool:
        return True

    async def run(
        self,
        target: Target,
        config,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        emit_finding: FindingCallback,
        **kwargs,
    ) -> List[Finding]:
        await emit_log(LogLevel.INFO, "Simulating fatal socket error...")
        raise ConnectionResetError("Simulated connection reset")


class MockPartialToolEngine(BaseAssessmentEngine):
    @property
    def name(self) -> str:
        return "mock_partial_tool"

    @property
    def display_name(self) -> str:
        return "Mock Partial Tool Engine"

    @property
    def description(self) -> str:
        return "Emits a degraded external-tool state"

    def is_applicable(self, target: Target) -> bool:
        return True

    async def run(self, target, config, emit_log, emit_progress, emit_finding, **kwargs):
        await kwargs["emit_tool_execution_state"]("subfinder", "PARTIAL_RESULTS_WITH_WARNING")
        return []


@pytest.mark.asyncio
async def test_token_bucket_rate_limiter():
    limiter = TokenBucketRateLimiter(rate_rps=10.0, burst_capacity=5.0)
    
    # Acquire burst capacity
    start = time.monotonic()
    for _ in range(5):
        await limiter.acquire()
    elapsed = time.monotonic() - start
    assert elapsed < 0.1  # Fast because of burst tokens

    # Halve rate
    limiter.halve_rate()
    assert limiter.rate_rps == 5.0

    # Reset rate
    limiter.reset_rate(20.0)
    assert limiter.rate_rps == 20.0


def test_circuit_breaker_transitions():
    cb = CircuitBreaker(pause_seconds=0.1)
    assert cb.state == CircuitState.NORMAL

    # Record 4 consecutive 5xx errors (should stay NORMAL)
    for _ in range(4):
        cb.record_response(status_code=503)
    assert cb.state == CircuitState.NORMAL

    # 5th consecutive 5xx error triggers THROTTLED
    cb.record_response(status_code=500)
    assert cb.state == CircuitState.THROTTLED

    # 5 more errors while throttled triggers TRIPPED
    for _ in range(5):
        cb.record_response(status_code=500)
    assert cb.state == CircuitState.TRIPPED
    assert cb.is_tripped() is True


@pytest.mark.asyncio
async def test_orchestrator_full_scan_lifecycle():
    orch = ScanOrchestrator()
    mock_engine = MockSuccessfulEngine()
    orch.register_engine(mock_engine)

    assert orch.get_engine("mock_success") == mock_engine
    assert len(orch.get_registered_engines()) == 1

    target = Target(name="Test Target", type=TargetType.URL, value="https://example.com")
    scan_job = ScanJob(
        target=target,
        profile=ScanProfile.CUSTOM,
        enabled_engines=["mock_success"],
    )

    # Subscribe to SSE events
    queue = orch.subscribe_events(scan_job.id)

    # Start scan
    task = await orch.start_scan(scan_job)
    await task

    # Verify final state
    completed_job = orch.get_active_job(scan_job.id)
    assert completed_job is not None
    assert completed_job.status == ScanStatus.COMPLETED
    assert completed_job.progress_percent == 100
    assert len(completed_job.findings) == 1
    assert completed_job.findings[0].check_id == "MOCK-001"
    assert completed_job.summary.overall_security_grade == "B"  # 1 Medium finding -> Grade B

    # Verify event stream items received in queue
    events = []
    while not queue.empty():
        events.append(queue.get_nowait())

    event_types = [e["event"] for e in events]
    assert "progress" in event_types
    assert "log" in event_types
    assert "finding" in event_types
    assert "completed" in event_types

    orch.unsubscribe_events(scan_job.id, queue)


@pytest.mark.asyncio
async def test_final_grading_preserves_subfinder_coverage_degradation():
    orch = ScanOrchestrator()
    orch.register_engine(MockPartialToolEngine())
    job = ScanJob(
        target=Target(name="Example", type=TargetType.DOMAIN, value="example.com"),
        profile=ScanProfile.CUSTOM,
        enabled_engines=["mock_partial_tool"],
    )

    task = await orch.start_scan(job)
    await task

    completed = orch.get_active_job(job.id)
    assert completed is not None
    assert completed.status == ScanStatus.COMPLETED
    assert completed.tool_execution_states["subfinder"] == "PARTIAL_RESULTS_WITH_WARNING"
    assert completed.summary.coverage.is_fully_assessed is False
    assert "subfinder: PARTIAL_RESULTS_WITH_WARNING" in completed.summary.coverage.coverage_limitations


@pytest.mark.asyncio
async def test_unknown_tool_state_fails_closed():
    orch = ScanOrchestrator()
    job = ScanJob(target=Target(name="Example", type=TargetType.DOMAIN, value="example.com"))
    orch._active_jobs[job.id] = job

    await orch.emit_tool_execution_state(job.id, "subfinder", "EXECUTION_NOT_A_REAL_STATE")

    assert job.tool_execution_states["subfinder"] == "TOOL_EXECUTION_FAILED"
    assert job.summary.coverage.is_fully_assessed is False
    assert "subfinder: INVALID_STATE" in job.summary.coverage.coverage_limitations


@pytest.mark.asyncio
async def test_orchestrator_error_isolation():
    orch = ScanOrchestrator()
    orch.register_engine(MockFailingEngine())
    orch.register_engine(MockSuccessfulEngine())

    target = Target(name="Test Target", type=TargetType.URL, value="https://example.com")
    scan_job = ScanJob(
        target=target,
        profile=ScanProfile.CUSTOM,
        enabled_engines=["mock_fail", "mock_success"],
    )

    # Execution should NOT crash even if one engine fails
    task = await orch.start_scan(scan_job)
    await task

    job = orch.get_active_job(scan_job.id)
    assert job is not None
    assert job.status == ScanStatus.COMPLETED
    # The successful engine still added its finding
    assert len(job.findings) == 1
    # Error log from the failing engine was captured
    error_logs = [log for log in job.logs if log.level == LogLevel.ERROR]
    assert len(error_logs) >= 1
    assert "Simulated connection reset" in error_logs[0].message


@pytest.mark.asyncio
async def test_orchestrator_cancellation():
    class SlowEngine(BaseAssessmentEngine):
        @property
        def name(self) -> str:
            return "slow_engine"

        @property
        def display_name(self) -> str:
            return "Slow Engine"

        @property
        def description(self) -> str:
            return "Sleeps to test cancellation"

        def is_applicable(self, target: Target) -> bool:
            return True

        async def run(self, target, config, emit_log, emit_progress, emit_finding, **kwargs):
            await emit_progress(10, "Sleeping...")
            await asyncio.sleep(5.0)
            return []

    orch = ScanOrchestrator()
    orch.register_engine(SlowEngine())

    target = Target(name="Cancel Test", type=TargetType.URL, value="https://example.com")
    scan_job = ScanJob(
        target=target,
        profile=ScanProfile.CUSTOM,
        enabled_engines=["slow_engine"],
    )

    task = await orch.start_scan(scan_job)
    await asyncio.sleep(0.05)  # Let it begin

    # Cancel scan
    cancelled = await orch.cancel_scan(scan_job.id)
    assert cancelled is True

    # Await task to complete cancellation
    with pytest.raises(asyncio.CancelledError):
        await task

    job = orch.get_active_job(scan_job.id)
    assert job.status == ScanStatus.CANCELLED
