"""
Contract 03 & 08 Base Assessment Engine Plugin Interface.
"""

from abc import ABC, abstractmethod
from typing import List, Callable, Awaitable
from app.core.models import Target, Finding, ScanConfig, LogLevel

# Callback signatures for asynchronous telemetry streaming
LogCallback = Callable[[LogLevel, str], Awaitable[None]]
ProgressCallback = Callable[[int, str], Awaitable[None]]
FindingCallback = Callable[[Finding], Awaitable[None]]


class BaseAssessmentEngine(ABC):
    """
    Standardized abstract interface contract for all security assessment engines.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Unique machine identifier of the engine (e.g. 'network', 'web_dast', 'code_sast', 'infra_iac', 'cicd_audit').
        """
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """
        Human-readable title of the engine for UI dashboards and reports.
        """
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """
        Comprehensive description of the security domains and checks evaluated by this engine.
        """
        pass

    @abstractmethod
    def is_applicable(self, target: Target) -> bool:
        """
        Validates if this engine can execute against the provided target type.
        """
        pass

    @abstractmethod
    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        emit_finding: FindingCallback,
    ) -> List[Finding]:
        """
        Executes the assessment logic asynchronously.

        Args:
            target: The validated target configuration (URL, IP, or path).
            config: Scan execution options (timeout, rate limit, headers, etc.).
            emit_log: Async callable to stream live log events.
            emit_progress: Async callable to stream engine progress and stage updates.
            emit_finding: Async callable to stream findings immediately when confirmed.

        Returns:
            List of normalized Finding objects.
        """
        pass
