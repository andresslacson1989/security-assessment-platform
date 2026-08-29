"""
Engine plugin interface and registration package.
"""

from app.engines.base import (
    BaseAssessmentEngine,
    LogCallback,
    ProgressCallback,
    FindingCallback,
)

__all__ = [
    "BaseAssessmentEngine",
    "LogCallback",
    "ProgressCallback",
    "FindingCallback",
]
