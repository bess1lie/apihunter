from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from apihunter.core.models import Finding, ScanRun
from apihunter.parser.models import SpecResult


@dataclass(frozen=True)
class AnalyzerContext:
    """Context for an analyzer, potentially including session info or tools."""

    pass


class BaseAnalyzer(ABC):
    """Abstract base class for all analyzers."""

    def __init__(self, context: AnalyzerContext | None = None) -> None:
        self.context = context

    @abstractmethod
    async def analyze(self, spec: SpecResult, scan_run: ScanRun) -> list[Finding]:
        """Perform analysis on a given specification."""
        pass
