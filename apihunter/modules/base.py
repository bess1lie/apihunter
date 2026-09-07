from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from apihunter.core.models import Finding, ScanRun
from apihunter.parser.models import SpecResult


@dataclass(frozen=True)
class AnalyzerContext:
    """Context passed to every analyzer.

    Attributes
    ----------
    target:
        Original scan target (e.g. https://api.example.com).
    scope:
        Scope object for is_in_scope checks.
    client:
        Shared HttpClient for active probes (None for passive analyzers).
    executor:
        Optional :class:`Executor` for controlled active probes.
    """

    target: str | None = None
    scope: Any | None = None
    client: Any | None = None
    executor: Any | None = None


class BaseAnalyzer(ABC):
    """Abstract base class for all analyzers."""

    def __init__(self, context: AnalyzerContext | None = None) -> None:
        self.context = context

    @abstractmethod
    async def analyze(self, spec: SpecResult, scan_run: ScanRun) -> list[Finding]:
        """Perform analysis on a given specification."""
        pass
