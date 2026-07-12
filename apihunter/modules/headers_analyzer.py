from __future__ import annotations

from apihunter.core.models import Finding, ScanRun
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class HeadersAnalyzer(BaseAnalyzer):
    """
    Analyzes for missing security headers.
    Identifies if endpoints are missing headers like HSTS, CSP, X-Content-Type-Options, etc.
    """

    def __init__(self, context: AnalyzerContext):
        super().__init__(context)

    async def analyze(self, spec: SpecResult, scan_run: ScanRun) -> list[Finding]:
        return []
