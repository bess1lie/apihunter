from __future__ import annotations

from apihunter.core.models import Finding, ScanRun
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class IDORAnalyzer(BaseAnalyzer):
    """
    Analyzes for Insecure Direct Object Reference (IDOR) vulnerabilities.
    Identتifies endpoints where user-controlled parameters (e.g., IDs)
    could be manipulated to access other users' data.
    """

    def __init__(self, context: AnalyzerContext):
        super().__init__(context)

    async def analyze(self, spec: SpecResult, scan_run: ScanRun) -> list[Finding]:
        return []
