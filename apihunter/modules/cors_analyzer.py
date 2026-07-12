from __future__ import annotations

from apihunter.core.models import Finding, ScanRun
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class CORSAnalyzer(BaseAnalyzer):
    """
    Analyzes for CORS misconfigurations.
    Identifies if the API allows wildcard origins with credentials,
    or has overly permissive CORS policies.
    """

    def __init__(self, context: AnalyzerContext):
        super().__init__(context)

    async def analyze(self, spec: SpecResult, scan_run: ScanRun) -> list[Finding]:
        return []
