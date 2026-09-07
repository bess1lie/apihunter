from __future__ import annotations

from apihunter.core.models import Finding, ScanRun
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class HeadersAnalyzer(BaseAnalyzer):
    """
    DEPRECATED alias for SpecSecurityAnalyzer (passive OpenAPI checks).

    For real HTTP response header checks (HSTS, CSP, X-Frame-Options) use
    the future ResponseHeadersAnalyzer (active via executor).
    Kept for backward compatibility.
    """

    def __init__(self, context: AnalyzerContext):
        super().__init__(context)
        from apihunter.modules.spec_security_analyzer import SpecSecurityAnalyzer

        self._impl = SpecSecurityAnalyzer(context)

    async def analyze(self, spec: SpecResult, scan_run: ScanRun) -> list[Finding]:
        return await self._impl.analyze(spec, scan_run)
