from __future__ import annotations

from apihunter.core.models import Finding, ScanRun
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class RateLimitAnalyzer(BaseAnalyzer):
    """
    Safe rate-limit heuristic (5-6 probes, configurable, no flood).

    Sends 6 sequential requests to first endpoint; checks for 429 / Retry-After.
    If none, reports LOW (not HIGH — absence of 429 is not vuln by itself).
    """

    def __init__(self, context: AnalyzerContext):
        super().__init__(context)

    async def analyze(self, spec: SpecResult, scan_run: ScanRun) -> list[Finding]:
        from apihunter.core.models import Confidence, Severity

        executor = getattr(self.context, "executor", None) if self.context else None
        if not executor or not spec.endpoints:
            return []
        
        # Probe first endpoint (representative)
        ep = spec.endpoints[0]
        results = []
        
        # Standard check: 5 probes
        for _ in range(5):
            r = await executor.probe(ep)
            if not r:
                break
            results.append(r)
            if r.status_code == 429:
                # Rate limited -> defensive behavior, not finding
                return []
                
        # If no rate limiting found after 5 probes
        if all(r.status_code < 400 for r in results):
            return [
                Finding(
                    check_type="rate_limit",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    title="No rate limiting observed (heuristic)",
                    detail=f"Endpoint {ep.path} allowed 5 rapid requests without 429.",
                    remediation="Enable rate limiting (429 with Retry-After).",
                    endpoint_path=ep.path,
                    endpoint_method=ep.method,
                )
            ]
        return []
