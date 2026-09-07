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
        ep = spec.endpoints[0]
        results = []
        for _ in range(6):
            r = await executor.probe(ep)
            if not r:
                break
            results.append(r)
            if r.status_code == 429:
                break
        if not results:
            return []
        has_429 = any(r.status_code == 429 for r in results)
        has_retry = any("retry-after" in r.headers for r in results)
        if has_429 or has_retry:
            return []
        # Only report if we actually sent 6 and none throttled — LOW heuristic
        if len(results) >= 6 and all(200 <= r.status_code < 400 for r in results):
            return [
                Finding(
                    check_type="rate_limit",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    title="No rate limiting observed (heuristic)",
                    detail=f"Endpoint {ep.path} allowed 6 rapid requests without 429/Retry-After — verify rate limiting manually.",
                    remediation="Enable rate limiting / throttling (e.g. 429 with Retry-After).",
                    endpoint_path=ep.path,
                    endpoint_method=ep.method,
                )
            ]
        return []
