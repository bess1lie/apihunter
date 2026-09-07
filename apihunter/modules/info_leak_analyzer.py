from __future__ import annotations

from apihunter.core.models import Finding, ScanRun
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class InfoLeakAnalyzer(BaseAnalyzer):
    """
    Analyzes for information disclosure via spec metadata.

    Passive heuristics:
    - Debug / test endpoints exposed (/debug, /test, /status, /admin)
    - Verbose example responses containing stacktrace / exception keywords
    """

    def __init__(self, context: AnalyzerContext):
        super().__init__(context)

    async def analyze(self, spec: SpecResult, scan_run: ScanRun) -> list[Finding]:
        from apihunter.core.models import Confidence, Severity

        findings: list[Finding] = []
        verbose_keywords = ["stacktrace", "traceback", "exception", "java.lang", "at org.", "Traceback"]
        # Active: probe first endpoint for leak markers in body
        executor = getattr(self.context, "executor", None) if self.context else None
        if executor and spec.endpoints:
            ep = spec.endpoints[0]
            result = await executor.probe(ep)
            if result and result.body:
                body_txt = result.body.decode(errors="ignore")
                leak_markers = [
                    "Traceback",
                    "stacktrace",
                    "java.lang.",
                    "at org.",
                    "SQLSTATE",
                    "ORA-",
                    "/var/www",
                    "/usr/local",
                    "internal server error",
                    "debug mode",
                ]
                for mk in leak_markers:
                    if mk.lower() in body_txt.lower():
                        findings.append(
                            Finding(
                                check_type="info_leak",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.LOW,
                                title="Information disclosure in response",
                                detail=f"Endpoint {ep.path} response contains {mk!r} — possible leak.",
                                remediation="Sanitize error responses; disable debug in production.",
                                endpoint_path=ep.path,
                                endpoint_method=ep.method,
                            )
                        )
                        break
        for ep in spec.endpoints:
            lower_path = ep.path.lower()
            if any(kw in lower_path for kw in ["debug", "trace", "admin", "test"] if len(kw) > 3) and lower_path not in ("/health",):
                # Only flag obvious debug paths
                if "/debug" in lower_path or "/admin" in lower_path or lower_path.endswith("/test"):
                    findings.append(
                        Finding(
                            check_type="info_leak",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            title="Potential debug/admin endpoint exposed",
                            detail=f"Endpoint {ep.path} looks like a debug/admin path exposed in spec.",
                            remediation="Remove debug endpoints from production spec or protect with auth.",
                            endpoint_path=ep.path,
                            endpoint_method=ep.method,
                        )
                    )
            # Check response examples for verbose errors
            for code, desc in (ep.responses or {}).items():
                if isinstance(desc, str) and any(vk.lower() in desc.lower() for vk in verbose_keywords):
                    findings.append(
                        Finding(
                            check_type="info_leak",
                            severity=Severity.LOW,
                            confidence=Confidence.LOW,
                            title="Verbose error description",
                            detail=f"Endpoint {ep.path} response {code} may leak internals: {desc[:120]!r}",
                            remediation="Use generic error messages in production.",
                            endpoint_path=ep.path,
                            endpoint_method=ep.method,
                        )
                    )
                    break
        return findings
