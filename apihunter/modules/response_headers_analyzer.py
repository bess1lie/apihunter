from __future__ import annotations

from apihunter.core.models import Finding, ScanRun
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class ResponseHeadersAnalyzer(BaseAnalyzer):
    """
    Active response header checks via executor.

    Checks for missing HSTS (https), X-Content-Type-Options, X-Frame-Options, CSP, Server leaks.
    """

    def __init__(self, context: AnalyzerContext):
        super().__init__(context)

    async def analyze(self, spec: SpecResult, scan_run: ScanRun) -> list[Finding]:
        from apihunter.core.models import Confidence, Severity

        executor = getattr(self.context, "executor", None) if self.context else None
        if not executor or not spec.endpoints:
            return []
        ep = spec.endpoints[0]
        result = await executor.probe(ep)
        if not result:
            return []
        headers = result.headers
        findings: list[Finding] = []
        is_https = (executor.target or "").startswith("https://")  # type: ignore[union-attr]
        if is_https and "strict-transport-security" not in headers:
            findings.append(
                Finding(
                    check_type="headers",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    title="Missing HSTS header",
                    detail=f"Endpoint {ep.path} over https missing Strict-Transport-Security.",
                    remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    endpoint_path=ep.path,
                    endpoint_method=ep.method,
                )
            )
        if "x-content-type-options" not in headers:
            findings.append(
                Finding(
                    check_type="headers",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    title="Missing X-Content-Type-Options",
                    detail=f"Endpoint {ep.path} missing X-Content-Type-Options: nosniff.",
                    remediation="Add X-Content-Type-Options: nosniff",
                    endpoint_path=ep.path,
                    endpoint_method=ep.method,
                )
            )
        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            findings.append(
                Finding(
                    check_type="headers",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    title="Missing X-Frame-Options / CSP frame-ancestors",
                    detail=f"Endpoint {ep.path} missing clickjacking protection.",
                    remediation="Add X-Frame-Options: DENY or CSP frame-ancestors",
                    endpoint_path=ep.path,
                    endpoint_method=ep.method,
                )
            )
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        if server or powered:
            findings.append(
                Finding(
                    check_type="headers",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    title="Server header disclosure",
                    detail=f"Endpoint {ep.path} leaks Server: {server!r} X-Powered-By: {powered!r}",
                    remediation="Remove or obscure Server / X-Powered-By headers.",
                    endpoint_path=ep.path,
                    endpoint_method=ep.method,
                )
            )
        return findings
