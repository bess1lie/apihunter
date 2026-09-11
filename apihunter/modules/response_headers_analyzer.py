from __future__ import annotations

from apihunter.core.models import Finding, ScanRun
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class ResponseHeadersAnalyzer(BaseAnalyzer):
    """
    Active response header checks via executor (heuristic + direct facts).

    - HSTS: only for https target (not http — no finding on http)
    - X-CTO / X-Frame / CSP: LOW heuristics
    - Server disclosure: LOW/HIGH direct fact with header values as evidence
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
                    title="Missing HSTS header (https)",
                    detail=(
                        f"Endpoint {ep.path} over https missing Strict-Transport-Security — direct fact, not vuln by itself.\n"
                        f"Evidence: target={executor.target} hsts_missing=true headers_present={list(headers.keys())[:5]}"
                    ),
                    remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    endpoint_path=ep.path,
                    endpoint_method=ep.method,
                )
            )
        # Only report missing X-CTO if we actually got a response (headers dict exists)
        if "x-content-type-options" not in headers and result.headers:
            findings.append(
                Finding(
                    check_type="headers",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    title="Missing X-Content-Type-Options",
                    detail=(
                        f"Endpoint {ep.path} missing X-Content-Type-Options: nosniff.\n"
                        f"Evidence: header_x-content-type-options=missing headers={list(headers.keys())[:5]}"
                    ),
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
                    detail=(f"Endpoint {ep.path} missing clickjacking protection.\nEvidence: x-frame-options=missing csp=missing"),
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
                    title="Server header disclosure (direct fact)",
                    detail=(
                        f"Endpoint {ep.path} discloses Server/X-Powered-By — configuration fact, not vulnerability.\n"
                        f"Evidence: Server={server!r} X-Powered-By={powered!r}"
                    ),
                    remediation="Remove or obscure Server / X-Powered-By headers.",
                    endpoint_path=ep.path,
                    endpoint_method=ep.method,
                )
            )
        return findings
