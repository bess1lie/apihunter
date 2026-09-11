from __future__ import annotations

from apihunter.core.models import Finding, ScanRun
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class SpecSecurityAnalyzer(BaseAnalyzer):
    """
    Passive OpenAPI security configuration checks (no network).

    Checks:
    - servers[] using plain http://
    - auth_required but no securitySchemes defined

    This is NOT an HTTP response header analyzer. For real response
    headers (HSTS, CSP, X-Frame-Options) see `ResponseHeadersAnalyzer`
    (active probe via executor).
    """

    def __init__(self, context: AnalyzerContext):
        super().__init__(context)

    async def analyze(self, spec: SpecResult, scan_run: ScanRun) -> list[Finding]:
        from apihunter.core.models import Confidence, Severity

        findings: list[Finding] = []
        raw = spec.raw_spec or {}
        for srv in raw.get("servers", []):
            url = srv.get("url", "")
            if url.startswith("http://"):
                findings.append(
                    Finding(
                        check_type="spec_security",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        title="Insecure server URL (http) — direct config fact",
                        detail=(
                            f"Server URL {url!r} uses plain http — configuration fact, not confirmed vulnerability.\n"
                            f"Evidence: server_url={url!r} scheme=http"
                        ),
                        remediation="Use https:// and set Strict-Transport-Security.",
                        endpoint_path=None,
                        endpoint_method=None,
                    )
                )
                break
        components = raw.get("components", {})
        if not components.get("securitySchemes") and any(e.auth_required for e in spec.endpoints):
            findings.append(
                Finding(
                    check_type="spec_security",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    title="No securitySchemes defined (direct config fact)",
                    detail=(
                        "Spec requires auth but defines no securitySchemes — direct spec fact, not vulnerability.\n"
                        "Evidence: components.securitySchemes=missing auth_required_endpoints>0"
                    ),
                    remediation="Define components/securitySchemes (JWT, OAuth2, etc.).",
                    endpoint_path=None,
                    endpoint_method=None,
                )
            )
        return findings


# Backward compatibility: old name used in registry/tests
HeadersAnalyzer = SpecSecurityAnalyzer
