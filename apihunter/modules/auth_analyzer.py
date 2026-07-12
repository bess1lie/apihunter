from __future__ import annotations

from apihunter.core.models import Confidence, Finding, ScanRun, Severity
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class AuthAnalyzer(BaseAnalyzer):
    """
    Analyte for broken or missing authentication.
    Identifies endpoints that should require authentication but do not,
    or endpoints that respond with 200 to unauthenticated requests.
    """

    def __init__(self, context: AnalyzerContext):
        super().__init__(context)

    async def analyze(self, spec: SpecResult, scan_run: ScanRun) -> list[Finding]:
        findings = []

        for endpoint in spec.endpoints:
            # If the spec says auth is required but no auth schemes are provided
            if endpoint.auth_required and not endpoint.auth_schemes:
                findings.append(
                    Finding(
                        check_type="auth",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        title="Missing Authentication Scheme",
                        detail=(
                            f"Endpoint {endpoint.path} requires authentication but no schemes are defined in the spec."
                        ),
                        remediation="Configure security schemes in the OpenAPI specification.",
                    )
                )

            # If the spec says auth is NOT required, but the endpoint is sensitive
            # (Heuristic: paths containing 'admin', 'config', 'settings', 'user', 'account')
            sensitive_keywords = ["admin", "config", "settings", "user", "account", "profile", "auth"]
            is_sensitive = any(kw in endpoint.path.lower() for kw in sensitive_keywords)

            if not endpoint.auth_required and is_sensitive:
                findings.append(
                    Finding(
                        check_type="auth",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        title="Potentially Unauthenticated Sensitive Endpoint",
                        detail=f"Endpoint {endpoint.path} appears to be sensitive but does not require authentication.",
                        remediation="Enable authentication for this endpoint.",
                    )
                )

        return findings
