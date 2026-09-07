from __future__ import annotations

from apihunter.core.models import Confidence, Finding, ScanRun, Severity
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class AuthAnalyzer(BaseAnalyzer):
    """
    Passive + active authentication checks.

    Passive (always):
    - missing securitySchemes when auth_required
    - sensitive path without auth (heuristic)

    Active (when executor in context):
    - probe endpoint without credentials; if 2xx while spec says
      auth_required → HIGH (auth bypass candidate, not confirmed vuln).
    """

    def __init__(self, context: AnalyzerContext):
        super().__init__(context)

    async def analyze(self, spec: SpecResult, scan_run: ScanRun) -> list[Finding]:
        findings = []

        for endpoint in spec.endpoints:
            if endpoint.auth_required and not endpoint.auth_schemes:
                findings.append(
                    Finding(
                        check_type="auth",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        title="Missing Authentication Scheme",
                        detail=(f"Endpoint {endpoint.path} requires authentication but no schemes are defined in the spec."),
                        remediation="Configure security schemes in the OpenAPI specification.",
                        endpoint_path=endpoint.path,
                        endpoint_method=endpoint.method,
                    )
                )

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
                        endpoint_path=endpoint.path,
                        endpoint_method=endpoint.method,
                    )
                )

        # Active probe if executor available
        executor = getattr(self.context, "executor", None) if self.context else None
        if executor:
            for endpoint in spec.endpoints:
                if not endpoint.auth_required:
                    continue
                # Only probe a small subset to stay safe (first 5 auth endpoints)
                # executor has budget, so it will auto-limit
                result = await executor.probe(endpoint)
                if not result:
                    continue
                # Heuristic: 2xx without auth while spec says auth → suspicious
                if 200 <= result.status_code < 300:
                    findings.append(
                        Finding(
                            check_type="auth",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            title="Endpoint accessible without authentication",
                            detail=(
                                f"Endpoint {endpoint.path} ({endpoint.method}) returned {result.status_code} "
                                f"without credentials (spec says auth required) — possible auth bypass, verify manually."
                            ),
                            remediation="Ensure endpoint enforces authentication and returns 401/403 for anonymous.",
                            endpoint_path=endpoint.path,
                            endpoint_method=endpoint.method,
                        )
                    )
                elif result.status_code in (401, 403):
                    # Correctly protected — no finding
                    continue

        return findings
