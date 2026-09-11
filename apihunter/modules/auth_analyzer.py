from __future__ import annotations

from apihunter.core.models import Confidence, Finding, ScanRun, Severity
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class AuthAnalyzer(BaseAnalyzer):
    """
    Passive + active authentication checks.

    Passive:
    - missing securitySchemes when auth_required → HIGH/HIGH (config fact)
    - sensitive path without auth (heuristic) → LOW/LOW — path alone is not vuln

    Active (executor):
    - probe without credentials; 2xx while spec says auth_required →
      heuristic auth bypass, not confirmed vuln (needs real token test).
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
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        title="Potentially Unauthenticated Sensitive Endpoint (heuristic)",
                        detail=(
                            f"Endpoint {endpoint.path} appears sensitive but spec does not mark it auth_required.\n"
                            f"Evidence: path={endpoint.path} auth_required=false sensitive_keyword_match=true\n"
                            f"Caveat: public endpoints (e.g. /users) may be intentionally unauthenticated — verify spec auth model."
                        ),
                        remediation="Verify whether endpoint intentionally public; enable authentication if it exposes sensitive data.",
                        endpoint_path=endpoint.path,
                        endpoint_method=endpoint.method,
                    )
                )

        # Active probe if executor available
        executor = getattr(self.context, "executor", None) if self.context else None
        if executor:
            # Extract bearer token from scope if configured (env-expanded, never logged)
            bearer_token: str | None = None
            scope_obj = getattr(self.context, "scope", None) if self.context else None
            if scope_obj is not None:
                if hasattr(scope_obj, "get_bearer_token"):
                    try:
                        bearer_token = scope_obj.get_bearer_token()  # type: ignore[no-redef]
                    except Exception:
                        bearer_token = None
                else:
                    bearer_token = getattr(scope_obj, "bearer_token", None)
                if bearer_token is not None and not isinstance(bearer_token, str):
                    bearer_token = str(bearer_token)
                if bearer_token is not None and not bearer_token.strip():
                    bearer_token = None

            for endpoint in spec.endpoints:
                if not endpoint.auth_required:
                    continue
                # Token-aware comparison: two probes (unauth + auth) when token configured
                if bearer_token:
                    unauth_result = await executor.probe(endpoint)
                    if not unauth_result:
                        continue
                    # Only send credentials to in-scope target (executor checks scope)
                    auth_result = await executor.probe(endpoint, extra_headers={"Authorization": f"Bearer {bearer_token}"})
                    if not auth_result:
                        # Fallback to single-probe logic if auth probe blocked/budget
                        if 200 <= unauth_result.status_code < 300:
                            body_len = len(unauth_result.body or b"")
                            findings.append(
                                Finding(
                                    check_type="auth",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.MEDIUM,
                                    title="Potential Authentication Bypass (heuristic)",  # noqa: E501
                                    detail=(
                                        f"Endpoint {endpoint.path} ({endpoint.method}) returned {unauth_result.status_code} "
                                        f"without credentials while spec says auth_required=true — possible bypass.\n"
                                        f"Evidence: method={endpoint.method} endpoint={endpoint.path} auth_required=true "
                                        f"unauthenticated_status={unauth_result.status_code} authenticated_status=unknown "
                                        f"unauthenticated_body_len={body_len} authenticated_body_len=unknown"
                                    ),
                                    remediation="Verify endpoint enforces authentication; retest with valid/invalid tokens manually.",
                                    endpoint_path=endpoint.path,
                                    endpoint_method=endpoint.method,
                                )
                            )
                        continue

                    unauth_status = unauth_result.status_code
                    auth_status = auth_result.status_code
                    unauth_len = len(unauth_result.body or b"")
                    auth_len = len(auth_result.body or b"")

                    # Case: unauth 401/403 → properly protected (whether auth 2xx or 401/403) → no finding
                    if unauth_status in (401, 403):
                        continue
                    # Case: unauth 2xx and auth 2xx → heuristic bypass (both succeed without and with token)
                    if 200 <= unauth_status < 300 and 200 <= auth_status < 300:
                        findings.append(
                            Finding(
                                check_type="auth",
                                severity=Severity.HIGH,
                                confidence=Confidence.MEDIUM,
                                title="Potential Authentication Bypass (heuristic)",  # noqa: E501
                                detail=(
                                    f"Endpoint {endpoint.path} ({endpoint.method}) accepts unauthenticated request "
                                    f"despite spec auth_required=true (both unauth and auth return 2xx) — heuristic, not confirmed vuln.\n"
                                    f"Evidence: method={endpoint.method} endpoint={endpoint.path} auth_required=true "
                                    f"unauthenticated_status={unauth_status} authenticated_status={auth_status} "
                                    f"unauthenticated_body_len={unauth_len} authenticated_body_len={auth_len}"
                                ),
                                remediation="Ensure endpoint enforces authentication; manual verification required.",  # noqa: E501
                                endpoint_path=endpoint.path,
                                endpoint_method=endpoint.method,
                            )
                        )
                    # Case: unauth 2xx and auth 401/403 → ambiguous (token rejected but unauth succeeds)
                    elif 200 <= unauth_status < 300 and auth_status in (401, 403):
                        findings.append(
                            Finding(
                                check_type="auth",
                                severity=Severity.LOW,
                                confidence=Confidence.LOW,
                                title="Ambiguous authentication result (heuristic)",  # noqa: E501
                                detail=(
                                    f"Endpoint {endpoint.path} ({endpoint.method}) returned 2xx without token but "
                                    f"{auth_status} with token — ambiguous, not automatically HIGH. Diagnostic only.\n"
                                    f"Evidence: method={endpoint.method} endpoint={endpoint.path} auth_required=true "
                                    f"unauthenticated_status={unauth_status} authenticated_status={auth_status} "
                                    f"unauthenticated_body_len={unauth_len} authenticated_body_len={auth_len}"
                                ),
                                remediation="Investigate auth logic; token may be invalid — retest with known-valid token.",  # noqa: E501
                                endpoint_path=endpoint.path,
                                endpoint_method=endpoint.method,
                            )
                        )
                    # Other unauth statuses (e.g. 500, 404) → no bypass finding
                    else:
                        continue
                else:
                    # No token configured — single unauth probe (backward compatible)
                    result = await executor.probe(endpoint)
                    if not result:
                        continue
                    if 200 <= result.status_code < 300:
                        body_len = len(result.body or b"")
                        findings.append(
                            Finding(
                                check_type="auth",
                                severity=Severity.HIGH,
                                confidence=Confidence.MEDIUM,
                                title="Potential Authentication Bypass (heuristic)",  # noqa: E501
                                detail=(
                                    f"Endpoint {endpoint.path} ({endpoint.method}) returned {result.status_code} "
                                    f"without credentials (spec says auth_required=true) — possible auth bypass, verify manually.\n"
                                    f"Evidence: method={endpoint.method} endpoint={endpoint.path} auth_required=true "
                                    f"unauthenticated_status={result.status_code} authenticated_status=unknown "
                                    f"unauthenticated_body_len={body_len} authenticated_body_len=unknown"
                                ),
                                remediation="Ensure endpoint enforces authentication and returns 401/403 for anonymous. Retest.",  # noqa: E501
                                endpoint_path=endpoint.path,
                                endpoint_method=endpoint.method,
                            )
                        )
                    elif result.status_code in (401, 403):
                        continue

        return findings
