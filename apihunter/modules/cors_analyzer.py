from __future__ import annotations

from apihunter.core.models import Finding, ScanRun
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class CORSAnalyzer(BaseAnalyzer):
    """
    Active CORS misconfiguration check (safe).

    Sends Origin: https://example-attacker.invalid and checks:
    - reflected origin
    - wildcard + credentials
    """

    def __init__(self, context: AnalyzerContext):
        super().__init__(context)

    async def analyze(self, spec: SpecResult, scan_run: ScanRun) -> list[Finding]:
        from apihunter.core.models import Confidence, Severity

        executor = getattr(self.context, "executor", None) if self.context else None
        if not executor or not spec.endpoints:
            return []
        # Probe first endpoint as representative (budget safe)
        ep = spec.endpoints[0]
        attacker_origin = "https://example-attacker.invalid"
        result = await executor.probe(ep, extra_headers={"Origin": attacker_origin})
        if not result:
            return []
        findings: list[Finding] = []
        acao = result.headers.get("access-control-allow-origin", "")
        acac = result.headers.get("access-control-allow-credentials", "")
        # Reflected arbitrary origin
        if acao == attacker_origin:
            sev = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
            findings.append(
                Finding(
                    check_type="cors",
                    severity=sev,
                    confidence=Confidence.MEDIUM,
                    title="CORS reflects arbitrary Origin",
                    detail=f"Endpoint {ep.path} reflects Origin {attacker_origin!r} (Allow-Credentials: {acac or 'missing'}).",
                    remediation="Whitelist specific origins; do not reflect arbitrary Origin.",
                    endpoint_path=ep.path,
                    endpoint_method=ep.method,
                )
            )
        elif acao == "*":
            sev = Severity.HIGH if acac.lower() == "true" else Severity.LOW
            if acac.lower() == "true":
                findings.append(
                    Finding(
                        check_type="cors",
                        severity=sev,
                        confidence=Confidence.HIGH,
                        title="CORS wildcard with credentials",
                        detail=f"Endpoint {ep.path} sends ACAO: * with Allow-Credentials: true.",
                        remediation="Do not use wildcard with credentials.",
                        endpoint_path=ep.path,
                        endpoint_method=ep.method,
                    )
                )
        return findings
