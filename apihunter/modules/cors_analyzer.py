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

        findings: list[Finding] = []
        attacker_origin = "https://example-attacker.invalid"
        
        # Probe subset of endpoints (first 3) to balance budget
        for ep in spec.endpoints[:3]:
            result = await executor.probe(ep, extra_headers={"Origin": attacker_origin})
            if not result:
                continue
                
            acao = result.headers.get("access-control-allow-origin", "")
            acac = result.headers.get("access-control-allow-credentials", "").lower() == "true"
            
            # 1. No CORS headers
            if not acao:
                continue # Info level or not a finding

            # 2. Wildcard *
            if acao == "*":
                if acac:
                    findings.append(Finding(
                        check_type="cors",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        title="CORS wildcard with credentials",
                        detail=f"Endpoint {ep.path} sends ACAO: * and ACAC: true.",
                        remediation="Do not use wildcard with credentials.",
                        endpoint_path=ep.path,
                        endpoint_method=ep.method,
                    ))
                else:
                    findings.append(Finding(
                        check_type="cors",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        title="CORS wildcard origin",
                        detail=f"Endpoint {ep.path} sends ACAO: *.",
                        remediation="Avoid wildcard; whitelist specific origins.",
                        endpoint_path=ep.path,
                        endpoint_method=ep.method,
                    ))
            # 3. Reflected arbitrary origin
            elif acao == attacker_origin:
                sev = Severity.HIGH if acac else Severity.MEDIUM
                findings.append(Finding(
                    check_type="cors",
                    severity=sev,
                    confidence=Confidence.MEDIUM,
                    title="CORS reflects arbitrary Origin",
                    detail=f"Endpoint {ep.path} reflects Origin {attacker_origin!r} (ACAC: {acac}).",
                    remediation="Whitelist specific origins; do not reflect arbitrary Origin.",
                    endpoint_path=ep.path,
                    endpoint_method=ep.method,
                ))
            # 4. Specific origin (Normal policy) - do nothing
            else:
                pass
                
        return findings
