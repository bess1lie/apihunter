from __future__ import annotations

from apihunter.core.models import Finding, ScanRun
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class CORSAnalyzer(BaseAnalyzer):
    """
    Active CORS misconfiguration check (safe).

    Sends Origin: https://example-attacker.invalid and checks:
    - wildcard * (INFO without creds, HIGH with creds)
    - reflected arbitrary origin (MEDIUM, check Vary)
    Evidence includes ACAO/ACAC/Vary/tested origin.
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
            acac_raw = result.headers.get("access-control-allow-credentials", "")
            acac = acac_raw.lower() == "true"
            vary = result.headers.get("vary", "")

            # 1. No CORS headers → no finding
            if not acao:
                continue

            evidence_base = f"Evidence: ACAO={acao!r} ACAC={acac_raw!r} Vary={vary!r} tested_origin={attacker_origin!r}"

            # 2. Wildcard *
            if acao == "*":
                if acac:
                    findings.append(
                        Finding(
                            check_type="cors",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            title="CORS wildcard with credentials",
                            detail=(  # noqa: E501
                                f"Endpoint {ep.path} sends ACAO: * and ACAC: true — any origin can read credentialed responses.\n"
                                f"{evidence_base}"
                            ),
                            remediation="Do not use wildcard with credentials.",
                            endpoint_path=ep.path,
                            endpoint_method=ep.method,
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_type="cors",
                            severity=Severity.INFO,
                            confidence=Confidence.MEDIUM,
                            title="CORS wildcard origin (info)",
                            detail=(  # noqa: E501
                                f"Endpoint {ep.path} sends ACAO: * without credentials — often intentional for public APIs.\n"
                                f"{evidence_base}"
                            ),
                            remediation="If not public, whitelist specific origins; otherwise no action needed.",
                            endpoint_path=ep.path,
                            endpoint_method=ep.method,
                        )
                    )
            # 3. Reflected arbitrary origin
            elif acao == attacker_origin:
                sev = Severity.HIGH if acac else Severity.MEDIUM
                findings.append(
                    Finding(
                        check_type="cors",
                        severity=sev,
                        confidence=Confidence.MEDIUM,
                        title="CORS reflects arbitrary Origin (heuristic)",
                        detail=(  # noqa: E501
                            f"Endpoint {ep.path} reflects arbitrary Origin {attacker_origin!r} (ACAC: {acac}). Check Vary.\n{evidence_base}"
                        ),
                        remediation="Whitelist specific origins; do not reflect arbitrary Origin.",
                        endpoint_path=ep.path,
                        endpoint_method=ep.method,
                    )
                )
            # 4. Specific origin (Normal policy) - do nothing
            else:
                pass

        return findings
