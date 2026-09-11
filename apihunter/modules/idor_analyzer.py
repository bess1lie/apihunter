from __future__ import annotations

from apihunter.core.models import Finding, ScanRun
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class IDORAnalyzer(BaseAnalyzer):
    """
    BOLA/IDOR heuristic — LOW confidence only (no ownership context).

    For endpoints with object-like path params ({id}, {userId}, ...):
    - probe id=1 and id=2
    - compare status/body size
    - heuristic only: confirmed bypass requires two different auth contexts
      (victim vs attacker token) — this analyzer has no second token.
    Confidence is always LOW; severity downgraded to LOW for 200 vs 200 case.
    """

    OBJECT_PARAM_HINTS = ("id", "user", "account", "order", "profile", "org", "team")

    def __init__(self, context: AnalyzerContext):
        super().__init__(context)

    async def analyze(self, spec: SpecResult, scan_run: ScanRun) -> list[Finding]:
        from apihunter.core.models import Confidence, Severity

        executor = getattr(self.context, "executor", None) if self.context else None
        # Fallback passive heuristic if no executor (spec-only)
        if not executor:
            findings: list[Finding] = []
            for ep in spec.endpoints:
                if "{" in ep.path and "}" in ep.path:
                    if any(h in ep.path.lower() for h in self.OBJECT_PARAM_HINTS):
                        findings.append(
                            Finding(
                                check_type="idor",
                                severity=Severity.LOW,
                                confidence=Confidence.LOW,
                                title="Potential BOLA/IDOR (heuristic) — object reference",
                                detail=(
                                    f"Endpoint {ep.path} uses object-like path param — review for BOLA/IDOR manually.\n"
                                    f"Evidence: path={ep.path} param_hint=object-id heuristic_only=true\n"
                                    f"Caveat: requires two auth contexts (different users) to confirm ownership bypass."
                                ),
                                remediation="Enforce authorization checks on object access; use indirect references.",
                                endpoint_path=ep.path,
                                endpoint_method=ep.method,
                            )
                        )
            return findings

        # Active: probe two IDs for first few candidate endpoints (budget-aware)
        findings = []
        probed = 0
        for ep in spec.endpoints:
            if probed >= 3:
                break
            if "{" not in ep.path:
                continue
            lower = ep.path.lower()
            if not any(h in lower for h in self.OBJECT_PARAM_HINTS):
                continue
            # Build URLs for id=1 and id=999999
            url1 = self._build_url_for_id(ep.path, "1")
            url2 = self._build_url_for_id(ep.path, "2")
            if not url1 or not url2:
                continue
            # Resolve base via executor.target
            if not getattr(executor, "target", None):
                continue
            from urllib.parse import urljoin

            base = executor.target.rstrip("/")  # type: ignore[union-attr]
            full1 = urljoin(base + "/", url1.lstrip("/"))
            full2 = urljoin(base + "/", url2.lstrip("/"))
            if executor.scope and (not executor.scope.is_in_scope(full1) or not executor.scope.is_in_scope(full2)):
                continue
            r1 = await executor.probe_raw(full1, method=ep.method)
            r2 = await executor.probe_raw(full2, method=ep.method)
            probed += 1
            if not r1 or not r2:
                continue
            # Both 200 but bodies differ -> possible IDOR/BOLA (heuristic, LOW/LOW)
            if r1.status_code == 200 and r2.status_code == 200:
                b1, b2 = r1.body or b"", r2.body or b""
                # Identical bodies → no finding (likely static / same object)
                if b1 == b2:
                    continue
                # Downgrade: any 200 vs 200 without ownership proof is LOW
                len1, len2 = len(b1), len(b2)
                diff = abs(len1 - len2)
                similar = diff < max(len1, len2) * 0.5 if max(len1, len2) else False
                title = "Potential BOLA/IDOR (heuristic)" if similar else "Object reference with differing responses (heuristic)"
                detail = (
                    f"Endpoint {ep.path} returned 200 for both id=1 and id=2 without ownership context — manual verification needed.\n"
                    f"Evidence: status1=200 status2=200 body_len1={len1} body_len2={len2} diff={diff} similar_size={similar}\n"
                    f"Heuristic only: requires two auth contexts (victim vs attacker) to confirm ownership bypass."
                )
                findings.append(
                    Finding(
                        check_type="idor",
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        title=title,
                        detail=detail,
                        remediation="Verify authorization on object access; test with two users' tokens.",  # noqa: E501
                        endpoint_path=ep.path,
                        endpoint_method=ep.method,
                    )
                )
        return findings

    def _build_url_for_id(self, path: str, val: str) -> str | None:
        import re

        def repl(m: re.Match[str]) -> str:
            return val

        return re.sub(r"\{[^}]+\}", repl, path)
