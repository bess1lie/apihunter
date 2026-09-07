from __future__ import annotations

from apihunter.core.models import Finding, ScanRun
from apihunter.modules.base import AnalyzerContext, BaseAnalyzer
from apihunter.parser.models import SpecResult


class InjectionAnalyzer(BaseAnalyzer):
    """
    Safe injection heuristic (no destructive payloads).

    For query/path params and JSON fields, sends harmless probe
    (e.g. "'\"") and compares response: 500 with SQL error fragment
    vs normal 200 → LOW.
    """

    def __init__(self, context: AnalyzerContext):
        super().__init__(context)

    async def analyze(self, spec: SpecResult, scan_run: ScanRun) -> list[Finding]:
        from apihunter.core.models import Confidence, Severity

        executor = getattr(self.context, "executor", None) if self.context else None
        if not executor or not spec.endpoints:
            return []
        # Find endpoint with query param
        target_ep = None
        for ep in spec.endpoints:
            for p in ep.parameters or []:
                name = getattr(p, "name", "") or ""
                loc = str(getattr(p, "location", "")).lower()
                if loc in ("query", "path") and name:
                    target_ep = ep
                    break
            if target_ep:
                break
        if not target_ep:
            return []
        # Probe normal vs probe with single quote
        import re

        base_path = target_ep.path
        # Build probe path: append harmless ' if query, else inject in path
        has_query = any(str(getattr(p, "location", "")).lower() == "query" for p in (target_ep.parameters or []))
        from urllib.parse import urljoin

        if not getattr(executor, "target", None):
            return []
        base = executor.target.rstrip("/")  # type: ignore[union-attr]
        # Normal
        normal_url = urljoin(base + "/", _sub_path(base_path))
        # Probe with '
        probe_path = base_path
        if has_query:
            # add ?q='
            sep = "&" if "?" in probe_path else "?"
            probe_path = probe_path + sep + "test=%27"
        else:
            probe_path = re.sub(r"\{[^}]+\}", "1%27", probe_path, count=1)
        probe_url = urljoin(base + "/", _sub_path(probe_path))
        r_normal = await executor.probe_raw(normal_url, method=target_ep.method)
        r_probe = await executor.probe_raw(probe_url, method=target_ep.method)
        if not r_normal or not r_probe:
            return []
        # Heuristic: probe returns 500 with SQL fragment while normal is 200
        sql_fragments = ["sql", "syntax", "sqlite", "postgres", "mysql", "ora-", "query failed"]
        probe_body = (r_probe.body or b"").decode(errors="ignore").lower()
        normal_body = (r_normal.body or b"").decode(errors="ignore").lower()
        if r_probe.status_code == 500 and 200 <= r_normal.status_code < 300 and any(s in probe_body for s in sql_fragments):
            if not any(s in normal_body for s in sql_fragments):
                return [
                    Finding(
                        check_type="injection",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        title="Possible SQL error in response (heuristic)",
                        detail=f"Endpoint {target_ep.path} probe with ' returned 500 with SQL fragment — manual verification needed.",
                        remediation="Use parameterized queries; sanitize inputs.",
                        endpoint_path=target_ep.path,
                        endpoint_method=target_ep.method,
                    )
                ]
        return []


def _sub_path(p: str) -> str:
    import re

    return re.sub(r"\{[^}]+\}", "1", p)
