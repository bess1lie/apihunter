from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

from apihunter.core.http_client import HttpClient
from apihunter.core.scope import Scope
from apihunter.parser.models import SpecEndpoint


@dataclass(frozen=True)
class ProbeResult:
    """Result of a single active probe."""

    url: str
    method: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: int
    endpoint: SpecEndpoint | None = None


def _substitute_path_params(path: str) -> str:
    """Replace {param} with safe dummy values."""

    # Use 1 for id-like params, test for others
    def repl(m: re.Match[str]) -> str:
        name = m.group(1).lower()
        if any(k in name for k in ("id", "uuid", "guid")):
            return "1"
        if "page" in name:
            return "1"
        return "test"

    return re.sub(r"\{([^}]+)\}", repl, path)


class Executor:
    """Active HTTP executor for analyzers.

    Wraps :class:`HttpClient` with endpoint building, scope checks,
    and safe limits. Respects:

    - scope.is_in_scope()
    - HttpClient private IP blocking, redirect policy, 2MB limit
    - max_requests guard
    """

    def __init__(
        self,
        client: HttpClient,
        scope: Scope | None = None,
        target: str | None = None,
        max_requests: int = 20,
        timeout: float = 10.0,
    ) -> None:
        self.client = client
        self.scope = scope
        self.target = target
        self.max_requests = max_requests
        self.timeout = timeout
        self._request_count = 0

    def _check_budget(self) -> bool:
        return self._request_count < self.max_requests

    def build_url(self, endpoint_path: str) -> str | None:
        """Build absolute URL for *endpoint_path* using target base."""
        if not self.target:
            return None
        # Use target as base, strip to host
        base = self.target.rstrip("/")
        # Substitute path params
        sub_path = _substitute_path_params(endpoint_path)
        # Ensure single slash
        return urljoin(base + "/", sub_path.lstrip("/"))

    async def probe(
        self,
        endpoint: SpecEndpoint,
        extra_headers: dict[str, str] | None = None,
        method: str | None = None,
        body: Any | None = None,
    ) -> ProbeResult | None:
        """Probe *endpoint* with optional extra_headers/body.

        Returns None if scope blocks, budget exceeded, or request fails.
        """
        if not self._check_budget():
            return None
        url = self.build_url(endpoint.path)
        if not url:
            return None
        if self.scope and not self.scope.is_in_scope(url):
            return None
        m = (method or endpoint.method or "GET").upper()
        headers: dict[str, str] = {}
        if extra_headers:
            headers.update(extra_headers)

        self._request_count += 1
        start = time.monotonic()
        try:
            # HttpClient handles its own validation, redirects, size limit
            resp = await self.client.request(m, url, headers=headers, json=body if body else None)
        except Exception:
            return None
        elapsed = int((time.monotonic() - start) * 1000)
        # Normalize headers to lower-case keys for easy checks
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        return ProbeResult(
            url=url,
            method=m,
            status_code=resp.status_code,
            headers=hdrs,
            body=resp.content or b"",
            elapsed_ms=elapsed,
            endpoint=endpoint,
        )

    async def probe_raw(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> ProbeResult | None:
        """Probe arbitrary URL (for CORS, etc.) with scope check."""
        if not self._check_budget():
            return None
        if self.scope and not self.scope.is_in_scope(url):
            return None
        self._request_count += 1
        start = time.monotonic()
        try:
            resp = await self.client.request(method.upper(), url, headers=headers or {})
        except Exception:
            return None
        elapsed = int((time.monotonic() - start) * 1000)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        return ProbeResult(
            url=url,
            method=method.upper(),
            status_code=resp.status_code,
            headers=hdrs,
            body=resp.content or b"",
            elapsed_ms=elapsed,
            endpoint=None,
        )
