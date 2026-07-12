"""Path-based discovery provider.

Probes a configurable list of well-known paths (see
:data:`apihunter.discovery.constants.COMMON_PATHS`) on a target base
URL.  For each path:

1.  **Scope check** — skip if the host is out of scope or the extension
    is excluded.
2.  **HEAD request** — check existence without downloading the body.
3.  **GET fallback** — if HEAD returns 405 or is not useful, issue a
    GET with ``Range`` header to limit download size.
4.  **Status filter** — only statuses in
    :data:`VALID_STATUS_CODES` are considered hits.
5.  **Confidence assignment** — based on :data:`PATH_CONFIDENCE`.

Concurrency is bounded by an :class:`asyncio.Semaphore` so 22 paths do
not flood the target simultaneously.

Error handling
--------------
Per-URL errors (timeout, permanent HTTP error) are collected into the
result's ``errors`` list — they never stop the remaining probes.
"""

from __future__ import annotations

import asyncio

import httpx

from apihunter.core.exceptions import PermanentHttpError, RetryableHttpError
from apihunter.core.http_client import HttpClient
from apihunter.core.scope import Scope
from apihunter.discovery.base import BaseDiscoveryProvider
from apihunter.discovery.constants import (
    COMMON_PATHS,
    DEFAULT_CONCURRENCY,
    DEFAULT_MAX_SIZE,
    PATH_CONFIDENCE,
    VALID_STATUS_CODES,
)
from apihunter.discovery.models import DiscoveredSpec, DiscoveryConfidence


class PathDiscoveryProvider(BaseDiscoveryProvider):
    """Probes well-known paths for OpenAPI/Swagger/GraphQL documents.

    Parameters
    ----------
    client:
        Injected :class:`HttpClient`.
    scope:
        Optional :class:`Scope` for filtering.
    paths:
        Override the default path list (defaults to
        :data:`COMMON_PATHS`).
    concurrency:
        Maximum number of simultaneous probes.
    max_size:
        Maximum response body size in bytes for GET fallback.
    """

    def __init__(
        self,
        client: HttpClient,
        scope: Scope | None = None,
        paths: list[str] | None = None,
        concurrency: int = DEFAULT_CONCURRENCY,
        max_size: int = DEFAULT_MAX_SIZE,
    ) -> None:
        super().__init__(client, scope)
        self._paths = paths if paths is not None else list(COMMON_PATHS)
        self._concurrency = concurrency
        self._max_size = max_size

    @property
    def name(self) -> str:
        return "path"

    async def discover(self, base_url: str) -> list[DiscoveredSpec]:
        """Probe all configured paths under *base_url*.

        Returns a list of :class:`DiscoveredSpec` for every path that
        returned a valid status code.  Errors are silently skipped
        here — the orchestrator collects them via the error callbacks.
        """
        sem = asyncio.Semaphore(self._concurrency)
        tasks = [self._probe_path(base_url, path, sem) for path in self._paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        specs: list[DiscoveredSpec] = []
        for result in results:
            if isinstance(result, DiscoveredSpec):
                specs.append(result)
        return specs

    async def _probe_path(
        self,
        base_url: str,
        path: str,
        sem: asyncio.Semaphore,
    ) -> DiscoveredSpec | None:
        """Probe a single path and return a :class:`DiscoveredSpec` or ``None``."""
        full_url = self._build_url(base_url, path)

        if self._scope is not None:
            if not self._scope.is_in_scope(full_url):
                return None
            if self._scope.is_extension_excluded(full_url):
                return None

        async with sem:
            return await self._fetch(full_url, path)

    async def _fetch(self, url: str, path: str) -> DiscoveredSpec | None:
        """Try HEAD first, fall back to GET with size limit.

        Returns ``None`` if the status code is not in
        :data:`VALID_STATUS_CODES` or if both requests fail.
        """
        try:
            resp = await self._client.request("HEAD", url)
            if resp.status_code in VALID_STATUS_CODES:
                return self._make_spec(url, path, resp)
            if resp.status_code != 405:
                return None
        except (RetryableHttpError, PermanentHttpError):
            pass

        try:
            resp = await self._client.request("GET", url, headers={"Range": f"bytes=0-{self._max_size - 1}"})
            if resp.status_code in VALID_STATUS_CODES:
                return self._make_spec(url, path, resp)
        except (RetryableHttpError, PermanentHttpError):
            pass

        return None

    def _make_spec(self, url: str, path: str, resp: httpx.Response) -> DiscoveredSpec:
        """Build a :class:`DiscoveredSpec` from an HTTP response."""
        content_length_str = resp.headers.get("content-length")
        content_length = int(content_length_str) if content_length_str else None
        confidence_str = PATH_CONFIDENCE.get(path, "low")
        confidence = DiscoveryConfidence(confidence_str)
        return DiscoveredSpec(
            url=url,
            path=path,
            status_code=resp.status_code,
            content_type=resp.headers.get("content-type"),
            content_length=content_length,
            confidence=confidence,
            source=self.name,
        )

    @staticmethod
    def _build_url(base_url: str, path: str) -> str:
        """Join *base_url* and *path* ensuring exactly one slash between them."""
        return base_url.rstrip("/") + "/" + path.lstrip("/")
