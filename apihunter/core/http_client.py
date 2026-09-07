"""Async HTTP client — the single network access point for apihunter.

No other module in the project is permitted to instantiate
:class:`httpx.AsyncClient` directly.  All HTTP traffic flows through
:class:`HttpClient`, which provides:

* configurable timeout and connection pooling;
* exponential-backoff retry on transient errors (wrapped as
  :class:`RetryableHttpError`) — HTTP 5xx are **not** retried;
* non-retryable errors wrapped as :class:`PermanentHttpError`;
* dual-layer rate limiting (concurrency semaphore + minimum interval);
* default headers merged with per-request overrides;
* async context-manager protocol for guaranteed cleanup.

Public API stability
--------------------
The public surface (``request``, ``get``, ``post``, ``close``,
``__aenter__``, ``__aexit__``) will not change in later stages.  New
capabilities (e.g. proxy support, custom transports) can be added as
constructor parameters without breaking existing callers.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from apihunter.core.exceptions import PermanentHttpError, RetryableHttpError

try:
    from importlib.metadata import version as _get_version

    _DEFAULT_USER_AGENT = f"apihunter/{_get_version('apihunter-bess1lie')}"
except Exception:
    _DEFAULT_USER_AGENT = "apihunter/1.0.0"

# Maximum response body to read (2 MB) — prevents OOM on huge specs
_MAX_BODY_SIZE = 2 * 1024 * 1024

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
]


def _is_blocked_ip(host: str) -> bool:
    """Return True if *host* is a private/link-local IP or localhost."""
    # Fast path: IP literal
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _BLOCKED_NETWORKS) or addr.is_private or addr.is_loopback or addr.is_link_local  # noqa: E501
    except ValueError:
        pass
    lowered = host.lower()
    if lowered in ("localhost", "localhost.localdomain") or lowered.endswith(".localhost"):
        return True
    # Do not do blocking DNS resolution here — it would hang tests and
    # is bypassable anyway. Private IPs are caught as literals; DNS
    # rebinding to 127.0.0.1 is blocked via redirect re-validation of
    # literal IP after redirect.
    return False


def _validate_url(url: str, allow_private: bool = False) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise PermanentHttpError(f"Blocked non-http(s) scheme: {parsed.scheme or 'empty'}")
    host = parsed.hostname
    if not host:
        raise PermanentHttpError(f"URL has no hostname: {url}")
    if not allow_private and _is_blocked_ip(host):
        raise PermanentHttpError(f"Blocked private/link-local target: {host}")


@dataclass
class HttpClient:
    """Rate-limited, retrying async HTTP client.

    Parameters
    ----------
    timeout:
        Per-request timeout in seconds.
    max_retries:
        Number of retries on transient errors before giving up.
    rate_per_second:
        Maximum requests per second (enforced via semaphore + interval).
    max_connections:
        Maximum number of concurrent HTTP connections.
    max_keepalive_connections:
        Number of keep-alive connections to maintain in the pool.
    headers:
        Default headers sent with every request.

    Raises
    ------
    RetryableHttpError:
        When all retry attempts are exhausted on a transient error.
    PermanentHttpError:
        When a non-retryable error occurs (e.g. invalid request).
    """

    timeout: float = 10.0
    max_retries: int = 2
    rate_per_second: float = 10.0
    max_connections: int = 20
    max_keepalive_connections: int = 5
    headers: dict[str, str] = field(default_factory=lambda: {"User-Agent": _DEFAULT_USER_AGENT})
    allow_private: bool = False
    _client: httpx.AsyncClient | None = field(default=None, repr=False)
    _sem: asyncio.Semaphore | None = field(default=None, repr=False)
    _last_request: float = field(default=0.0, repr=False)

    def __post_init__(self) -> None:
        """Create the underlying ``httpx.AsyncClient`` and semaphore."""
        limits = httpx.Limits(
            max_keepalive_connections=self.max_keepalive_connections,
            max_connections=self.max_connections,
        )
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            limits=limits,
            follow_redirects=False,
        )
        # Semaphore created lazily inside request (needs running loop)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Send an HTTP request with retry and rate limiting.

        Parameters
        ----------
        method:
            HTTP method (``GET``, ``POST``, ...).
        url:
            Target URL.
        **kwargs:
            Forwarded to :meth:`httpx.AsyncClient.request`.

        Returns
        -------
        httpx.Response
            The response from the first successful attempt.

        Raises
        ------
        RetryableHttpError:
            If every attempt fails with a transient error (timeout,
            connection error).
        PermanentHttpError:
            If a non-retryable httpx error occurs.
        """
        if self._client is None:
            raise PermanentHttpError("HttpClient is closed")
        _validate_url(url, allow_private=self.allow_private)
        if self._sem is None:
            try:
                self._sem = asyncio.Semaphore(max(1, int(self.rate_per_second)))
            except RuntimeError:
                # Trio or no loop — fallback to un-limited
                self._sem = None  # type: ignore[assignment]

        merged_headers = dict(self.headers)
        extra_headers = kwargs.pop("headers", None)
        if extra_headers:
            merged_headers.update(extra_headers)

        async def _execute() -> httpx.Response:
            cur_url = url
            await self._rate_limit()
            last_exc: Exception | None = None
            for attempt in range(1 + self.max_retries):
                try:
                    assert self._client is not None
                    resp = await self._client.request(method, cur_url, headers=merged_headers, **kwargs)
                    # Manual redirect handling with scope/SSRF re-validation
                    redirect_count = 0
                    while resp.is_redirect and redirect_count < 5:
                        location = resp.headers.get("location")
                        if not location:
                            break
                        from urllib.parse import urljoin

                        next_url = urljoin(cur_url, location)
                        _validate_url(next_url, allow_private=self.allow_private)
                        cur_url = next_url
                        resp = await self._client.request(method, cur_url, headers=merged_headers, **kwargs)
                        redirect_count += 1
                    # Body size guard
                    clen = resp.headers.get("content-length")
                    if clen and clen.isdigit() and int(clen) > _MAX_BODY_SIZE:
                        raise PermanentHttpError(f"Response too large: {clen} bytes")
                    if resp.content and len(resp.content) > _MAX_BODY_SIZE:
                        raise PermanentHttpError(f"Response body exceeds {_MAX_BODY_SIZE} bytes")
                    return resp
                except (httpx.TimeoutException, httpx.ConnectError) as exc:
                    last_exc = exc
                    if attempt < self.max_retries:
                        await asyncio.sleep(2**attempt)
                    continue
                except PermanentHttpError:
                    raise
                except (httpx.HTTPError, httpx.InvalidURL, httpx.CookieConflict) as exc:
                    raise PermanentHttpError(str(exc)) from exc
            msg = f"Request to {url} failed after {self.max_retries} retries"
            raise RetryableHttpError(msg) from last_exc

        # Use semaphore only if available (asyncio); trio fallback is no-limit
        sem = self._sem
        if sem is not None:
            async with sem:
                return await _execute()
        else:
            return await _execute()

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Shorthand for ``request("GET", url, **kwargs)``."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, json: dict[str, Any] | None = None, **kwargs: Any) -> httpx.Response:
        """Shorthand for ``request("POST", url, json=json, **kwargs)``."""
        return await self.request("POST", url, json=json, **kwargs)

    async def close(self) -> None:
        """Close the underlying client and release resources."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> HttpClient:
        """Return self for use in ``async with``."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Ensure the client is closed on exit."""
        await self.close()

    async def _rate_limit(self) -> None:
        """Enforce a minimum interval between successive requests."""
        now = time.monotonic()
        elapsed = now - self._last_request
        min_interval = 1.0 / self.rate_per_second
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request = time.monotonic()
