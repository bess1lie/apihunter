"""Tests for :class:`apihunter.core.http_client.HttpClient`.

All tests use ``unittest.mock.AsyncMock`` to avoid real HTTP requests.
``asyncio.sleep`` is patched to prevent real delays during retry tests.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest

from apihunter.core.exceptions import (
    HttpClientError,
    PermanentHttpError,
    RetryableHttpError,
)
from apihunter.core.http_client import HttpClient


async def _no_sleep(_seconds: float) -> None:
    """Async no-op replacement for asyncio.sleep."""


@pytest.mark.anyio
class TestHttpClientSuccess:
    """Successful request scenarios."""

    async def test_get_returns_response(self) -> None:
        async with HttpClient(timeout=5.0, rate_per_second=10000) as client:
            mock_resp = httpx.Response(200, text='{"ok": true}')
            client._client.request = AsyncMock(return_value=mock_resp)
            resp = await client.get("https://example.com/test")
            assert resp.status_code == 200
            assert resp.json() == {"ok": True}

    async def test_post_with_json(self) -> None:
        async with HttpClient(timeout=5.0, rate_per_second=10000) as client:
            mock_resp = httpx.Response(201, text="created")
            client._client.request = AsyncMock(return_value=mock_resp)
            resp = await client.post("https://example.com/test", json={"q": 1})
            assert resp.status_code == 201


@pytest.mark.anyio
class TestHttpClientRetry:
    """Retry behaviour on transient errors."""

    async def test_retries_on_timeout_then_succeeds(self, monkeypatch) -> None:
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        async with HttpClient(timeout=5.0, max_retries=2, rate_per_second=10000) as client:
            ok = httpx.Response(200, text="ok")
            client._client.request = AsyncMock(
                side_effect=[
                    httpx.TimeoutException("timeout"),
                    httpx.TimeoutException("timeout"),
                    ok,
                ]
            )
            resp = await client.get("https://example.com/test")
            assert resp.status_code == 200
            assert client._client.request.call_count == 3

    async def test_retries_on_connect_error_then_succeeds(self, monkeypatch) -> None:
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        async with HttpClient(timeout=5.0, max_retries=1, rate_per_second=10000) as client:
            ok = httpx.Response(200)
            client._client.request = AsyncMock(side_effect=[httpx.ConnectError("refused"), ok])
            resp = await client.get("https://example.com/test")
            assert resp.status_code == 200
            assert client._client.request.call_count == 2

    async def test_raises_retryable_after_all_fail(self, monkeypatch) -> None:
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        async with HttpClient(timeout=5.0, max_retries=1, rate_per_second=10000) as client:
            client._client.request = AsyncMock(side_effect=httpx.TimeoutException("always"))
            with pytest.raises(RetryableHttpError, match="failed after 1 retries"):
                await client.get("https://example.com/test")
            assert client._client.request.call_count == 2


@pytest.mark.anyio
class TestHttpClientPermanentError:
    """Non-retryable errors raise PermanentHttpError immediately."""

    async def test_http_error_not_retried(self) -> None:
        async with HttpClient(timeout=5.0, max_retries=3, rate_per_second=10000) as client:
            client._client.request = AsyncMock(side_effect=httpx.RemoteProtocolError("bad proto"))
            with pytest.raises(PermanentHttpError):
                await client.get("https://example.com/test")
            assert client._client.request.call_count == 1

    async def test_invalid_url_not_retried(self) -> None:
        async with HttpClient(timeout=5.0, max_retries=3, rate_per_second=10000) as client:
            client._client.request = AsyncMock(side_effect=httpx.InvalidURL("bad url"))
            with pytest.raises(PermanentHttpError):
                await client.get("https://example.com/test")
            assert client._client.request.call_count == 1

    async def test_closed_client_raises_permanent(self) -> None:
        client = HttpClient(timeout=5.0)
        await client.__aenter__()
        await client.close()
        with pytest.raises(PermanentHttpError, match="closed"):
            await client.get("https://example.com/test")


@pytest.mark.anyio
class TestHttpClientHeaders:
    """Header merging and defaults."""

    async def test_default_headers_sent(self) -> None:
        async with HttpClient(timeout=5.0, rate_per_second=10000) as client:
            mock_resp = httpx.Response(200)
            client._client.request = AsyncMock(return_value=mock_resp)
            await client.get("https://example.com/test")
            call_kwargs = client._client.request.call_args[1]
            assert call_kwargs["headers"]["User-Agent"] == "apihunter/0.1.0"

    async def test_extra_headers_merged(self) -> None:
        async with HttpClient(timeout=5.0, rate_per_second=10000) as client:
            mock_resp = httpx.Response(200)
            client._client.request = AsyncMock(return_value=mock_resp)
            await client.get("https://example.com/test", headers={"Authorization": "Bearer x"})
            call_kwargs = client._client.request.call_args[1]
            assert call_kwargs["headers"]["User-Agent"] == "apihunter/0.1.0"
            assert call_kwargs["headers"]["Authorization"] == "Bearer x"


@pytest.mark.anyio
class TestHttpClientLifecycle:
    """Context manager and close behaviour."""

    async def test_close_sets_client_to_none(self) -> None:
        async with HttpClient(timeout=5.0) as client:
            assert client._client is not None
        assert client._client is None

    async def test_double_close_safe(self) -> None:
        client = HttpClient(timeout=5.0)
        await client.__aenter__()
        await client.close()
        await client.close()
        assert client._client is None


@pytest.mark.anyio
class TestHttpClientRateLimit:
    """Rate limiter enforces a minimum interval between requests."""

    async def test_rate_limit_sleeps_when_interval_too_short(self, monkeypatch) -> None:
        """When elapsed < min_interval, asyncio.sleep is called."""
        sleep_calls: list[float] = []

        async def _track_sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _track_sleep)

        async with HttpClient(timeout=5.0, rate_per_second=1.0) as client:
            mock_resp = httpx.Response(200)
            client._client.request = AsyncMock(return_value=mock_resp)
            # First request — _last_request is 0.0, so elapsed is huge → no sleep
            await client.get("https://example.com/first")
            assert len(sleep_calls) == 0
            # Second request immediately after — elapsed ~0 < 1.0/1.0 → sleep
            await client.get("https://example.com/second")
            assert len(sleep_calls) == 1
            assert sleep_calls[0] > 0


class TestHttpClientConfig:
    """Constructor parameters (sync tests, no network)."""

    def test_configurable_pooling(self) -> None:
        client = HttpClient(max_connections=50, max_keepalive_connections=10)
        assert client.max_connections == 50
        assert client.max_keepalive_connections == 10

    def test_configurable_timeout(self) -> None:
        client = HttpClient(timeout=30.0)
        assert client.timeout == 30.0

    def test_configurable_retries(self) -> None:
        client = HttpClient(max_retries=5)
        assert client.max_retries == 5

    def test_custom_headers(self) -> None:
        client = HttpClient(headers={"User-Agent": "custom/1.0"})
        assert client.headers["User-Agent"] == "custom/1.0"


class TestHttpExceptions:
    """Exception hierarchy."""

    def test_retryable_is_http_client_error(self) -> None:
        assert issubclass(RetryableHttpError, HttpClientError)

    def test_permanent_is_http_client_error(self) -> None:
        assert issubclass(PermanentHttpError, HttpClientError)

    def test_http_client_error_is_apihunter_error(self) -> None:
        from apihunter.core.exceptions import ApihunterError

        assert issubclass(HttpClientError, ApihunterError)

    def test_retryable_and_permanent_distinct(self) -> None:
        assert RetryableHttpError is not PermanentHttpError
