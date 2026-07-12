"""Tests for the discovery module.

All HTTP traffic is mocked with ``respx`` — no real requests are made.
``asyncio.sleep`` inside HttpClient is patched to prevent delays.
``assert_all_called=False`` is used because HEAD success skips GET.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from apihunter.core.http_client import HttpClient
from apihunter.core.scope import Scope
from apihunter.discovery import (
    DiscoveredSpec,
    Discovery,
    DiscoveryConfidence,
    DiscoveryError,
    DiscoveryResult,
    PathDiscoveryProvider,
)
from apihunter.discovery.base import BaseDiscoveryProvider


async def _no_sleep(_seconds: float) -> None:
    """Async no-op replacement for asyncio.sleep."""


_BASE = "https://api.example.com"


@pytest.fixture()
def _client():
    """Create a fast HttpClient for tests."""
    return HttpClient(timeout=5.0, rate_per_second=10000, max_retries=0)


def _mock_404_catchall(router: respx.MockRouter) -> None:
    """Register a catch-all route returning 404 for unspecified paths."""
    router.route().mock(return_value=httpx.Response(404))


def _mock_path_ok(router: respx.MockRouter, path: str, status: int = 200, **headers) -> None:
    """Register a route for *path* matching ALL methods (HEAD + GET)."""
    router.route(path=path).mock(return_value=httpx.Response(status, headers=headers))


@pytest.mark.anyio
class TestPathDiscoveryProviderBasics:
    """Core provider behaviour: finds specs, returns typed models."""

    async def test_finds_openapi_json(self, _client: HttpClient, monkeypatch) -> None:
        """A 200 on /openapi.json yields a HIGH confidence spec."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            _mock_path_ok(router, "/openapi.json", 200, **{"content-type": "application/json", "content-length": "500"})
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client)
                specs = await provider.discover(_BASE)

        openapi = [s for s in specs if s.path == "/openapi.json"]
        assert len(openapi) == 1
        assert openapi[0].status_code == 200
        assert openapi[0].confidence == DiscoveryConfidence.HIGH
        assert openapi[0].content_type == "application/json"
        assert openapi[0].content_length == 500
        assert openapi[0].source == "path"

    async def test_returns_typed_discovered_spec(self, _client: HttpClient, monkeypatch) -> None:
        """Every returned item is a DiscoveredSpec, not a dict."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            _mock_path_ok(router, "/swagger.json")
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client)
                specs = await provider.discover(_BASE)
        assert all(isinstance(s, DiscoveredSpec) for s in specs)

    async def test_empty_result_when_all_404(self, _client: HttpClient, monkeypatch) -> None:
        """All paths returning 404 yields an empty spec list."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client)
                specs = await provider.discover(_BASE)
        assert specs == []

    async def test_finds_multiple_documents(self, _client: HttpClient, monkeypatch) -> None:
        """Multiple paths return 200 — all are in the result."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            _mock_path_ok(router, "/openapi.json")
            _mock_path_ok(router, "/swagger.json")
            _mock_path_ok(router, "/docs")
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client)
                specs = await provider.discover(_BASE)
        paths = {s.path for s in specs}
        assert paths == {"/openapi.json", "/swagger.json", "/docs"}


@pytest.mark.anyio
class TestPathDiscoveryConfidence:
    """Confidence levels are correctly assigned per path."""

    @pytest.mark.parametrize(
        "path,expected_confidence",
        [
            ("/openapi.json", DiscoveryConfidence.HIGH),
            ("/openapi.yaml", DiscoveryConfidence.HIGH),
            ("/api/openapi.json", DiscoveryConfidence.HIGH),
            ("/swagger.json", DiscoveryConfidence.HIGH),
            ("/swagger.yaml", DiscoveryConfidence.HIGH),
            ("/api/swagger.json", DiscoveryConfidence.HIGH),
            ("/v2/api-docs", DiscoveryConfidence.HIGH),
            ("/v3/api-docs", DiscoveryConfidence.HIGH),
            ("/api/v1/api-docs", DiscoveryConfidence.HIGH),
            ("/api/v2/api-docs", DiscoveryConfidence.HIGH),
            ("/api/v3/api-docs", DiscoveryConfidence.HIGH),
            ("/api/docs", DiscoveryConfidence.MEDIUM),
            ("/docs", DiscoveryConfidence.MEDIUM),
            ("/redoc", DiscoveryConfidence.MEDIUM),
            ("/api/spec", DiscoveryConfidence.MEDIUM),
            ("/spec", DiscoveryConfidence.MEDIUM),
            ("/swagger-resources", DiscoveryConfidence.MEDIUM),
            ("/api/swagger-resources", DiscoveryConfidence.MEDIUM),
            ("/graphql", DiscoveryConfidence.LOW),
            ("/graphiql", DiscoveryConfidence.LOW),
            ("/voyager", DiscoveryConfidence.LOW),
            ("/altair", DiscoveryConfidence.LOW),
        ],
    )
    async def test_confidence_per_path(
        self, path: str, expected_confidence: DiscoveryConfidence, _client: HttpClient, monkeypatch
    ) -> None:
        """Each of the 22 paths gets the correct confidence level."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            _mock_path_ok(router, path)
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client)
                specs = await provider.discover(_BASE)
        matched = [s for s in specs if s.path == path]
        assert len(matched) == 1
        assert matched[0].confidence == expected_confidence


@pytest.mark.anyio
class TestPathDiscoveryStatusCodes:
    """Valid and invalid status code handling."""

    @pytest.mark.parametrize("status_code", [200, 204, 301, 302, 307, 308, 401, 403])
    async def test_valid_status_codes_accepted(self, status_code: int, _client: HttpClient, monkeypatch) -> None:
        """Status codes in VALID_STATUS_CODES produce a spec."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            _mock_path_ok(router, "/openapi.json", status_code)
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client)
                specs = await provider.discover(_BASE)
        assert len(specs) == 1
        assert specs[0].status_code == status_code

    @pytest.mark.parametrize("status_code", [400, 404, 405, 500, 502, 503])
    async def test_invalid_status_codes_skipped(self, status_code: int, _client: HttpClient, monkeypatch) -> None:
        """Status codes NOT in VALID_STATUS_CODES produce no spec."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            router.route().mock(return_value=httpx.Response(status_code))
            async with _client:
                provider = PathDiscoveryProvider(_client)
                specs = await provider.discover(_BASE)
        assert specs == []


@pytest.mark.anyio
class TestPathDiscoveryHeadFallback:
    """HEAD → GET fallback when HEAD returns 405."""

    async def test_head_405_falls_back_to_get(self, _client: HttpClient, monkeypatch) -> None:
        """When HEAD returns 405, GET is used instead."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            router.route(method="HEAD", path="/openapi.json").mock(return_value=httpx.Response(405))
            router.route(method="GET", path="/openapi.json").mock(return_value=httpx.Response(200))
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client)
                specs = await provider.discover(_BASE)
        assert len(specs) == 1
        assert specs[0].path == "/openapi.json"
        assert specs[0].status_code == 200

    async def test_head_200_no_get_needed(self, _client: HttpClient, monkeypatch) -> None:
        """When HEAD returns 200, GET is not attempted."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            router.route(method="HEAD", path="/openapi.json").mock(
                return_value=httpx.Response(200, headers={"content-type": "application/json"})
            )
            get_route = router.route(method="GET", path="/openapi.json").mock(return_value=httpx.Response(200))
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client)
                specs = await provider.discover(_BASE)
        assert len(specs) == 1
        assert not get_route.called, "GET should not be called when HEAD succeeds"

    async def test_head_error_falls_back_to_get(self, _client: HttpClient, monkeypatch) -> None:
        """When HEAD raises a timeout, GET is still attempted."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            router.route(method="HEAD", path="/openapi.json").mock(side_effect=httpx.TimeoutException("timeout"))
            router.route(method="GET", path="/openapi.json").mock(return_value=httpx.Response(200))
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client)
                specs = await provider.discover(_BASE)
        assert len(specs) == 1
        assert specs[0].path == "/openapi.json"


@pytest.mark.anyio
class TestPathDiscoveryErrorHandling:
    """Per-URL errors do not stop other probes."""

    async def test_timeout_does_not_stop_others(self, _client: HttpClient, monkeypatch) -> None:
        """A timeout on one path does not prevent others from being found."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            router.route(path="/openapi.json").mock(side_effect=httpx.TimeoutException("timeout"))
            _mock_path_ok(router, "/swagger.json")
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client)
                specs = await provider.discover(_BASE)
        paths = {s.path for s in specs}
        assert "/swagger.json" in paths
        assert "/openapi.json" not in paths

    async def test_permanent_error_skipped(self, _client: HttpClient, monkeypatch) -> None:
        """A permanent HTTP error on one path does not affect others."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            router.route(path="/graphql").mock(side_effect=httpx.RemoteProtocolError("bad"))
            _mock_path_ok(router, "/openapi.json")
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client)
                specs = await provider.discover(_BASE)
        paths = {s.path for s in specs}
        assert "/openapi.json" in paths
        assert "/graphql" not in paths


@pytest.mark.anyio
class TestPathDiscoveryScope:
    """Scope filtering: deny and excluded_extensions."""

    async def test_scope_deny_skips_host(self, _client: HttpClient, monkeypatch) -> None:
        """When the host is denied by scope, no probes are made."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        scope = Scope(allow=["*.example.com"], deny=["api.example.com"])
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            _mock_path_ok(router, "/openapi.json")
            async with _client:
                provider = PathDiscoveryProvider(_client, scope=scope)
                specs = await provider.discover(_BASE)
        assert specs == []

    async def test_scope_allow_matches(self, _client: HttpClient, monkeypatch) -> None:
        """When the host is allowed, probes proceed normally."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        scope = Scope(allow=["*.example.com"])
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            _mock_path_ok(router, "/openapi.json")
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client, scope=scope)
                specs = await provider.discover(_BASE)
        assert len(specs) == 1
        assert specs[0].path == "/openapi.json"

    async def test_excluded_extensions_not_applied_to_spec_paths(self, _client: HttpClient, monkeypatch) -> None:
        """Spec paths like /openapi.json are not affected by excluded_extensions."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        scope = Scope(allow=["*.example.com"], excluded_extensions=["png", "jpg"])
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            _mock_path_ok(router, "/openapi.json")
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client, scope=scope)
                specs = await provider.discover(_BASE)
        assert any(s.path == "/openapi.json" for s in specs)


@pytest.mark.anyio
class TestPathDiscoveryConcurrency:
    """Concurrency is bounded by Semaphore."""

    async def test_custom_concurrency(self, _client: HttpClient, monkeypatch) -> None:
        """Provider accepts a custom concurrency value without error."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client, concurrency=5)
                specs = await provider.discover(_BASE)
        assert specs == []

    async def test_custom_paths(self, _client: HttpClient, monkeypatch) -> None:
        """Custom path list overrides the default 22 paths."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        custom = ["/custom-spec.json", "/my-api/openapi.json"]
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            router.route().mock(return_value=httpx.Response(200))
            async with _client:
                provider = PathDiscoveryProvider(_client, paths=custom)
                specs = await provider.discover(_BASE)
        assert len(specs) == 2
        paths = {s.path for s in specs}
        assert paths == {"/custom-spec.json", "/my-api/openapi.json"}


@pytest.mark.anyio
class TestPathDiscoveryMaxSize:
    """Max size configuration is honoured."""

    async def test_custom_max_size_range_header(self, _client: HttpClient, monkeypatch) -> None:
        """Custom max_size is used in the Range header for GET fallback."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        captured_headers: dict[str, str] = {}
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            router.route(method="HEAD", path="/openapi.json").mock(return_value=httpx.Response(405))

            def _capture(request):
                captured_headers.update(dict(request.headers))
                return httpx.Response(200)

            router.route(method="GET", path="/openapi.json").mock(side_effect=_capture)
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client, max_size=2048)
                specs = await provider.discover(_BASE)
        assert len(specs) == 1
        assert "range" in {k.lower() for k in captured_headers}
        assert "0-2047" in captured_headers.get("range", "")


@pytest.mark.anyio
class TestDiscoveryOrchestrator:
    """Discovery class coordinates providers and aggregates results."""

    async def test_run_returns_discovery_result(self, _client: HttpClient, monkeypatch) -> None:
        """Discovery.run returns a DiscoveryResult with typed fields."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            _mock_path_ok(router, "/openapi.json")
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client)
                discovery = Discovery([provider])
                result = await discovery.run(_BASE)
        assert isinstance(result, DiscoveryResult)
        assert len(result.specs) == 1
        assert len(result.errors) == 0

    async def test_specs_sorted_by_confidence(self, _client: HttpClient, monkeypatch) -> None:
        """HIGH confidence specs appear before MEDIUM and LOW."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)
        with respx.mock(base_url=_BASE, assert_all_called=False) as router:
            _mock_path_ok(router, "/graphql")
            _mock_path_ok(router, "/docs")
            _mock_path_ok(router, "/openapi.json")
            _mock_404_catchall(router)
            async with _client:
                provider = PathDiscoveryProvider(_client)
                discovery = Discovery([provider])
                result = await discovery.run(_BASE)
        confidences = [s.confidence for s in result.specs]
        assert confidences[0] == DiscoveryConfidence.HIGH
        assert confidences[1] == DiscoveryConfidence.MEDIUM
        assert confidences[2] == DiscoveryConfidence.LOW

    async def test_provider_error_recorded(self, _client: HttpClient, monkeypatch) -> None:
        """A provider exception is caught and recorded in errors."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)

        class FailingProvider(BaseDiscoveryProvider):
            async def discover(self, base_url: str) -> list[DiscoveredSpec]:
                raise RuntimeError("provider crashed")

        async with _client:
            discovery = Discovery([FailingProvider(_client)])
            result = await discovery.run(_BASE)
        assert len(result.specs) == 0
        assert len(result.errors) == 1
        assert isinstance(result.errors[0], DiscoveryError)
        assert "provider crashed" in result.errors[0].message

    async def test_empty_providers_raises(self) -> None:
        """Construction with no providers raises ValueError."""
        with pytest.raises(ValueError, match="At least one"):
            Discovery([])

    async def test_multiple_providers_aggregated(self, _client: HttpClient, monkeypatch) -> None:
        """Results from multiple providers are combined."""
        monkeypatch.setattr("apihunter.core.http_client.asyncio.sleep", _no_sleep)

        class StubProvider(BaseDiscoveryProvider):
            def __init__(self, client, label, paths):
                super().__init__(client)
                self._label = label
                self._paths = paths

            @property
            def name(self) -> str:
                return self._label

            async def discover(self, base_url: str) -> list[DiscoveredSpec]:
                return [
                    DiscoveredSpec(
                        url=f"{base_url}{p}",
                        path=p,
                        status_code=200,
                        source=self._label,
                    )
                    for p in self._paths
                ]

        async with _client:
            discovery = Discovery(
                [
                    StubProvider(_client, "stub_a", ["/a"]),
                    StubProvider(_client, "stub_b", ["/b"]),
                ]
            )
            result = await discovery.run(_BASE)
        assert len(result.specs) == 2
        sources = {s.source for s in result.specs}
        assert sources == {"stub_a", "stub_b"}


class TestDiscoveryModels:
    """Model properties and immutability (sync tests)."""

    def test_discovered_spec_is_frozen(self) -> None:
        spec = DiscoveredSpec(url="https://x.com/openapi.json", path="/openapi.json", status_code=200)
        with pytest.raises(AttributeError):
            spec.status_code = 404  # type: ignore[misc]

    def test_discovery_result_defaults(self) -> None:
        result = DiscoveryResult()
        assert result.specs == []
        assert result.errors == []

    def test_discovery_confidence_str_enum(self) -> None:
        assert DiscoveryConfidence.HIGH.value == "high"
        assert str(DiscoveryConfidence.HIGH) == "high"

    def test_discovery_error_fields(self) -> None:
        err = DiscoveryError(url="https://x.com", error_type="timeout", message="timed out")
        assert err.url == "https://x.com"
        assert err.error_type == "timeout"
