import pytest
from unittest.mock import AsyncMock, MagicMock

import httpx
import respx
from httpx import Response

from apihunter.core.http_client import HttpClient
from apihunter.core.scope import Scope
from apihunter.discovery.providers.crawl import CrawlDiscoveryProvider
from apihunter.discovery.providers.graphql import GraphQLDiscoveryProvider

_BASE = "https://api.example.com"


@pytest.mark.anyio
async def test_graphql_introspection_found():
    mock_resp = Response(200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}})
    client = AsyncMock(spec=HttpClient)

    # First path /graphql returns 200 with data, others 404
    async def fake_request(method, url, **kwargs):
        if url == _BASE + "/graphql" and method == "POST":
            return mock_resp
        return Response(404)

    client.request = AsyncMock(side_effect=fake_request)
    provider = GraphQLDiscoveryProvider(client, scope=Scope(allow=["api.example.com"]))
    specs = await provider.discover(_BASE)
    assert len(specs) >= 1
    assert any(s.path == "/graphql" for s in specs)


@pytest.mark.anyio
async def test_graphql_scope_blocked():
    client = AsyncMock(spec=HttpClient)
    client.request = AsyncMock(return_value=Response(200, json={"data": {}}))
    scope = Scope(allow=["other.com"])
    provider = GraphQLDiscoveryProvider(client, scope=scope)
    specs = await provider.discover(_BASE)
    assert len(specs) == 0
    # No request should be made for blocked scope? Actually scope checks before request, so 0 calls
    assert client.request.call_count == 0


@pytest.mark.anyio
async def test_crawl_robots_found():
    # Mock robots.txt with Allow: /api/openapi.json
    robots_resp = Response(200, text="User-agent: *\nAllow: /api/openapi.json\n")
    sitemap_resp = Response(404)
    root_resp = Response(200, headers={"content-type": "text/html"}, text='<html><a href="/api/test">api</a></html>')

    async def fake_request(method, url, **kwargs):
        if url.endswith("/robots.txt"):
            return robots_resp
        if url.endswith("/sitemap.xml"):
            return sitemap_resp
        if url == _BASE + "/":
            return root_resp
        return Response(404)

    client = AsyncMock(spec=HttpClient)
    client.request = AsyncMock(side_effect=fake_request)
    provider = CrawlDiscoveryProvider(client, scope=Scope(allow=["api.example.com"]))
    specs = await provider.discover(_BASE)
    # Should find at least robots path
    assert any("/api/openapi.json" in s.path for s in specs)


@pytest.mark.anyio
async def test_crawl_no_404():
    client = AsyncMock(spec=HttpClient)
    client.request = AsyncMock(return_value=Response(404))
    provider = CrawlDiscoveryProvider(client, scope=Scope(allow=["api.example.com"]))
    specs = await provider.discover(_BASE)
    assert specs == []
