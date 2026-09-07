from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from apihunter.core.executor import Executor, _substitute_path_params
from apihunter.core.scope import Scope
from apihunter.parser.models import SpecEndpoint


def test_substitute_path_params():
    assert _substitute_path_params("/users/{id}") == "/users/1"
    assert _substitute_path_params("/users/{userId}/orders/{orderId}") == "/users/1/orders/1"
    assert _substitute_path_params("/test/{page}") == "/test/1"
    assert _substitute_path_params("/static/{name}") == "/static/test"


@pytest.mark.anyio
async def test_executor_build_url():
    scope = Scope(allow=["*.example.com"])
    client = MagicMock()
    exe = Executor(client, scope, "https://api.example.com")
    assert exe.build_url("/users/{id}") == "https://api.example.com/users/1"
    assert exe.build_url("/v1/users") == "https://api.example.com/v1/users"
    exe2 = Executor(client, scope, None)
    assert exe2.build_url("/test") is None


@pytest.mark.anyio
async def test_executor_scope_blocked():
    scope = Scope(allow=["api.example.com"], deny=[])
    client = AsyncMock()
    exe = Executor(client, scope, "https://api.example.com")
    # Try to probe out-of-scope URL via build_url -> will be in scope (api.example.com)
    # But probe_raw with evil.com should be blocked
    res = await exe.probe_raw("https://evil.com/api", method="GET")
    assert res is None
    assert exe._request_count == 0


@pytest.mark.anyio
async def test_executor_probe_success():
    scope = Scope(allow=["api.example.com"])
    mock_resp = httpx.Response(200, headers={"content-type": "application/json"}, content=b'{"ok": true}')
    client = AsyncMock()
    client.request = AsyncMock(return_value=mock_resp)
    exe = Executor(client, scope, "https://api.example.com", max_requests=5)
    ep = SpecEndpoint(path="/users/{id}", method="GET")
    res = await exe.probe(ep)
    assert res is not None
    assert res.status_code == 200
    assert res.url == "https://api.example.com/users/1"
    assert exe._request_count == 1


@pytest.mark.anyio
async def test_executor_budget():
    scope = Scope(allow=["api.example.com"])
    mock_resp = httpx.Response(200, content=b"ok")
    client = AsyncMock()
    client.request = AsyncMock(return_value=mock_resp)
    exe = Executor(client, scope, "https://api.example.com", max_requests=1)
    ep = SpecEndpoint(path="/a", method="GET")
    r1 = await exe.probe(ep)
    assert r1 is not None
    r2 = await exe.probe(ep)
    assert r2 is None


@pytest.mark.anyio
async def test_executor_probe_raw():
    scope = Scope(allow=["api.example.com"])
    mock_resp = httpx.Response(200, headers={"server": "nginx"}, content=b"hi")
    client = AsyncMock()
    client.request = AsyncMock(return_value=mock_resp)
    exe = Executor(client, scope, "https://api.example.com")
    res = await exe.probe_raw("https://api.example.com/test", method="GET", headers={"Origin": "https://evil.com"})
    assert res is not None
    assert res.headers["server"] == "nginx"
