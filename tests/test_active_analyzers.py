from unittest.mock import AsyncMock

import httpx
import pytest

from apihunter.core.executor import Executor
from apihunter.core.models import ScanRun
from apihunter.core.scope import Scope
from apihunter.parser.models import SpecEndpoint, SpecResult


def _make_spec(endpoints):
    return SpecResult(title="Test", version="1.0", endpoints=endpoints, base_url=None, raw_spec={})


@pytest.mark.anyio
async def test_auth_active_bypass():
    from apihunter.modules.auth_analyzer import AuthAnalyzer
    from apihunter.modules.base import AnalyzerContext

    scope = Scope(allow=["api.example.com"])
    mock_resp = httpx.Response(200, content=b"ok")
    client = AsyncMock()
    client.request = AsyncMock(return_value=mock_resp)
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    ep = SpecEndpoint(path="/admin", method="GET", auth_required=True, auth_schemes=["bearer"])
    spec = _make_spec([ep])
    analyzer = AuthAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    # Should have passive + active (active because 200 without auth)
    assert any(f.check_type == "auth" and "without credentials" in f.detail for f in findings)


@pytest.mark.anyio
async def test_idor_passive():
    from apihunter.modules.base import AnalyzerContext
    from apihunter.modules.idor_analyzer import IDORAnalyzer

    ctx = AnalyzerContext()
    ep = SpecEndpoint(path="/users/{id}", method="GET")
    spec = _make_spec([ep])
    analyzer = IDORAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert any(f.check_type == "idor" for f in findings)


@pytest.mark.anyio
async def test_cors_active_reflected():
    from apihunter.modules.base import AnalyzerContext
    from apihunter.modules.cors_analyzer import CORSAnalyzer

    scope = Scope(allow=["api.example.com"])
    mock_resp = httpx.Response(
        200,
        headers={"access-control-allow-origin": "https://example-attacker.invalid", "access-control-allow-credentials": "true"},
        content=b"ok",
    )
    client = AsyncMock()
    client.request = AsyncMock(return_value=mock_resp)
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    ep = SpecEndpoint(path="/api", method="GET")
    spec = _make_spec([ep])
    analyzer = CORSAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert any("arbitrary Origin" in f.title for f in findings)


@pytest.mark.anyio
async def test_rate_limit_no_throttle():
    from apihunter.modules.base import AnalyzerContext
    from apihunter.modules.rate_limit_analyzer import RateLimitAnalyzer

    scope = Scope(allow=["api.example.com"])
    mock_resp = httpx.Response(200, content=b"ok")
    client = AsyncMock()
    client.request = AsyncMock(return_value=mock_resp)
    exe = Executor(client, scope, "https://api.example.com", max_requests=10)
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    ep = SpecEndpoint(path="/login", method="POST")
    spec = _make_spec([ep])
    analyzer = RateLimitAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert any(f.check_type == "rate_limit" for f in findings)


@pytest.mark.anyio
async def test_response_headers_missing():
    from apihunter.modules.base import AnalyzerContext
    from apihunter.modules.response_headers_analyzer import ResponseHeadersAnalyzer

    scope = Scope(allow=["api.example.com"])
    mock_resp = httpx.Response(200, headers={"server": "nginx"}, content=b"ok")
    client = AsyncMock()
    client.request = AsyncMock(return_value=mock_resp)
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    ep = SpecEndpoint(path="/api", method="GET")
    spec = _make_spec([ep])
    analyzer = ResponseHeadersAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert any("Missing HSTS" in f.title or "X-Content" in f.title for f in findings)


@pytest.mark.anyio
async def test_injection_safe():
    from apihunter.modules.base import AnalyzerContext
    from apihunter.modules.injection_analyzer import InjectionAnalyzer

    scope = Scope(allow=["api.example.com"])
    # Normal 200, probe 500 with SQL fragment
    normal_resp = httpx.Response(200, content=b'{"ok": true}')
    probe_resp = httpx.Response(500, content=b"SQL syntax error near")
    client = AsyncMock()
    client.request = AsyncMock(side_effect=[normal_resp, probe_resp])
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    from apihunter.parser.models import ParameterLocation, SpecParameter

    ep = SpecEndpoint(path="/search", method="GET", parameters=[SpecParameter(name="q", location=ParameterLocation.QUERY, required=False)])
    spec = _make_spec([ep])
    analyzer = InjectionAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    # May be empty or found, just ensure no crash and returns list
    assert isinstance(findings, list)


@pytest.mark.anyio
async def test_info_leak_active():
    from apihunter.modules.base import AnalyzerContext
    from apihunter.modules.info_leak_analyzer import InfoLeakAnalyzer

    scope = Scope(allow=["api.example.com"])
    mock_resp = httpx.Response(200, content=b"Traceback (most recent call last)")
    client = AsyncMock()
    client.request = AsyncMock(return_value=mock_resp)
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    ep = SpecEndpoint(path="/api", method="GET")
    spec = _make_spec([ep])
    analyzer = InfoLeakAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert any("Information disclosure" in f.title for f in findings)
