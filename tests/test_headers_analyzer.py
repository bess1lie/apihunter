from unittest.mock import AsyncMock

import httpx
import pytest

from apihunter.core.executor import Executor
from apihunter.core.models import ScanRun
from apihunter.core.scope import Scope
from apihunter.modules.base import AnalyzerContext
from apihunter.modules.headers_analyzer import HeadersAnalyzer
from apihunter.modules.response_headers_analyzer import ResponseHeadersAnalyzer
from apihunter.parser.models import SpecEndpoint, SpecResult


@pytest.mark.anyio
async def test_headers_analyzer_empty_spec():
    spec = SpecResult(title="Test API", version="1.0", endpoints=[])
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = HeadersAnalyzer(context=None)

    findings = await analyzer.analyze(spec, scan_run)
    assert len(findings) == 0


@pytest.mark.anyio
async def test_response_headers_server_disclosure_low():
    scope = Scope(allow=["api.example.com"])
    resp = httpx.Response(200, headers={"server": "nginx/1.18", "x-powered-by": "PHP"}, content=b"ok")
    client = AsyncMock()
    client.request = AsyncMock(return_value=resp)
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/api", method="GET")])
    analyzer = ResponseHeadersAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    disc = [f for f in findings if "Server header" in f.title]
    assert len(disc) == 1
    assert disc[0].severity == "low"
    assert disc[0].confidence == "high"
    assert "Evidence:" in (disc[0].detail or "")
    assert "nginx" in (disc[0].detail or "")


@pytest.mark.anyio
async def test_response_headers_hsts_only_https():
    scope = Scope(allow=["api.example.com"])
    resp = httpx.Response(200, headers={}, content=b"ok")
    client = AsyncMock()
    client.request = AsyncMock(return_value=resp)
    # http target → no HSTS finding
    exe = Executor(client, scope, "http://api.example.com")
    ctx = AnalyzerContext(target="http://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/api", method="GET")])
    analyzer = ResponseHeadersAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="http://api.example.com", status="running", id=1))
    assert not any("HSTS" in f.title for f in findings)


@pytest.mark.anyio
async def test_response_headers_hsts_missing_https():
    scope = Scope(allow=["api.example.com"])
    resp = httpx.Response(200, headers={}, content=b"ok")
    client = AsyncMock()
    client.request = AsyncMock(return_value=resp)
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/api", method="GET")])
    analyzer = ResponseHeadersAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert any("HSTS" in f.title for f in findings)
    hsts = [f for f in findings if "HSTS" in f.title][0]
    assert "Evidence:" in (hsts.detail or "")
