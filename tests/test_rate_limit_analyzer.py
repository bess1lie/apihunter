from unittest.mock import AsyncMock

import httpx
import pytest

from apihunter.core.executor import Executor
from apihunter.core.models import ScanRun
from apihunter.core.scope import Scope
from apihunter.modules.base import AnalyzerContext
from apihunter.modules.rate_limit_analyzer import RateLimitAnalyzer
from apihunter.parser.models import SpecEndpoint, SpecResult


@pytest.mark.anyio
async def test_rate_limit_analyzer_empty_spec():
    spec = SpecResult(title="Test API", version="1.0", endpoints=[])
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = RateLimitAnalyzer(context=None)

    findings = await analyzer.analyze(spec, scan_run)
    assert len(findings) == 0


@pytest.mark.anyio
async def test_rate_limit_5x200_heuristic_low():
    scope = Scope(allow=["api.example.com"])
    resp = httpx.Response(200, content=b"ok")
    client = AsyncMock()
    client.request = AsyncMock(return_value=resp)
    exe = Executor(client, scope, "https://api.example.com", max_requests=10)
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/login", method="POST")])
    analyzer = RateLimitAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].confidence == "low"
    assert "heuristic" in findings[0].title.lower()
    assert "Evidence:" in (findings[0].detail or "")
    assert "Not a vulnerability" in (findings[0].detail or "")


@pytest.mark.anyio
async def test_rate_limit_429_no_finding():
    scope = Scope(allow=["api.example.com"])
    resp_429 = httpx.Response(429, headers={"retry-after": "10"}, content=b"rate limit")
    client = AsyncMock()
    # First probe returns 429 immediately
    client.request = AsyncMock(return_value=resp_429)
    exe = Executor(client, scope, "https://api.example.com", max_requests=10)
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/login", method="POST")])
    analyzer = RateLimitAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert len(findings) == 0


@pytest.mark.anyio
async def test_rate_limit_evidence_statuses():
    scope = Scope(allow=["api.example.com"])
    resp = httpx.Response(200, content=b"ok")
    client = AsyncMock()
    client.request = AsyncMock(return_value=resp)
    exe = Executor(client, scope, "https://api.example.com", max_requests=10)
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/login", method="POST")])
    analyzer = RateLimitAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert "statuses=" in (findings[0].detail or "")
