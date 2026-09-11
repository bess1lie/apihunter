from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest

from apihunter.core.executor import Executor
from apihunter.core.models import ScanRun
from apihunter.core.scope import Scope
from apihunter.modules.base import AnalyzerContext
from apihunter.modules.cors_analyzer import CORSAnalyzer
from apihunter.parser.models import SpecEndpoint, SpecResult


@pytest.mark.anyio
async def test_cors_analyzer_empty_spec():
    spec = SpecResult(title="Test API", version="1.0", endpoints=[])
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = CORSAnalyzer(context=None)

    findings = await analyzer.analyze(spec, scan_run)
    assert len(findings) == 0


@pytest.mark.anyio
async def test_cors_analyzer_wildcard_origin():
    # Placeholder test - no executor → no finding
    spec = SpecResult(title="Test API", version="1.0", endpoints=[SpecEndpoint(path="/public", method="GET", responses={200: "OK"})])
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = CORSAnalyzer(context=None)

    findings = await analyzer.analyze(spec, scan_run)
    assert isinstance(findings, list)


@pytest.mark.anyio
async def test_cors_wildcard_with_credentials_high():
    scope = Scope(allow=["api.example.com"])
    resp = httpx.Response(200, headers={"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}, content=b"ok")
    client = AsyncMock()
    client.request = AsyncMock(return_value=resp)
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/api", method="GET")])
    analyzer = CORSAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].confidence == "high"
    assert "wildcard with credentials" in findings[0].title.lower()
    assert "Evidence:" in (findings[0].detail or "")


@pytest.mark.anyio
async def test_cors_wildcard_without_credentials_info():
    scope = Scope(allow=["api.example.com"])
    resp = httpx.Response(200, headers={"access-control-allow-origin": "*"}, content=b"ok")
    client = AsyncMock()
    client.request = AsyncMock(return_value=resp)
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/api", method="GET")])
    analyzer = CORSAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].confidence == "medium"
    assert "Evidence:" in (findings[0].detail or "")


@pytest.mark.anyio
async def test_cors_reflected_origin_medium():
    scope = Scope(allow=["api.example.com"])
    resp = httpx.Response(
        200,
        headers={
            "access-control-allow-origin": "https://example-attacker.invalid",
            "access-control-allow-credentials": "true",
            "vary": "Origin",
        },
        content=b"ok",
    )
    client = AsyncMock()
    client.request = AsyncMock(return_value=resp)
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/api", method="GET")])
    analyzer = CORSAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert len(findings) == 1
    assert findings[0].severity == "high"  # with creds → HIGH
    assert findings[0].confidence == "medium"
    assert "Evidence:" in (findings[0].detail or "")
    assert "Vary" in (findings[0].detail or "")


@pytest.mark.anyio
async def test_cors_no_headers_no_finding():
    scope = Scope(allow=["api.example.com"])
    resp = httpx.Response(200, content=b"ok")
    client = AsyncMock()
    client.request = AsyncMock(return_value=resp)
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/api", method="GET")])
    analyzer = CORSAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert len(findings) == 0
