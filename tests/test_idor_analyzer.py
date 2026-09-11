from unittest.mock import AsyncMock

import httpx
import pytest

from apihunter.core.executor import Executor
from apihunter.core.models import ScanRun
from apihunter.core.scope import Scope
from apihunter.modules.base import AnalyzerContext
from apihunter.modules.idor_analyzer import IDORAnalyzer
from apihunter.parser.models import SpecEndpoint, SpecResult


@pytest.mark.anyio
async def test_idor_analyzer_empty_findings():
    spec = SpecResult(title="Test API", version="1.0", endpoints=[])
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = IDORAnalyzer(context=None)

    findings = await analyzer.analyze(spec, scan_run)
    assert len(findings) == 0


@pytest.mark.anyio
async def test_idor_passive_heuristic_low():
    spec = SpecResult(title="Test API", version="1.0", endpoints=[SpecEndpoint(path="/users/{id}", method="GET")])
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = IDORAnalyzer(context=AnalyzerContext())
    findings = await analyzer.analyze(spec, scan_run)
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].confidence == "low"
    assert "heuristic" in findings[0].title.lower()
    assert "Evidence:" in (findings[0].detail or "")


@pytest.mark.anyio
async def test_idor_active_200_200_heuristic():
    scope = Scope(allow=["api.example.com"])
    r1 = httpx.Response(200, content=b'{"id":1,"name":"alice"}')
    r2 = httpx.Response(200, content=b'{"id":2,"name":"bob","extra":"x"}')
    client = AsyncMock()
    client.request = AsyncMock(side_effect=[r1, r2])
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/users/{id}", method="GET")])
    analyzer = IDORAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].confidence == "low"
    assert "Potential BOLA" in findings[0].title
    assert "status1=200" in (findings[0].detail or "")
    assert "body_len1=" in (findings[0].detail or "")


@pytest.mark.anyio
async def test_idor_active_identical_body_no_strong_finding():
    scope = Scope(allow=["api.example.com"])
    body = b'{"id":1}'
    r1 = httpx.Response(200, content=body)
    r2 = httpx.Response(200, content=body)
    client = AsyncMock()
    client.request = AsyncMock(side_effect=[r1, r2])
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/users/{id}", method="GET")])
    analyzer = IDORAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    # Identical bodies → no finding (not interesting)
    assert len(findings) == 0


@pytest.mark.anyio
async def test_idor_no_object_param_no_finding():
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/search", method="GET")])
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = IDORAnalyzer(context=AnalyzerContext())
    findings = await analyzer.analyze(spec, scan_run)
    assert len(findings) == 0
