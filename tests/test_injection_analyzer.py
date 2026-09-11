from unittest.mock import AsyncMock

import httpx
import pytest

from apihunter.core.executor import Executor
from apihunter.core.models import ScanRun
from apihunter.core.scope import Scope
from apihunter.modules.base import AnalyzerContext
from apihunter.modules.injection_analyzer import InjectionAnalyzer
from apihunter.parser.models import ParameterLocation, SpecEndpoint, SpecParameter, SpecResult


@pytest.mark.anyio
async def test_injection_analyzer_empty_spec():
    spec = SpecResult(title="Test API", version="1.0", endpoints=[])
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = InjectionAnalyzer(context=None)

    findings = await analyzer.analyze(spec, scan_run)
    assert len(findings) == 0


@pytest.mark.anyio
async def test_injection_500_sql_fragment_heuristic():
    scope = Scope(allow=["api.example.com"])
    normal = httpx.Response(200, content=b'{"ok":true}')
    probe = httpx.Response(500, content=b"SQL syntax error near '")
    client = AsyncMock()
    client.request = AsyncMock(side_effect=[normal, probe])
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    ep = SpecEndpoint(path="/search", method="GET", parameters=[SpecParameter(name="q", location=ParameterLocation.QUERY, required=False)])
    spec = SpecResult(title="Test", version="1.0", endpoints=[ep])
    analyzer = InjectionAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].confidence == "low"
    assert "heuristic" in findings[0].title.lower()
    assert "Evidence:" in (findings[0].detail or "")
    assert "probe_status=500" in (findings[0].detail or "")
    assert "matched_fragment" in (findings[0].detail or "")


@pytest.mark.anyio
async def test_injection_400_no_fragment_no_finding():
    scope = Scope(allow=["api.example.com"])
    normal = httpx.Response(200, content=b'{"ok":true}')
    probe = httpx.Response(400, content=b"bad request")
    client = AsyncMock()
    client.request = AsyncMock(side_effect=[normal, probe])
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    ep = SpecEndpoint(path="/search", method="GET", parameters=[SpecParameter(name="q", location=ParameterLocation.QUERY, required=False)])
    spec = SpecResult(title="Test", version="1.0", endpoints=[ep])
    analyzer = InjectionAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert len(findings) == 0


@pytest.mark.anyio
async def test_injection_500_without_fragment_no_finding():
    scope = Scope(allow=["api.example.com"])
    normal = httpx.Response(200, content=b'{"ok":true}')
    probe = httpx.Response(500, content=b"internal error")
    client = AsyncMock()
    client.request = AsyncMock(side_effect=[normal, probe])
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    ep = SpecEndpoint(path="/search", method="GET", parameters=[SpecParameter(name="q", location=ParameterLocation.QUERY, required=False)])
    spec = SpecResult(title="Test", version="1.0", endpoints=[ep])
    analyzer = InjectionAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert len(findings) == 0
