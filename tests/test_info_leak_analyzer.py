from unittest.mock import AsyncMock

import httpx
import pytest

from apihunter.core.executor import Executor
from apihunter.core.models import ScanRun
from apihunter.core.scope import Scope
from apihunter.modules.base import AnalyzerContext
from apihunter.modules.info_leak_analyzer import InfoLeakAnalyzer
from apihunter.parser.models import SpecEndpoint, SpecResult


@pytest.mark.anyio
async def test_info_leak_analyzer_empty_spec():
    spec = SpecResult(title="Test API", version="1.0", endpoints=[])
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = InfoLeakAnalyzer(context=None)

    findings = await analyzer.analyze(spec, scan_run)
    assert len(findings) == 0


@pytest.mark.anyio
async def test_info_leak_path_heuristic_low():
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/api/debug", method="GET")])
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = InfoLeakAnalyzer(context=None)
    findings = await analyzer.analyze(spec, scan_run)
    assert len(findings) >= 1
    f = [x for x in findings if "debug" in x.endpoint_path.lower()][0]
    assert f.severity == "low"
    assert f.confidence == "low"
    assert "heuristic" in f.title.lower()
    assert "Evidence:" in (f.detail or "")


@pytest.mark.anyio
async def test_info_leak_active_traceback():
    scope = Scope(allow=["api.example.com"])
    resp = httpx.Response(200, content=b"Traceback most recent call")
    client = AsyncMock()
    client.request = AsyncMock(return_value=resp)
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/api", method="GET")])
    analyzer = InfoLeakAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert len(findings) >= 1
    assert any("Information disclosure" in f.title for f in findings)
    assert any("Evidence:" in (f.detail or "") for f in findings)


@pytest.mark.anyio
async def test_info_leak_no_leak_no_finding():
    scope = Scope(allow=["api.example.com"])
    resp = httpx.Response(200, content=b'{"ok":true}')
    client = AsyncMock()
    client.request = AsyncMock(return_value=resp)
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/api", method="GET")])
    analyzer = InfoLeakAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    # Only path-based if path is /api -> no debug/admin -> no finding
    assert len(findings) == 0
