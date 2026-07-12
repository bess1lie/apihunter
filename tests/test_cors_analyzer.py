from __future__ import annotations

import pytest

from apihunter.core.models import ScanRun
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
    # Placeholder test
    spec = SpecResult(
        title="Test API", version="1.0", endpoints=[SpecEndpoint(path="/public", method="GET", responses={200: "OK"})]
    )
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = CORSAnalyzer(context=None)

    findings = await analyzer.analyze(spec, scan_run)
    assert isinstance(findings, list)
