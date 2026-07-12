import pytest

from apihunter.core.models import ScanRun
from apihunter.modules.headers_analyzer import HeadersAnalyzer
from apihunter.parser.models import SpecResult


@pytest.mark.anyio
async def test_headers_analyzer_empty_spec():
    spec = SpecResult(title="Test API", version="1.0", endpoints=[])
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = HeadersAnalyzer(context=None)

    findings = await analyzer.analyze(spec, scan_run)
    assert len(findings) == 0
