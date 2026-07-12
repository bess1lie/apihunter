import pytest

from apihunter.core.models import ScanRun
from apihunter.modules.idor_analyzer import IDORAnalyzer
from apihunter.parser.models import SpecResult


@pytest.mark.anyio
async def test_idor_analyzer_empty_findings():
    spec = SpecResult(title="Test API", version="1.0", endpoints=[])
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = IDORAnalyzer(context=None)

    findings = await analyzer.analyze(spec, scan_run)
    assert len(findings) == 0
