import pytest

from apihunter.core.models import ScanRun
from apihunter.modules.injection_analyzer import InjectionAnalyzer
from apihunter.parser.models import SpecResult


@pytest.mark.anyio
async def test_injection_analyzer_empty_spec():
    spec = SpecResult(title="Test API", version="1.0", endpoints=[])
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = InjectionAnalyzer(context=None)

    findings = await analyzer.analyze(spec, scan_run)
    assert len(findings) == 0
