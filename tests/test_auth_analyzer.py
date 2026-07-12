import pytest

from apihunter.core.models import ScanRun
from apihunter.modules.auth_analyzer import AuthAnalyzer
from apihunter.parser.models import SpecEndpoint, SpecResult


@pytest.mark.anyio
async def test_auth_missing_scheme():
    spec = SpecResult(
        title="Test API",
        version="1.0",
        endpoints=[
            SpecEndpoint(
                path="/admin",
                method="GET",
                auth_required=True,
                auth_schemes=[],  # Missing scheme
                responses={200: "OK"},
            )
        ],
    )
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = AuthAnalyzer(context=None)  # context not used in this simple test

    findings = await analyzer.analyze(spec, scan_run)

    assert len(findings) == 1
    assert findings[0].title == "Missing Authentication Scheme"
    assert findings[0].severity == "high"


@pytest.mark.anyio
async def test_auth_sensitive_endpoint_unauthenticated():
    spec = SpecResult(
        title="Test API",
        version="1.0",
        endpoints=[
            SpecEndpoint(
                path="/user/profile",
                method="GET",
                auth_required=False,  # Sensitive but no auth
                responses={200: "OK"},
            )
        ],
    )
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = AuthAnalyzer(context=None)

    findings = await analyzer.analyze(spec, scan_run)

    assert len(findings) == 1
    assert findings[0].title == "Potentially Unauthenticated Sensitive Endpoint"
    assert findings[0].severity == "medium"


@pytest.mark.anyio
async def test_auth_not_required_for_public():
    spec = SpecResult(
        title="Test API",
        version="1.0",
        endpoints=[SpecEndpoint(path="/public/info", method="GET", auth_required=False, responses={200: "OK"})],
    )
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = AuthAnalyzer(context=None)

    findings = await analyzer.analyze(spec, scan_run)

    assert len(findings) == 0
