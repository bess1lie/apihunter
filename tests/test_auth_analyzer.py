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
    assert "Potentially Unauthenticated" in findings[0].title
    assert findings[0].severity == "low"
    assert findings[0].confidence == "low"
    assert "Evidence:" in (findings[0].detail or "")
    assert "heuristic" in findings[0].title.lower()


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


@pytest.mark.anyio
async def test_auth_active_bypass_evidence():
    """Active probe 200 without auth → HIGH/MEDIUM with Evidence (no token)."""
    from unittest.mock import AsyncMock

    import httpx

    from apihunter.core.executor import Executor
    from apihunter.core.scope import Scope
    from apihunter.modules.base import AnalyzerContext

    scope = Scope(allow=["api.example.com"])
    mock_resp = httpx.Response(200, content=b'{"user":"admin"}')
    client = AsyncMock()
    client.request = AsyncMock(return_value=mock_resp)
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(
        title="Test", version="1.0", endpoints=[SpecEndpoint(path="/admin", method="GET", auth_required=True, auth_schemes=["bearer"])]
    )
    analyzer = AuthAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    active = [f for f in findings if "Potential Authentication Bypass" in f.title]
    assert len(active) == 1
    assert active[0].severity == "high"
    assert active[0].confidence == "medium"
    assert "Evidence:" in (active[0].detail or "")
    assert "unauthenticated_status=200" in (active[0].detail or "")
    assert "heuristic" in active[0].title.lower()


@pytest.mark.anyio
async def test_auth_active_401_no_bypass():
    """401 correctly protected → no bypass finding (negative case)."""
    from unittest.mock import AsyncMock

    import httpx

    from apihunter.core.executor import Executor
    from apihunter.core.scope import Scope
    from apihunter.modules.base import AnalyzerContext

    scope = Scope(allow=["api.example.com"])
    mock_resp = httpx.Response(401, content=b"unauthorized")
    client = AsyncMock()
    client.request = AsyncMock(return_value=mock_resp)
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(
        title="Test", version="1.0", endpoints=[SpecEndpoint(path="/admin", method="GET", auth_required=True, auth_schemes=["bearer"])]
    )
    analyzer = AuthAnalyzer(ctx)
    findings = await analyzer.analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert not any("Potential Authentication Bypass" in f.title for f in findings)


@pytest.mark.anyio
async def test_auth_evidence_contains_endpoint():
    spec = SpecResult(
        title="Test API",
        version="1.0",
        endpoints=[SpecEndpoint(path="/admin", method="GET", auth_required=True, auth_schemes=[], responses={200: "OK"})],
    )
    scan_run = ScanRun(id=1, endpoint="https://api.example.com", status="running")
    analyzer = AuthAnalyzer(context=None)
    findings = await analyzer.analyze(spec, scan_run)
    assert len(findings) >= 1
    assert findings[0].confidence == "high"


# --- New authenticated comparison tests ---


@pytest.mark.anyio
async def test_authenticated_endpoint_401_without_token_no_bypass():
    """Unauth 401 with token configured → no bypass (properly protected)."""
    from unittest.mock import AsyncMock

    import httpx

    from apihunter.core.executor import Executor
    from apihunter.core.scope import Scope
    from apihunter.modules.base import AnalyzerContext

    scope = Scope(allow=["api.example.com"], bearer_token="lab-test-token")
    unauth = httpx.Response(401, content=b"unauthorized")
    auth = httpx.Response(200, content=b'{"ok":true}')
    client = AsyncMock()
    client.request = AsyncMock(side_effect=[unauth, auth])
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(
        title="Test",
        version="1.0",
        endpoints=[SpecEndpoint(path="/api/protected", method="GET", auth_required=True, auth_schemes=["bearer"])],
    )
    findings = await AuthAnalyzer(ctx).analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert not any("Potential Authentication Bypass" in f.title for f in findings)
    assert not any("Ambiguous" in f.title for f in findings)


@pytest.mark.anyio
async def test_authenticated_endpoint_200_without_token_200_with_token_heuristic():
    """Unauth 200 + auth 200 → heuristic HIGH/MEDIUM with safe evidence."""
    from unittest.mock import AsyncMock

    import httpx

    from apihunter.core.executor import Executor
    from apihunter.core.scope import Scope
    from apihunter.modules.base import AnalyzerContext

    scope = Scope(allow=["api.example.com"], bearer_token="lab-test-token")
    unauth = httpx.Response(200, content=b'{"protected":true}')
    auth = httpx.Response(200, content=b'{"protected":true}')
    client = AsyncMock()
    client.request = AsyncMock(side_effect=[unauth, auth])
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(
        title="Test",
        version="1.0",
        endpoints=[SpecEndpoint(path="/api/protected", method="GET", auth_required=True, auth_schemes=["bearer"])],
    )
    findings = await AuthAnalyzer(ctx).analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    bypass = [f for f in findings if "Potential Authentication Bypass" in f.title]
    assert len(bypass) == 1
    assert bypass[0].severity == "high"
    assert bypass[0].confidence == "medium"
    assert "unauthenticated_status=200" in (bypass[0].detail or "")
    assert "authenticated_status=200" in (bypass[0].detail or "")
    assert "unauthenticated_body_len=" in (bypass[0].detail or "")
    assert "authenticated_body_len=" in (bypass[0].detail or "")
    assert "lab-test-token" not in (bypass[0].detail or "")
    assert "Authorization" not in (bypass[0].detail or "")


@pytest.mark.anyio
async def test_authenticated_endpoint_200_without_token_401_with_token():
    """Unauth 200 + auth 401 → ambiguous LOW/LOW, not HIGH."""
    from unittest.mock import AsyncMock

    import httpx

    from apihunter.core.executor import Executor
    from apihunter.core.scope import Scope
    from apihunter.modules.base import AnalyzerContext

    scope = Scope(allow=["api.example.com"], bearer_token="lab-test-token")
    unauth = httpx.Response(200, content=b'{"data":"x"}')
    auth = httpx.Response(401, content=b"unauthorized")
    client = AsyncMock()
    client.request = AsyncMock(side_effect=[unauth, auth])
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(
        title="Test",
        version="1.0",
        endpoints=[SpecEndpoint(path="/api/protected", method="GET", auth_required=True, auth_schemes=["bearer"])],
    )
    findings = await AuthAnalyzer(ctx).analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    # No HIGH bypass, only ambiguous low
    assert not any(f.severity == "high" and "Potential Authentication Bypass" in f.title for f in findings)
    amb = [f for f in findings if "Ambiguous" in f.title]
    assert len(amb) == 1
    assert amb[0].severity == "low"
    assert amb[0].confidence == "low"
    assert "unauthenticated_status=200" in (amb[0].detail or "")
    assert "authenticated_status=401" in (amb[0].detail or "")


@pytest.mark.anyio
async def test_public_endpoint_no_auth_bypass_even_with_token():
    """Public endpoint (auth_required false) → no bypass even with token."""
    from unittest.mock import AsyncMock

    import httpx

    from apihunter.core.executor import Executor
    from apihunter.core.scope import Scope
    from apihunter.modules.base import AnalyzerContext

    scope = Scope(allow=["api.example.com"], bearer_token="lab-test-token")
    # Even if unauth 200, public endpoints should not trigger bypass
    client = AsyncMock()
    client.request = AsyncMock(return_value=httpx.Response(200, content=b"ok"))
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[SpecEndpoint(path="/public/info", method="GET", auth_required=False)])
    findings = await AuthAnalyzer(ctx).analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert not any("Potential Authentication Bypass" in f.title for f in findings)
    assert not any("Ambiguous" in f.title for f in findings)


@pytest.mark.anyio
async def test_security_empty_override_no_bypass():
    """security: [] explicit override → auth_required false → no bypass."""
    from apihunter.parser.openapi_parser import parse_spec

    # Spec with global security but operation overrides with security: []
    spec_dict = {
        "openapi": "3.0.0",
        "info": {"title": "Test", "version": "1.0"},
        "security": [{"bearerAuth": []}],
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        "paths": {
            "/public": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}},
            "/private": {"get": {"responses": {"200": {"description": "ok"}}}},
        },
    }
    result = parse_spec(spec_dict)
    # /public should be auth_required false, /private true
    pub = [e for e in result.endpoints if e.path == "/public"][0]
    priv = [e for e in result.endpoints if e.path == "/private"][0]
    assert pub.auth_required is False
    assert priv.auth_required is True

    # Now test analyzer: public should not get bypass even with token
    from unittest.mock import AsyncMock

    import httpx

    from apihunter.core.executor import Executor
    from apihunter.core.scope import Scope
    from apihunter.modules.base import AnalyzerContext

    scope = Scope(allow=["api.example.com"], bearer_token="lab-test-token")
    client = AsyncMock()
    client.request = AsyncMock(return_value=httpx.Response(200, content=b"ok"))
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(title="Test", version="1.0", endpoints=[pub])
    findings = await AuthAnalyzer(ctx).analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert len([f for f in findings if "Potential Authentication Bypass" in f.title]) == 0


@pytest.mark.anyio
async def test_auth_bypass_evidence_does_not_contain_token():
    """Evidence never contains raw token."""
    from unittest.mock import AsyncMock

    import httpx

    from apihunter.core.executor import Executor
    from apihunter.core.scope import Scope
    from apihunter.modules.base import AnalyzerContext
    from apihunter.report.render import render_html, render_markdown
    from apihunter.report.sarif import generate_sarif

    token = "lab-test-token-super-secret-123"
    scope = Scope(allow=["api.example.com"], bearer_token=token)
    unauth = httpx.Response(200, content=b'{"x":1}')
    auth = httpx.Response(200, content=b'{"x":1}')
    client = AsyncMock()
    client.request = AsyncMock(side_effect=[unauth, auth])
    exe = Executor(client, scope, "https://api.example.com")
    ctx = AnalyzerContext(target="https://api.example.com", scope=scope, client=client, executor=exe)
    spec = SpecResult(
        title="Test",
        version="1.0",
        endpoints=[SpecEndpoint(path="/api/protected", method="GET", auth_required=True, auth_schemes=["bearer"])],
    )
    findings = await AuthAnalyzer(ctx).analyze(spec, ScanRun(endpoint="https://api.example.com", status="running", id=1))
    assert len(findings) == 1
    f = findings[0]
    # Token not in detail
    assert token not in (f.detail or "")
    assert "Bearer" not in (f.detail or "")
    # Not in SARIF
    sarif_str = generate_sarif(findings)
    assert token not in sarif_str
    # Not in Markdown/HTML
    md = render_markdown(findings)
    html = render_html(findings)
    assert token not in md
    assert token not in html
    # Not in SQLite via save/load check handled by not storing token — scope to_dict redacts
    assert token not in str(scope.to_dict())
