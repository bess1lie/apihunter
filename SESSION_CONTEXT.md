# apihunter — Session Context (resume point)

## Last updated: 2026-06-30

## Quick start tomorrow
```bash
cd /home/bessilie/apihunter
.venv/bin/ruff check apihunter/ tests/
.venv/bin/python -m pytest tests/ -q --tb=short
```

## Completed groups (DONE, do not touch)

### Group 1: Configuration ✅
- 12 files: pyproject.toml, __init__.py, .gitignore, .dockerignore, .pre-commit-config.yaml, ci.yml, Dockerfile, docker-compose.yml, .env.example, LICENSE, README.md, tests/__init__.py
- pip install -e ".[dev]" works
- venv at /home/bessilie/apihunter/.venv (Python 3.14)

### Group 2: Core refactor ✅
Files (10, all ruff-clean, 100% test coverage):
- core/schema.py — SCHEMA_SQL, CURRENT_SCHEMA_VERSION
- core/migrations.py — MIGRATIONS dict (empty, ready for v2)
- core/db.py — Database (connection + writes + _transaction + migrate), 372 lines
- core/queries.py — Queries (read-only, returns dataclasses)
- core/models.py — frozen dataclasses: ScanRun, Endpoint, SpecInfo, AuthResult, Finding, FuzzResult, Checkpoint
- core/scope.py — Scope (frozen, allow/deny/targets/excluded_extensions, can_scan, is_in_scope, is_extension_excluded)
- core/http_client.py — HttpClient (configurable pooling, RetryableHttpError/PermanentHttpError)
- core/exceptions.py — ApihunterError hierarchy
- core/redaction.py — redact_secret (Bearer/Basic/ApiKey/Token/JWT/Cookie/Set-Cookie/X-Api-Key, idempotent)
- core/__init__.py

### Group 2b: Core tests ✅
- tests/test_redaction.py — 26 tests
- tests/test_scope.py — 30 tests
- tests/test_db.py — 47 tests
- tests/test_http_client.py — 27 tests
- Total: 130 tests, 100% coverage of apihunter.core
- All ruff-clean

## IN PROGRESS: Group 3 — Discovery

### Discovery code (DONE, ruff-clean):
- apihunter/discovery/constants.py — COMMON_PATHS (22), PATH_CONFIDENCE, VALID_STATUS_CODES, DEFAULT_MAX_SIZE, DEFAULT_CONCURRENCY
- apihunter/discovery/models.py — DiscoveryConfidence(StrEnum), DiscoveredSpec, DiscoveryError, DiscoveryResult (all frozen)
- apihunter/discovery/base.py — BaseDiscoveryProvider ABC
- apihunter/discovery/discovery.py — Discovery orchestrator (aggregates providers, sorts by confidence)
- apihunter/discovery/providers/__init__.py — exports PathDiscoveryProvider
- apihunter/discovery/providers/path.py — PathDiscoveryProvider (HEAD→GET fallback, Semaphore concurrency, scope filter, max_size Range header)
- apihunter/discovery/__init__.py — public API exports

### Discovery tests (WRITTEN BUT 42 FAILING):
- tests/test_discovery.py — 60 tests total, 18 pass, 42 fail

### THE BUG TO FIX TOMORROW:
**Root cause:** respx catch-all route `router.route().mock(404)` intercepts ALL requests
before specific path routes can match. Specific routes registered AFTER the catch-all
never get hit.

**Current broken pattern in test helpers:**
```python
def _mock_404_catchall(router):
    router.route().mock(return_value=httpx.Response(404))  # matches EVERYTHING

def _mock_path_ok(router, path, status=200, **headers):
    router.route(path=path).mock(...)  # NEVER reached — catch-all already matched
```

**Fix approach (2 options, pick one):**

Option A (recommended): Register specific routes BEFORE catch-all:
```python
def _mock_path_ok(router, path, status=200, **headers):
    router.route(path=path).mock(return_value=httpx.Response(status, headers=headers))

def _mock_404_catchall(router):
    router.route().mock(return_value=httpx.Response(404))
```
And in tests: call _mock_path_ok FIRST, then _mock_404_catchall LAST.

Option B: Don't use catch-all. Instead mock each of the 22 paths individually with 404,
then override the ones that should return 200.

**Additionally:** Some tests for HEAD/GET fallback need method-specific routes:
```python
router.route(method="HEAD", path="/openapi.json").mock(return_value=httpx.Response(405))
router.route(method="GET", path="/openapi.json").mock(return_value=httpx.Response(200))
```
These must be registered BEFORE the catch-all too.

### After fixing tests, verify:
1. `ruff check apihunter/ tests/` — must be clean
2. `ruff format --check apihunter/ tests/` — must be clean
3. `pytest tests/test_discovery.py --cov=apihunter.discovery --cov-report=term-missing` — all pass, coverage ≥95%
4. Then provide report and wait for user confirmation

## Remaining groups (NOT STARTED):

### Group 3b: Parser
- apihunter/parser/spec_parser.py — SpecEndpoint, SpecResult dataclasses, parse_spec() stub
- apihunter/parser/__init__.py
- Tests

### Group 4: Plugin Architecture
- apihunter/modules/base.py — Analyzer ABC, Finding, Severity(StrEnum), Confidence(StrEnum), AnalyzerContext, AnalyzerRegistry
- 7 stub analyzers: auth.py, headers.py, cors.py, http_profile.py, quality.py, fingerprint.py, heuristics.py
- apihunter/modules/__init__.py
- Tests

### Group 5: Report + Dashboard + Inventory
- apihunter/report/render.py — render_html, render_markdown (minimal valid HTML with Executive Summary)
- apihunter/report/sarif.py — generate_sarif (valid 2.1.0 skeleton)
- apihunter/report/__init__.py
- apihunter/dashboard.py — HTTPServer stub
- apihunter/inventory.py — InventoryReport dataclass + stubs
- Tests

### Group 6: CLI
- apihunter/cli.py — 13 commands (discover, scan, auth, inspect, inventory, report, export, diff, dashboard, batch, baseline, monitor, --version)
- checkpoint/resume pattern (from bounthunt)
- exit codes 0/1/2
- Tests

### Group 7: README.md
- Expand minimal README

### Group 8: Final verification
- pip install, ruff, pytest --cov, CLI smoke test

## Key architecture decisions (locked, do not change):
1. @dataclass (not Pydantic) for all models
2. frozen=True for all dataclasses
3. StrEnum for all enums
4. Database = writes only, Queries = reads only
5. No dict returns from Database/Queries — always typed dataclasses
6. HttpClient is the ONLY place httpx.AsyncClient is created
7. Discovery providers injected into Discovery orchestrator (no global registry)
8. Scope: allow/deny/targets/excluded_extensions (unified format)
9. redact_secret() is a pure function, idempotent
10. Exceptions: ApihunterError → DatabaseError/ScopeError/HttpClientError → leaf classes
11. _transaction() context manager in Database for rollback safety
12. CLI = orchestrator only, no business logic

## File count so far:
- apihunter/ — 21 Python files
- tests/ — 5 test files
- Config — 12 files
- Total — 38 files
