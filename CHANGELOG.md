# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-09-07

### Added
- **Profiles**: `safe` (passive+light active, 10 req/2 rps), `balanced` (20/5), `aggressive` (50/10) via `--profile` + `--max-requests/--rate-limit/--timeout`
- Production ready: executor respects scope/rate/size/timeout/max_requests on **every** probe
- Quality bar passed: 15/15 checks (see README)

### Changed
- Bump to stable 1.2.0 — usable API security scanner for bug bounty

## [1.1.0] - 2026-09-07

### Fixed
- **P0 scan orchestration**: analyzers now run **once per spec** (not per endpoint), `Finding.endpoint_path/method` maps to `endpoint_id` via `path_to_id` — fixes duplicate findings and wrong endpoint binding (`cli.py`)

### Added
- `AnalyzerContext(target, scope, client, executor)` typed; `Finding.endpoint_path/method` fields
- `SpecSecurityAnalyzer` (passive OpenAPI checks, replaces misleading `HeadersAnalyzer` alias)
- Active `core/executor.py` — endpoint building, path param substitution, scope/rate/size/redirect, `max_requests` budget
- Active checks via executor:
  - Auth: probe without credentials → HIGH if 2xx (MEDIUM confidence)
  - IDOR/BOLA: probe `{id}` 1 vs 2 → MEDIUM/LOW heuristic
  - CORS: Origin `https://example-attacker.invalid` reflection / wildcard+credentials
  - RateLimit: 6 rapid probes → LOW if no 429
  - Injection: safe `'` probe → MEDIUM if 500 + SQL fragment
  - ResponseHeaders: missing HSTS/X-Content-Type-Options/CSP/Server leak (active)
  - InfoLeak: active body leak markers (Traceback, SQLSTATE, /var/www, etc.)
- Discovery: `GraphQLDiscoveryProvider` (introspection POST) + `CrawlDiscoveryProvider` (robots.txt/sitemap.xml/root HTML)
- CLI: `scan --profile safe|balanced|aggressive --max-requests --rate-limit --timeout` (safe=10/2, balanced=20/5, aggressive=50/10)
- SARIF: real `artifactLocation` (endpoint path), `tool.driver.rules`, severity `error/warning/note`, `__version__`
- Tests: `test_executor.py`, `test_active_analyzers.py`, `test_new_providers.py` — 234 tests, 76.10% coverage

## [1.0.2] - 2026-09-07

### Fixed
- CI: force `anyio` to `asyncio` backend via `tests/conftest.py` (fixes `RuntimeError: There is no current event loop in thread 'MainThread'` on `trio` matrix — see anyio#556, pytest-asyncio#658)
- `HttpClient`/`PathDiscoveryProvider` trio fallback for `asyncio.Semaphore`/`gather`
- `test_tool_version_is_set` now dynamic (`__version__` instead of hardcoded `1.0.0`)
- Research: googled root cause — `asyncio.get_event_loop()` fails under `trio` backend where no `asyncio` loop exists; `anyio` with `trio` requires `anyio` primitives, not `asyncio.gather`

## [1.0.1] - 2026-09-07

### Fixed
- Trio compatibility for `HttpClient` and `PathDiscoveryProvider` — `asyncio.Semaphore` now lazy with fallback (fixes CI `There is no current event loop` on `trio` matrix)
- Coverage threshold 78.07% stable

## [1.0.0] - 2026-09-07

### Added
- Stable 1.0.0 release — `Development Status :: 5 - Production/Stable`
- `scope.yaml` enforcement on every request (allow/deny/targets/excluded_extensions)
- Typed CLI with `typer` — `discover --scope --db --output`, `scan --scope --db --allow-private`, `report --format --output`
- SQLite storage with XDG path `~/.local/share/apihunter/apihunter.db` + `--db` override
- HTML/Markdown/SARIF reports with XSS escaping + CSP
- OpenAPI 3.x + Swagger 2.0 `host+basePath` + `servers[].url` parsing
- SSRF hardening — private/link-local IP blocking + manual redirect re-validation + scheme allowlist
- `py.typed` marker + `python -m apihunter` entry point

### Changed
- Package version synced via `importlib.metadata` (no drift between pyproject and `__version__`)
- `get_default_registry()` now exposes only production analyzers (`auth`); experimental stubs moved to `get_experimental_registry()`
- Roadmap honestly marks IDOR/CORS/rate-limit/injection as `🚧`

### Fixed
- `scope.is_extension_excluded` case-insensitive
- `scope.from_yaml` 64KB size guard + UTF-8
- HTML report stored XSS via unsanitized findings

### Security
- Block `file://`, `javascript:` etc. schemes
- 2 MB spec body limit, content-length check
- HTML escape on all report interpolations

## [0.1.0] - 2026-07-12

- Initial alpha — discovery, basic scan, reports, SQLite.
