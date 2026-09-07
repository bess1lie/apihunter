# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
