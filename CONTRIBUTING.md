# Contributing to apihunter

Thanks for your interest! This project is open to contributions that improve
stability, documentation, and functionality within the scope of bug bounty
reconnaissance.

## Getting Started

1. Fork the repository.
2. Install dependencies: `pip install -e ".[dev]"`
3. Install pre-commit hooks: `pre-commit install`
4. Create a feature branch: `git checkout -b feat/my-feature`

## Development Guidelines

### Code style

- Python 3.11+ with full type annotations.
- Run `ruff check .` and `ruff format .` before committing.
- Pre-commit hooks run ruff automatically.

### Tests

- All contributions must include or update tests.
- Run tests: `pytest`
- Keep tests fast — no network calls, mock external tools.
- Target: 90+ tests, all passing.

### Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add support for custom rate limiting
fix: handle empty scope file gracefully
docs: update quickstart with docker example
test: add case for out-of-scope domain
```

### Pull request process

1. Ensure all tests pass and ruff is clean.
2. Write a clear PR description with motivation and testing notes.
3. Link any related issues.

## Scope of contributions

This project does **not** accept contributions that:
- Implement automated exploitation.
- Remove or weaken the scope guard.
- Reduce safety defaults for nuclei (`--include-intrusive` must remain opt-in).
- Add dependencies on web frameworks for the core CLI (web UI is a separate concern).

## Questions?

Open a [GitHub Discussion](https://github.com/bess1lie/apihunter/discussions).
