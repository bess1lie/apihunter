# Scope

apihunter is **scope-aware** — every network request is gated by `Scope`.

## File format

Create `scope.yaml` (copy from `scope.example.yaml`):

```yaml
allow:
  - "*.example.com"
  - "api.example.org"
deny:
  - "admin.example.com"
targets:
  - "https://api.example.com"
excluded_extensions:
  - png
  - jpg
  - css
  - js
```

All keys are optional. Empty file = fail-closed (nothing in scope).

| Key | Type | Purpose |
|-----|------|---------|
| `allow` | list[str] | Host patterns to permit (wildcards `*.example.com`, bare `example.com` matches subdomains) |
| `deny` | list[str] | Host patterns to block (evaluated first) |
| `targets` | list[str] | Concrete URLs; when `allow` is empty, host must match one target's hostname |
| `excluded_extensions` | list[str] | Skip discovery URLs ending with these extensions |

## Matching rules

- `*.example.com` matches `api.example.com` but **not** bare `example.com`.
- `example.com` matches `example.com` and `api.example.com`.
- Case-insensitive.
- `fnmatch` wildcards.

## Decision order (`Scope.can_scan`)

1. All lists empty → `False` (fail-closed).
2. Host matches `deny` → `False`.
3. `allow` non-empty → must match at least one `allow`.
4. `allow` empty but `targets` set → must match hostname of at least one target URL.
5. Otherwise (only `deny` set) → `True`.

## CLI usage

```bash
apihunter discover https://api.example.com --scope scope.yaml
apihunter scan https://api.example.com --scope scope.yaml
```

Out-of-scope targets are blocked before any HTTP request. See `apihunter/core/scope.py` for implementation.
