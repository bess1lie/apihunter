# Checks — Detection Confidence & Evidence

> **Heuristic finding ≠ confirmed vulnerability.** All active checks are detection-only, safe probes. Manual verification required.

## Confidence levels

| Confidence | Meaning | Example |
|---|---|---|
| **HIGH** | Direct, reliable config/behavior fact — no heuristic | Missing securitySchemes, CORS `*`+credentials, Server header |
| **MEDIUM** | Active probe with meaningful evidence, but not full exploit proof | CORS reflected Origin, auth bypass 2xx, rate-limit 5x |
| **LOW** | Heuristic with insufficient context — needs extra token / volume / review | IDOR 200 vs 200, injection 500+fragment, info-leak marker, sensitive path |

Evidence is embedded in `detail` as `Evidence: ...` and propagated to SARIF `properties.evidence`.

## Direct Configuration Findings (spec / header facts)

Not automatically "confirmed vulnerabilities" — they are config facts. Risk depends on runtime.

### `spec_security` — Insecure `http://` server URL
- **Mode:** passive (no network)
- **Severity:** MEDIUM **Confidence:** HIGH
- **Evidence:** `server_url='http://...' scheme=http`
- **Limitation:** Lab `http://127.0.0.1` intentionally flags — not production risk.
- **FP risk:** low

### `spec_security` — No securitySchemes but auth_required
- **Mode:** passive
- **Severity:** LOW **Confidence:** MEDIUM
- **Evidence:** `components.securitySchemes=missing auth_required_endpoints>0`
- **FP risk:** medium (spec may use custom auth not declared)

### `headers` — Server header disclosure
- **Mode:** active (1 probe)
- **Severity:** LOW **Confidence:** HIGH
- **Evidence:** `Server='nginx/1.18' X-Powered-By='...'`
- **FP risk:** low (fact)

### `headers` — Missing HSTS (https only)
- **Mode:** active
- **Severity:** MEDIUM **Confidence:** MEDIUM
- **Evidence:** `target=https://... hsts_missing=true`
- **Limitation:** Not reported for `http://` target (no finding).
- **FP risk:** low

## Heuristic Security Findings (require manual verification)

### `idor` — Potential BOLA/IDOR
- **Mode:** passive (no executor) + active probe `id=1` vs `id=2`
- **Severity:** LOW **Confidence:** LOW (always)
- **Evidence:** `status1=200 status2=200 body_len1=XX body_len2=YY diff=ZZ similar_size=true/false`
- **Heuristic:** Yes — needs two different auth contexts (victim vs attacker) to confirm ownership bypass. Current analyzer uses single anonymous context.
- **Negative cases:** identical bodies → no finding; non-object param path → no finding.
- **FP risk:** high if used as vuln — keep LOW.

### `auth` — Potentially Unauthenticated Sensitive Endpoint
- **Mode:** passive
- **Severity:** LOW **Confidence:** LOW
- **Evidence:** `path=/admin auth_required=false sensitive_keyword_match=true`
- **Heuristic:** Yes — path keyword alone not vulnerability; public `/users` may be intentional.
- **FP risk:** high — verify spec auth model.

### `auth` — Potential Authentication Bypass (heuristic)

**When it runs:**
- Only for endpoints where OpenAPI says `auth_required=true` (operation `security` overrides global; `security: []` explicitly disables and skips the check).
- Requires scope with optional `auth.bearer_token` (prefer `${APIHUNTER_BEARER_TOKEN}` via env var). Without token, fallback to single unauth probe.
- Both probes respect `scope.is_in_scope()` — token never sent to out-of-scope host.

**Logic:**

| Unauthenticated | Authenticated (Bearer) | Result |
|---|---|---|
| 401/403 | 401/403 or 2xx | No finding — properly protected |
| 2xx | 2xx | **HIGH / MEDIUM** `Potential Authentication Bypass (heuristic)` — endpoint accepts unauth despite spec, `Evidence: unauthenticated_status=200 authenticated_status=200 ...` |
| 2xx | 401/403 | **LOW / LOW** `Ambiguous authentication result (heuristic)` — token rejected but unauth succeeds, diagnostic only, not HIGH |
| other (500/404) | any | No finding |

- **Mode:** active (1 probe without token; 2 probes with token)
- **Severity:** HIGH (both 2xx) / LOW (ambiguous) **Confidence:** MEDIUM / LOW
- **Evidence (safe):** `method=GET endpoint=/api/protected auth_required=true unauthenticated_status=200 authenticated_status=200 unauthenticated_body_len=54 authenticated_body_len=54` — never includes token or `Authorization` header.
- **Heuristic:** Yes — 200 without auth not always vuln (public endpoint mis-marked, or token invalid). Manual verification required.
- **Negative:** 401/403 without token → no finding; public `auth_required=false` → no finding; `security: []` → no finding.
- **FP risk:** medium — verify spec auth model and test with invalid token.

**How to configure token:**

```yaml
# scope.yaml
allow: ["api.example.com"]
auth:
  bearer_token: "${APIHUNTER_BEARER_TOKEN}"  # recommended — env var
```
```bash
export APIHUNTER_BEARER_TOKEN="lab-test-token"
apihunter scan https://api.example.com --scope scope.yaml --profile balanced
```
Raw `bearer_token: "eyJ..."` is discouraged (keep `chmod 600`, `.gitignore`). Token never appears in `detail`, SQLite, SARIF, Markdown/HTML, or Rich output — only body lengths/statuses are stored. `Scope.to_dict()` redacts to `"***"`.

### `cors` — CORS wildcard with credentials
- **Mode:** active (`Origin: https://example-attacker.invalid`)
- **Severity:** HIGH **Confidence:** HIGH
- **Evidence:** `ACAO='*' ACAC='true' Vary='' tested_origin='https://...'`
- **FP risk:** low

### `cors` — CORS wildcard without credentials
- **Mode:** active
- **Severity:** INFO **Confidence:** MEDIUM
- **Evidence:** `ACAO='*' ACAC=''`
- **Heuristic:** Often intentional for public APIs — not vulnerability. INFO not LOW.
- **FP risk:** high if treated as vuln — correctly INFO.

### `cors` — CORS reflects arbitrary Origin
- **Mode:** active
- **Severity:** HIGH if ACAC true else MEDIUM **Confidence:** MEDIUM
- **Evidence:** `ACAO='https://example-attacker.invalid' ACAC=true/false Vary='...'`
- **Limitation:** Check `Vary: Origin` noted.
- **FP risk:** medium

### `rate_limit` — No rate limiting observed
- **Mode:** active 5 probes
- **Severity:** LOW **Confidence:** LOW
- **Evidence:** `statuses=[200,200,200,200,200] probes=5 no_429=true`
- **Heuristic:** Yes — "Not a vulnerability by itself. Server may rate-limit at higher threshold."
- **Negative:** any 429 → no finding.
- **FP risk:** high if claimed as vuln.

### `injection` — Potential SQL error
- **Mode:** active safe probe `q=test%27` (single quote), no destructive payloads
- **Severity:** MEDIUM **Confidence:** LOW
- **Evidence:** `baseline_status=200 probe_status=500 matched_fragment='sql syntax' snippet='...'`
- **Heuristic:** Yes — 500 + fragment not proof of injection; 400 without fragment → no finding.
- **FP risk:** medium

### `info_leak` — Potential debug/admin endpoint exposed
- **Mode:** passive
- **Severity:** LOW **Confidence:** LOW
- **Evidence:** `path=/api/debug auth_required=false exposed_in_spec=true`
- **Heuristic:** Path alone not vulnerability; auth context noted.

### `info_leak` — Potential Information disclosure in response
- **Mode:** active body marker
- **Severity:** MEDIUM **Confidence:** LOW
- **Evidence:** `marker='Traceback' snippet='...' status=200`
- **Heuristic:** Marker may be benign; verify.

### `headers` — Missing X-Content-Type-Options / X-Frame-Options
- **Severity:** LOW **Confidence:** MEDIUM / LOW
- **Evidence:** header lists
- **FP risk:** low — direct fact but not vuln alone.
