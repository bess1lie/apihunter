# apihunter

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=plastic&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=plastic)](https://opensource.org/licenses/MIT)
[![CI](https://img.shields.io/github/actions/workflow/status/bess1lie/apihunter/ci.yml?branch=main&style=plastic)](https://github.com/bess1lie/apihunter/actions)
[![PyPI](https://img.shields.io/badge/PyPI-apihunter--bess1lie-3776AB?style=plastic&logo=pypi&logoColor=white)](https://pypi.org/project/apihunter-bess1lie/)
[![Stars](https://img.shields.io/github/stars/bess1lie/apihunter?style=plastic)](https://github.com/bess1lie/apihunter/stargazers)
[![Issues](https://img.shields.io/github/issues/bess1lie/apihunter?style=plastic)](https://github.com/bess1lie/apihunter/issues)

<p align="center">
  <img src="https://raw.githubusercontent.com/bess1lie/apihunter/main/docs/banner.svg" alt="apihunter banner" width="100%" />
</p>

<p align="center">
  <strong>Professional REST API security testing CLI -- OpenAPI discovery, authentication auditing, heuristic scanning, and comprehensive reporting.</strong>
</p>

<p align="center">
  <a href="#why-apihunter">Why apihunter</a> •
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#roadmap">Roadmap</a> •
  <a href="#contributing">Contributing</a>
</p>

## 🚀 Demo

```bash
# Discover OpenAPI endpoints
$ apihunter discover https://api.example.com
╭──────────────────── Discovered Endpoints ─────────────────────╮
│ URL                              │ Method │ Auth      │ Status │
├──────────────────────────────────┼────────┼───────────┼────────┤
│ https://api.example.com/v1/users │ GET    │ JWT       │ 200    │
│ https://api.example.com/v1/users │ POST   │ JWT       │ 201    │
│ https://api.example.com/v1/login │ POST   │ None      │ 200    │
│ https://api.example.com/v1/admin │ GET    │ JWT+RBAC  │ 403    │
╰──────────────────────────────────┴────────┴───────────┴────────╯

# Run security scan
$ apihunter scan https://api.example.com
[INFO] Starting scan on 4 endpoints...
[INFO] Testing authentication: 2 endpoints require JWT
[INFO] Testing authorization (IDOR)...
[!] 🔴 CRITICAL: IDOR vulnerability on /v1/users/{id} (GET)
[!] 🟠 HIGH: Missing rate limiting on /v1/login
[!] 🟡 MEDIUM: Verbose error message on /v1/debug
[✓] 🟢 Scan completed in 12.3s

# Generate HTML report
$ apihunter report <run_id> --format html
[✓] 🟢 Report saved to report_<run_id>.html
```

## 🧐 Why apihunter?

| Problem | Manual approach | With apihunter |
|---------|-----------------|----------------|
| **Finding OpenAPI specs** | `grep`, `curl`, guesswork across dozens of endpoints | **Automatic discovery** -- detects Swagger/OpenAPI, GraphQL introspection, and common API patterns |
| **Authentication analysis** | Manual Burp testing, checking each endpoint individually | **Automated auth auditing** -- identifies JWT, OAuth, Basic Auth, and missing auth |
| **Security heuristics** | Random testing, no systematic coverage | **Built-in heuristics** -- IDOR, CORS misconfigurations, injection points, rate limiting |
| **Tracking findings** | Spreadsheets or scattered notes | **SQLite database** + **HTML/Markdown/SARIF** reports with severity badges |
| **CI/CD integration** | Custom scripts that break easily | **CLI-friendly** -- exit codes, JSON output, and SARIF for GitHub Code Scanning |

## ✨ Features

- 🔎 **OpenAPI / Swagger Discovery** -- probes 22 well-known paths (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/graphql`, etc.), parses OpenAPI 2.0/3.0 & Swagger `host+basePath`.
- 🔐 **Authentication Detection** -- detects missing `securitySchemes`, `auth_required` without schemes, and unauthenticated sensitive paths (`/admin`, `/user`, …).
- 🛡️ **Heuristic Security Scanning** -- active (implemented):
  - Missing authentication schemes (HIGH)
  - CORS misconfigurations (Origin reflection, wildcard+credentials)
  - IDOR/BOLA (path param mutation heuristic)
  - Rate limiting (5-probe heuristic)
  - Injection (safe SQL probe)
  - Insecure `http://` servers / Response headers (HSTS/CSP)
  - Info Leak (active body markers / debug endpoints)
- 📊 **Multi‑format Reports** -- HTML (XSS-escaped + CSP), Markdown, SARIF 2.1.0 for GitHub Code Scanning.
- 🗄️ **Local SQLite Storage** -- WAL + FK, parameterized, every scan stored with XDG `~/.local/share/apihunter/apihunter.db`.
- ⚙️ **Scope‑aware** -- `allow/deny/targets/excluded_extensions` enforced on **every** request (`docs/scope.md`).
- 🧩 **Extensible** -- `AnalyzerContext(target, scope, client)` + `AnalyzerRegistry` for custom checks.

## 🛠️ Tech Stack

- **Language:** [Python 3.11+](https://www.python.org/)
- **CLI:** [Typer](https://typer.tiangolo.com/)
- **Terminal output:** [Rich](https://rich.readthedocs.io/)
- **HTTP client:** [HTTPX](https://www.python-httpx.org/)
- **Storage:** [SQLite](https://www.sqlite.org/)
- **Reports:** [Jinja2](https://jinja.palletsprojects.com/)
- **Config:** [PyYAML](https://pyyaml.org/)

## 🏗️ Architecture

<!-- pypi:skip -->
```mermaid
graph TD
    A[CLI Entry] --> B{Command}
    B -->|discover| C[Discover Provider]
    B -->|scan| D[Scan Engine]
    B -->|report| E[Report Generator]
    B -->|db| F[Database Manager]
    
    C --> G[OpenAPI Parser]
    C --> H[GraphQL Introspection]
    C --> I[Common Patterns]
    
    D --> J[Heuristic Modules]
    J --> K[IDOR Checker]
    J --> L[CORS Checker]
    J --> M[Auth Checker]
    J --> N[Injection Detector]
    
    D --> F
    D --> O[Results]
    O --> E
    E --> P[HTML Report]
    E --> Q[Markdown Report]
    E --> R[SARIF Report]
    
    F --> S[SQLite Storage]
    S --> O
    
    style A fill:#58a6ff,stroke:#1f6feb,color:#fff
    style C fill:#3fb950,stroke:#2ea043
    style D fill:#d29922,stroke:#9e6a03
    style E fill:#f0883e,stroke:#d97a00
    style F fill:#f85149,stroke:#da3633
```

- **Discovery Engine**: Injects providers to probe target surfaces.
- **Scanner Engine**: Executes specialized analyzers against discovered endpoints.
- **Core**: Manages the database, HTTP client, and scope.

## 📦 Installation

```bash
# From PyPI (recommended) — detection-only, no payloads
pip install apihunter-bess1lie
# CLI stays `apihunter`
apihunter --help

# Isolated with pipx (recommended for tools)
pipx install apihunter-bess1lie

# From source (latest dev)
git clone https://github.com/bess1lie/apihunter.git
cd apihunter
pip install -e .
```

## ⚡ Quick Start

### Basic usage (scope-aware)

```bash
# 0. Create scope.yaml — every request gated by allowlist
cat > scope.yaml <<'YAML'
allow: ["api.example.com"]
targets: ["https://api.example.com"]
YAML

# 1. Discover endpoints
apihunter discover https://api.example.com --scope scope.yaml

# 2. Scan — profiles: safe (passive+light active, 10 req), balanced (20), aggressive (50)
apihunter scan https://api.example.com --scope scope.yaml --profile safe
apihunter scan https://api.example.com --scope scope.yaml --profile balanced  # default active: auth, IDOR, CORS
apihunter scan https://api.example.com --scope scope.yaml --profile aggressive --max-requests 50 --rate-limit 10

# 3. Report + SARIF for GitHub Code Scanning
apihunter report <run_id> --format html -o report.html
apihunter report <run_id> --format sarif -o apihunter.sarif

# Verify install
apihunter --help && apihunter version
```

> Requires `scope.yaml` — out-of-scope requests are blocked. See `scope.example.yaml` and `docs/scope.md`.

## ⚙️ Configuration

Create a `scope.yaml` file to define your testing boundaries (see `docs/scope.md`):

```yaml
allow:
  - "api.example.com"
  - "*.example.com"
deny:
  - "cdn.example.com"
targets:
  - "https://api.example.com"
excluded_extensions:
  - png
  - css
  - js
```

All keys optional; empty = fail-closed. `allow` supports `*.` wildcards, bare domain matches subdomains.

## 🎛️ Scan Profiles (1.2.0)

| Profile | Max requests | Rate | Checks |
|---------|--------------|------|--------|
| `safe` | 10 | 2/sec | passive (auth, spec_security, info_leak) |
| `balanced` | 20 | 5/sec | + active IDOR/CORS + more |
| `aggressive` | 50 | 10/sec | all experimental (injection, rate_limit, response_headers) |

```bash
apihunter scan https://api.example.com --scope scope.yaml --profile safe
apihunter scan https://api.example.com --scope scope.yaml --profile balanced --timeout 15
apihunter scan https://api.example.com --scope scope.yaml --profile aggressive --max-requests 50
```

All profiles respect `scope.yaml`, `2MB` limit, timeout, and `allow_private=false` by default.

## 🔄 Comparison with alternatives

| Feature | apihunter | Postman | OWASP ZAP | Burp Suite | Custom scripts |
|---------|-----------|---------|-----------|------------|----------------|
| OpenAPI Discovery | ✅ | ❌ (manual) | ❌ (add‑on) | ❌ (manual) | ❌ |
| Authentication Analysis | ✅ | ❌ | ✅ | ✅ | ❌ |
| Heuristic Scanning | ✅ | ❌ | ✅ | ✅ | ❌ |
| Reports (HTML/Markdown/SARIF) | ✅ | ❌ | ✅ | ✅ | ❌ |
| CI/CD Friendly | ✅ | ❌ | ✅ | ❌ | ✅ |
| Lightweight CLI | ✅ | ❌ | ❌ | ❌ | ✅ |
| Scope‑aware | ✅ | ❌ | ❌ | ❌ | ❌ |

## 🗺️ Roadmap

| Status | Feature |
|--------|---------|
| ✅ | OpenAPI 2.0/3.0 discovery + crawl (robots/sitemap/HTML) |
| ✅ | GraphQL introspection (`/graphql` POST) |
| ✅ | HTML / Markdown / SARIF (real locations) |
| ✅ | SQLite storage + scope-aware gating + executor |
| ✅ | Auth (passive + active bypass probe) |
| ✅ | IDOR/BOLA heuristic (active) |
| ✅ | CORS (active Origin probe) |
| ✅ | Rate limiting (5-probe heuristic) |
| ✅ | Injection safe probe (' + SQL fragment) |
| ✅ | Spec security + response headers (HSTS/CSP) |
| ✅ | Info leak (passive + active body markers) |
| 🚧 | Plugin system for custom checks |
| 🔮 | OpenTelemetry integration |
| 🔮 | Web UI dashboard |
| 🔮 | Kubernetes operator |

## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you would like to change.

## 🛡️ Security

If you find a vulnerability, please report it privately to [bess1iework@gmail.com](mailto:bess1iework@gmail.com) — see [SECURITY.md](SECURITY.md).

> **PyPI name:** `pip install apihunter-bess1lie` (import `apihunter`, CLI `apihunter`). The short name `apihunter` is reserved for a future 1.x alias.

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

## 🌐 More Tools

- [**bounthunt**](https://github.com/bess1lie/bounthunt) - Bug bounty reconnaissance and automation.
- [**gqlhunter**](https://github.com/bess1lie/gqlhunter) - GraphQL security testing and introspection.

<p align="center">
  <sub>detection-first · scope-aware · <a href="https://bess1lie.github.io">bess1lie.github.io</a> · <a href="mailto:bess1iework@gmail.com">contact</a></sub>
</p>
