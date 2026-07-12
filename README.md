# <img src="docs/logo.svg" width="60" height="60" /> apihunter

[![PyPI version](https://img.shields.io/pypi/v/apihunter.svg)](https://pypi.org/project/apihunter/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Versions](https://img.shields.io/pypi/pyversions/apihunter.svg)](https://pypi.org/project/apihunter/)
[![Build Status](https://github.com/bess1lie/apihunter/actions/workflows/ci.yml/badge.svg)](https://github.com/bess1lie/apihunter/actions)

<p align="center">
  <img src="docs/banner.svg" alt="apihunter banner" width="100%" />
</p>

<p align="center">
  <strong>Automated REST API security testing CLI — OpenAPI discovery, auth analysis, and security heuristics.</strong>
</p>

<p align="center">
  <a href="https://github.com/bess1lie/apihunter/issues">Report Bug</a> •
  <a href="https://github.com/bess1lie/apihunter/contributing">Contribute</a> •
  <a href="https://github.com/bess1lie/apihunter/releases">Releases</a>
</p>

---

## 🚀 Overview

**apihunter** is a high-performance, modular security tool built for bug hunters and security engineers. It automs the most tedious parts of API reconnaissance: finding specification files, mapping endpoint structures, and identifying low-hanging fruit like weak authentication or information leaks.

Built with `asyncio` and `httpx`, it is designed to scale with your targets.

---

## ✨ Key Features

| Feature | Description |
| :--- | :--- |
| 🔍 **Smart Discovery** | Automatically finds OpenAPI, Swagger, and GraphQL specs. |
| 🛡️ **Heuristic Scanning** | Detects injection, IDOR, CORS misconfigs, and info leaks. |
| 🔐 **Auth Auditing** | Analyates authentication schemes and bypass potential. |
| 📊 **Professional Reports** | Outputs in HTML, Markdown, and SARIF for CI/CD integration. |
| ⚡ **Blazing Fast** | Fully asynchronous engine for massive concurrency. |

---

## 🛠 Quick Start

### Installation

```bash
pip install apihunter
```

### Basic Workflow

1. **Discover** endpoints and specs:
```bash
apihunter discover https://api.example.com
```
![Discovery](docs/screenshots/discover.svg)

2. **Scan** for vulnerabilities:
```bash
apihunter scan https://api.example.com
```
![Scan](docs/screenshots/scan.svg)

3. **Generate** a report:
```bash
apihunter report <run_id> --format html
```
![Report](docs/screenshots/report-html.svg)

---

## 🏗 Architecture

apihunter utilizes a provider-based orchestration engine.

```mermaid
graph TD
    A[CLI] --> B[Orchestrator]
    B --> C[Discovery Engine]
    B --> D[Scanner Engine]
    C --> C1[Path Provider]
    C --> C2[Other Providers]
    D --> D1[Auth Analyzer]
    D --> D2[Injection Analyzer]
    D --> D3[CORS Analyzer]
    B --> E[(SQLite DB)]
    D --> F[Reporting Engine]
```

- **Discovery Engine**: Injects providers to probe target surfaces.
- **Scanner Engine**: Executes specialized analyzers against discovered endpoints.
- **Core**: Manly manages the database, HTTP client, and scope.

---

## ⚙️ Configuration

Control your scan via a `scope.yaml` file.

```yaml
targets:
  - https://api.example.com
exclude_extensions:
  - .png
  - .jpg
  - .css
deny:
  - https://api.example.com/admin/*
```

Run with scope:
```bash
apihunter scan https://api.example.com --scope-file scope.yaml
```

---

## 🗺 Roadmap

- [ ] **Advanced Discovery**: DNS and subdomain enumeration integration.
- [ ] **GraphQL Deep Scan**: Advanced query-based injection testing.
- [ ] **Live Dashboard**: Real-time web UI for monitoring active scans.
- [ ] **Cloud Integration**: Automated AWS/GCP/Azure metadata probing.

---

## 🤝 Contributing

We love contributions! Please follow our [CONTRIBUTING.md](CONTRIBUTING.md) to help make apihunter even better.

## 🔒 Security

If you find a vulnerability, please **do not open a public issue**. Report it privately via [SECURITY.md](SECURITY.md).

## 📄 License

[MIT](LICENSE)
