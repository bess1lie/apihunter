from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from urllib.parse import urlparse

import typer
import yaml
from rich.console import Console
from rich.table import Table

from apihunter.core.db import Database
from apihunter.core.exceptions import ApihunterError, PermanentHttpError, ScopeError
from apihunter.core.executor import Executor
from apihunter.core.http_client import HttpClient
from apihunter.core.queries import Queries
from apihunter.core.scope import Scope
from apihunter.discovery.discovery import Discovery
from apihunter.discovery.providers import CrawlDiscoveryProvider, GraphQLDiscoveryProvider, PathDiscoveryProvider
from apihunter.modules.registry import get_default_registry
from apihunter.parser.openapi_parser import parse_spec
from apihunter.report.render import render_html, render_markdown, render_sarif

try:
    from apihunter import __version__
except Exception:
    __version__ = "1.0.0"

app = typer.Typer(help="apihunter — REST API security testing CLI (detection-only, scope-aware)")
console = Console()

_DEFAULT_DB = Path.home() / ".local" / "share" / "apihunter" / "apihunter.db"
_MAX_SPEC_BYTES = 2 * 1024 * 1024


def _resolve_db(db_path: str | None) -> str:
    if db_path:
        p = Path(db_path).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        return str(p)
    # Legacy cwd fallback for backwards compat, but prefer XDG
    cwd_db = Path("apihunter.db")
    if cwd_db.exists():
        return str(cwd_db.resolve())
    _DEFAULT_DB.parent.mkdir(parents=True, exist_ok=True)
    return str(_DEFAULT_DB)


def _validate_target(target: str) -> None:
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        console.print(f"[red]Invalid target scheme: {parsed.scheme or 'empty'} — use http:// or https://[/red]")
        raise typer.Exit(code=2)
    if not parsed.hostname:
        console.print("[red]Invalid target: no hostname[/red]")
        raise typer.Exit(code=2)


def _load_scope(scope_file: str | None) -> Scope:
    if not scope_file:
        return Scope()
    try:
        return Scope.from_yaml(scope_file)
    except ScopeError as e:
        console.print(f"[red]Scope error: {e}[/red]")
        raise typer.Exit(code=2) from e


@app.command()
def discover(
    target: str = typer.Argument(..., help="Target base URL (https://api.example.com)"),
    scope: str | None = typer.Option(None, "--scope", "-s", help="Path to scope.yaml"),
    db: str | None = typer.Option(None, "--db", help="SQLite DB path (default: ~/.local/share/apihunter/apihunter.db)"),
    output: str | None = typer.Option(None, "--output", "-o", help="Write discovered specs as JSON to file"),
    allow_private: bool = typer.Option(False, "--allow-private", help="Allow private/link-local IPs (lab use)"),
):
    """Discover API endpoints using various providers."""
    _validate_target(target)
    scope_obj = _load_scope(scope)
    # Fail-closed: require scope to be non-empty
    if scope and not scope_obj.allow and not scope_obj.deny and not scope_obj.targets:
        console.print("[yellow]Warning: scope file is empty — nothing is in scope. Check docs/scope.md[/yellow]")
    # Pre-check target against scope if scope provided
    if scope and not scope_obj.is_in_scope(target):
        console.print(f"[red]Target {target} is out of scope — blocked. Check scope.yaml[/red]")
        raise typer.Exit(code=2)

    async def _run_discovery():
        async with HttpClient(allow_private=allow_private, scope=scope_obj) as client:
            providers = [
                PathDiscoveryProvider(client, scope=scope_obj),
                GraphQLDiscoveryProvider(client, scope=scope_obj),
                CrawlDiscoveryProvider(client, scope=scope_obj),
            ]
            discovery = Discovery(providers)
            return await discovery.run(target)

    db_path = _resolve_db(db)
    database = Database(db_path)
    database.connect()
    database.initialize()
    try:
        result = asyncio.run(_run_discovery())
        console.print(f"Discovered {len(result.specs)} specs.")
        for spec in result.specs:
            console.print(f"  - {spec.url} [{spec.confidence}]")
        if output:
            out = Path(output)
            out.write_text(
                json.dumps([s.__dict__ if hasattr(s, "__dict__") else str(s) for s in result.specs], indent=2, default=str),
                encoding="utf-8",
            )
            console.print(f"[green]Wrote {output}[/green]")
        if result.errors:
            console.print(f"[yellow]{len(result.errors)} provider errors (see --verbose)[/yellow]")
    except (ApihunterError, PermanentHttpError) as e:
        console.print(f"[red]Discovery failed: {e}[/red]")
        raise typer.Exit(code=1) from e
    finally:
        database.close()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target base URL"),
    scope_file: str | None = typer.Option(None, "--scope", "-s", help="Path to scope.yaml"),
    db: str | None = typer.Option(None, "--db", help="SQLite DB path"),
    allow_private: bool = typer.Option(False, "--allow-private", help="Allow scanning private/link-local IPs (lab use)"),
    profile: str = typer.Option("safe", "--profile", "-p", help="Scan profile: safe|balanced|aggressive"),
    max_requests: int | None = typer.Option(None, "--max-requests", help="Max active requests (overrides profile)"),
    rate_limit: float | None = typer.Option(None, "--rate-limit", help="Requests/sec (overrides profile)"),
    timeout: float | None = typer.Option(None, "--timeout", help="HTTP timeout seconds"),
):
    """Scan target for security findings (detection-only)."""
    _validate_target(target)
    scope = _load_scope(scope_file)
    if scope_file and not scope.is_in_scope(target):
        console.print(f"[red]Target {target} is out of scope — blocked.[/red]")
        raise typer.Exit(code=2)
    if profile not in ("safe", "balanced", "aggressive"):
        console.print(f"[red]Invalid profile: {profile} (choose safe|balanced|aggressive)[/red]")
        raise typer.Exit(code=2)

    db_path = _resolve_db(db)
    database = Database(db_path)
    database.connect()
    database.initialize()
    queries = Queries(database)

    # Profile defaults
    _profile_map = {
        "safe": {"max_requests": 10, "rate": 2.0},
        "balanced": {"max_requests": 20, "rate": 5.0},
        "aggressive": {"max_requests": 50, "rate": 10.0},
    }
    _max_req = max_requests if max_requests is not None else _profile_map[profile]["max_requests"]
    _rate = rate_limit if rate_limit is not None else _profile_map[profile]["rate"]
    _timeout = timeout if timeout is not None else 10.0

    executor_holder: dict = {}
    start_ts = time.monotonic()

    async def _perform_scan(run_id: int):
        async with HttpClient(allow_private=allow_private, timeout=_timeout, rate_per_second=_rate, scope=scope) as client:
            providers = [
                PathDiscoveryProvider(client, scope=scope),
                GraphQLDiscoveryProvider(client, scope=scope),
                CrawlDiscoveryProvider(client, scope=scope),
            ]
            discovery = Discovery(providers)
            discovery_result = await discovery.run(target)
            # Global executor for whole scan (not per-spec) — enforces profile budget across all specs
            executor = Executor(client, scope, target, max_requests=_max_req, timeout=_timeout)
            executor_holder["executor"] = executor
            if profile == "safe":
                registry = get_default_registry()
            else:
                from apihunter.modules.registry import get_experimental_registry

                registry = get_experimental_registry()

            if not discovery_result.specs:
                console.print("[red]No endpoints discovered. Aborting.[/red]")
                return

            console.print(f"Found {len(discovery_result.specs)} specs. Parsing and scanning...")

            scan_run = queries.get_run_by_id(run_id)
            if not scan_run:
                raise RuntimeError("Failed to retrieve scan run.")

            for spec_discovery in discovery_result.specs:
                # Gate fetch with scope
                if not scope.is_in_scope(spec_discovery.url) and (scope.allow or scope.deny or scope.targets):
                    console.print(f"[yellow]Skipping out-of-scope spec: {spec_discovery.url}[/yellow]")
                    continue
                try:
                    resp = await client.get(spec_discovery.url)
                    if resp.status_code != 200:
                        continue
                    ctype = resp.headers.get("content-type", "")
                    if resp.content and len(resp.content) > _MAX_SPEC_BYTES:
                        console.print(f"[yellow]Spec too large, skipping: {spec_discovery.url}[/yellow]")
                        continue
                    # Parse JSON or YAML
                    spec_data: dict
                    if "yaml" in ctype or spec_discovery.url.endswith((".yaml", ".yml")):
                        spec_data = yaml.safe_load(resp.text) or {}
                    else:
                        try:
                            spec_data = resp.json()
                        except json.JSONDecodeError:
                            # Fallback try YAML
                            try:
                                spec_data = yaml.safe_load(resp.text) or {}
                            except yaml.YAMLError as ye:
                                console.print(f"[yellow]Failed to parse {spec_discovery.url}: {ye}[/yellow]")
                                continue
                    # Size guard on paths
                    if isinstance(spec_data.get("paths"), dict) and len(spec_data["paths"]) > 1000:
                        console.print(f"[yellow]Spec has >1000 paths, truncating scan: {spec_discovery.url}[/yellow]")
                        spec_data["paths"] = dict(list(spec_data["paths"].items())[:1000])
                    spec_result = parse_spec(spec_data)
                except PermanentHttpError as e:
                    console.print(f"[yellow]Blocked/failed fetch {spec_discovery.url}: {e}[/yellow]")
                    continue
                except (ApihunterError, ValueError, yaml.YAMLError) as e:
                    console.print(f"[red]Failed to parse {spec_discovery.url}: {e}[/red]")
                    continue

                # --- Save all endpoints first, build map ---
                from urllib.parse import urljoin

                path_to_id: dict[str, int] = {}
                path_method_to_id: dict[tuple[str, str], int] = {}
                for endpoint in spec_result.endpoints:
                    full = urljoin(spec_discovery.url.rsplit("/", 1)[0] + "/", endpoint.path.lstrip("/"))
                    if not scope.is_in_scope(full) and (scope.allow or scope.deny or scope.targets):
                        continue
                    auth_str = "required" if endpoint.auth_required else None
                    ep_id = database.save_endpoint(run_id, endpoint.path, endpoint.method, None, auth_str)
                    if endpoint.path not in path_to_id:
                        path_to_id[endpoint.path] = ep_id
                    path_method_to_id[(endpoint.path, endpoint.method)] = ep_id

                # --- Run analyzers ONCE per spec (fixes duplicate findings bug) ---
                from apihunter.modules.base import AnalyzerContext

                all_findings: list = []
                for analyzer_cls in registry.get_all():
                    try:
                        ctx = AnalyzerContext(target=target, scope=scope, client=client, executor=executor)
                        analyzer = analyzer_cls(context=ctx)
                        findings = await analyzer.analyze(spec_result, scan_run)
                        all_findings.extend(findings)
                    except (ApihunterError, ValueError, TypeError) as e:
                        console.print(f"[yellow]Analyzer {analyzer_cls.__name__} failed: {e}[/yellow]")
                        continue

                # --- Save findings with correct endpoint mapping ---
                for finding in all_findings:
                    ep_id = None
                    # Prefer explicit mapping from Finding
                    f_path = getattr(finding, "endpoint_path", None)
                    f_method = getattr(finding, "endpoint_method", None)
                    if f_path:
                        ep_id = path_method_to_id.get((f_path, f_method or "GET")) or path_to_id.get(f_path)
                        if ep_id is None:
                            # case-insensitive fallback
                            for (p, m), eid in path_method_to_id.items():
                                if p.lower() == f_path.lower() and (not f_method or m == f_method):
                                    ep_id = eid
                                    break
                    # Global findings (no path) saved with NULL endpoint_id
                    database.save_finding(
                        run_id,
                        ep_id,
                        finding.check_type,
                        finding.severity,
                        finding.confidence,
                        finding.title,
                        finding.detail,
                        finding.remediation,
                    )
            database.finish_scan_run(run_id)

    try:
        run_id = database.create_scan_run(target)
        console.print(f"Run ID: [bold]{run_id}[/bold]")
        asyncio.run(_perform_scan(run_id))
        duration = time.monotonic() - start_ts
        # --- Summary (best-effort, no hard failure if DB closed) ---
        try:
            findings = queries.get_findings(run_id)
            endpoints = queries.get_endpoints(run_id)
            req_count = executor_holder.get("executor")._request_count if executor_holder.get("executor") else 0  # type: ignore
            sev_counts = {"high": 0, "medium": 0, "low": 0, "info": 0, "critical": 0}
            for f in findings:
                sev = str(f.severity).lower()
                if sev in sev_counts:
                    sev_counts[sev] += 1
                elif sev == "critical":
                    sev_counts["critical"] += 1
            console.print("")
            console.print(f"[bold]Scan completed[/bold]  Duration: {duration:.1f}s")
            console.print(f"Endpoints: {len(endpoints)}  Requests: {req_count}  Findings: {len(findings)}")
            console.print(
                f"HIGH: {sev_counts['high'] + sev_counts['critical']}  "  # noqa: E501
                f"MEDIUM: {sev_counts['medium']}  LOW: {sev_counts['low']}  INFO: {sev_counts['info']}"
            )
            if findings:
                table = Table(show_header=True, header_style="bold")
                table.add_column("Severity")
                table.add_column("Confidence")
                table.add_column("Title")
                table.add_column("Endpoint")
                table.add_column("Evidence")
                for f in findings[:20]:
                    sev = str(f.severity).upper()
                    conf = str(f.confidence).upper()
                    ep = f"{f.endpoint_method or ''} {f.endpoint_path or '-'}".strip()
                    ev = ""
                    if f.detail and "Evidence:" in f.detail:
                        ev = f.detail.split("Evidence:", 1)[1].strip().split("\n")[0][:80]
                    elif f.detail:
                        ev = f.detail[:80]
                    table.add_row(sev, conf, f.title[:60], ep, ev)
                console.print(table)
                if len(findings) > 20:
                    console.print(f"[dim]... and {len(findings) - 20} more findings (see report)[/dim]")
        except Exception:
            pass
        console.print("[green]Scan complete.[/green]")
    except typer.Exit:
        raise
    except (ApihunterError, PermanentHttpError, ValueError, RuntimeError) as e:
        console.print(f"[red]Error during scan: {e}[/red]")
        raise typer.Exit(code=1) from e
    finally:
        database.close()


@app.command()
def report(
    run_id: int = typer.Argument(..., help="Scan run ID"),
    format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown|html|sarif"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file (default: report_<id>.<ext>)"),
    db: str | None = typer.Option(None, "--db", help="SQLite DB path"),
):
    """Generate a report for a specific scan run."""
    console.print(f"[bold blue]Generating {format} report for run {run_id}...[/bold blue]")

    if db:
        db_path = _resolve_db(db)
    else:
        db_path = _resolve_db(None)
        # Try cwd DB first if report requested without --db flag
        for candidate in [Path("apihunter.db"), _DEFAULT_DB]:
            if candidate.exists():
                db_path = str(candidate.resolve())
                break

    database = Database(db_path)
    database.connect()
    database.initialize()
    queries = Queries(database)

    try:
        run = queries.get_run_by_id(run_id)
        if not run:
            console.print(f"[red]Run ID {run_id} not found.[/red]")
            raise typer.Exit(code=1)

        findings = queries.get_findings(run_id)

        if format == "markdown":
            content = render_markdown(findings)
            filename = output or f"report_{run_id}.md"
        elif format == "html":
            content = render_html(findings)
            filename = output or f"report_{run_id}.html"
        elif format == "sarif":
            content = render_sarif(findings)
            filename = output or f"report_{run_id}.sarif"
        else:
            console.print(f"[red]Unknown format: {format} (choose markdown|html|sarif)[/red]")
            raise typer.Exit(code=2)

        Path(filename).write_text(content, encoding="utf-8")
        console.print(f"[green]Report saved to {filename}[/green]")
    except typer.Exit:
        raise
    except (ApihunterError, ValueError, OSError) as e:
        console.print(f"[red]Error generating report: {e}[/red]")
        raise typer.Exit(code=1) from e
    finally:
        database.close()


@app.command()
def version():
    """Show version."""
    console.print(f"apihunter {__version__}")


if __name__ == "__main__":
    app()
