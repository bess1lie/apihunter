from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import urlparse

import typer
import yaml
from rich.console import Console

from apihunter.core.db import Database
from apihunter.core.exceptions import ApihunterError, PermanentHttpError, ScopeError
from apihunter.core.http_client import HttpClient
from apihunter.core.queries import Queries
from apihunter.core.scope import Scope
from apihunter.discovery.discovery import Discovery
from apihunter.discovery.providers import PathDiscoveryProvider
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
        async with HttpClient() as client:
            provider = PathDiscoveryProvider(client, scope=scope_obj)
            discovery = Discovery([provider])
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
                json.dumps(
                    [s.__dict__ if hasattr(s, "__dict__") else str(s) for s in result.specs], indent=2, default=str
                ),
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
    allow_private: bool = typer.Option(
        False, "--allow-private", help="Allow scanning private/link-local IPs (lab use)"
    ),
):
    """Scan target for security findings (detection-only)."""
    _validate_target(target)
    scope = _load_scope(scope_file)
    if scope_file and not scope.is_in_scope(target):
        console.print(f"[red]Target {target} is out of scope — blocked.[/red]")
        raise typer.Exit(code=2)

    db_path = _resolve_db(db)
    database = Database(db_path)
    database.connect()
    database.initialize()
    queries = Queries(database)

    async def _perform_scan(run_id: int):
        async with HttpClient(allow_private=allow_private) as client:
            provider = PathDiscoveryProvider(client, scope=scope)
            discovery = Discovery([provider])
            discovery_result = await discovery.run(target)

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

                for endpoint in spec_result.endpoints:
                    # Build full URL for scope check correctly
                    from urllib.parse import urljoin

                    full = urljoin(spec_discovery.url.rsplit("/", 1)[0] + "/", endpoint.path.lstrip("/"))
                    if not scope.is_in_scope(full) and (scope.allow or scope.deny or scope.targets):
                        continue

                    ep_id = database.save_endpoint(
                        run_id, endpoint.path, endpoint.method, endpoint.status_code, endpoint.auth_required
                    )

                    registry = get_default_registry()
                    for analyzer_cls in registry.get_all():
                        try:
                            analyzer = analyzer_cls(context=None)
                            findings = await analyzer.analyze(spec_result, scan_run)
                        except (ApihunterError, ValueError, TypeError) as e:
                            console.print(f"[yellow]Analyzer {analyzer_cls.__name__} failed: {e}[/yellow]")
                            continue
                        for finding in findings:
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
):
    """Generate a report for a specific scan run."""
    console.print(f"[bold blue]Generating {format} report for run {run_id}...[/bold blue]")

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
