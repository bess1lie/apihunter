from __future__ import annotations

import asyncio

import typer
from rich.console import Console

from apihunter.core.db import Database
from apihunter.core.http_client import HttpClient
from apihunter.core.queries import Queries
from apihunter.core.scope import Scope
from apihunter.discovery.discovery import Discovery
from apihunter.discovery.providers import PathDiscoveryProvider
from apihunter.modules.registry import get_default_registry
from apihunter.parser.openapi_parser import parse_spec
from apihunter.report.render import render_html, render_markdown, render_sarif

app = typer.Typer(help="apihunter — REST API security testing CLI")
console = Console()


@app.command()
def discover(target: str):
    """Discover API endpoints using various providers."""
    console.print(f"[bold blue]Discovering endpoints for:[/bold blue] {target}")

    async def _run_discovery():
        async with HttpClient() as client:
            provider = PathDiscoveryProvider(client)
            discovery = Discovery([provider])
            return await discovery.run(target)

    db = Database("apihunter.db")
    db.connect()
    db.initialize()

    result = asyncio.run(_run_discovery())
    console.print(f"Discovered {len(result.specs)} specs.")
    db.close()


@app.command()
def scan(target: str, scope_file: str | None = None):
    """Scan target for security vulnerabilities."""
    console.print(f"[bold blue]Scanning target:[/bold blue] {target}")

    scope = Scope.from_yaml(scope_file) if scope_file else Scope()
    db = Database("apihunter.db")
    db.connect()
    db.initialize()
    queries = Queries(db)

    async def _perform_scan(run_id: int):
        async with HttpClient() as client:
            discovery = Discovery([PathDiscoveryProvider(client)])
            discovery_result = await discovery.run(target)

            if not discovery_result.specs:
                console.print("[red]No endpoints discovered. Aborting.[/red]")
                return

            console.print(f"Found {len(discovery_result.specs)} specs. Parsing and scanning...")

            scan_run = queries.get_run_by_id(run_id)
            if not scan_run:
                raise Exception("Failed to retrieve scan run.")

            for spec_discovery in discovery_result.specs:
                try:
                    resp = await client.get(spec_discovery.url)
                    if resp.status_code != 200:
                        continue
                    spec_data = resp.json()
                    spec_result = parse_spec(spec_data)
                except Exception as e:
                    console.print(f"[red]Failed to parse {spec_discovery.url}: {e}[/red]")
                    continue

                for endpoint in spec_result.endpoints:
                    if not scope.is_in_scope(f"{spec_discovery.url}{endpoint.path}"):
                        continue

                    ep_id = db.save_endpoint(
                        run_id, endpoint.path, endpoint.method, endpoint.status_code, endpoint.auth_required
                    )

                    registry = get_default_registry()
                    for analyzer_cls in registry.get_all():
                        analyzer = analyzer_cls(context=None)
                        findings = await analyzer.analyze(spec_result, scan_run)
                        for finding in findings:
                            db.save_finding(
                                run_id,
                                ep_id,
                                finding.check_type,
                                finding.severity,
                                finding.confidence,
                                finding.title,
                                finding.detail,
                                finding.remediation,
                            )
            db.finish_scan_run(run_id)

    try:
        run_id = db.create_scan_run(target)
        console.print(f"Run ID: [bold]{run_id}[/bold]")
        asyncio.run(_perform_scan(run_id))
        console.print("[green]Scan complete.[/green]")
    except Exception as e:
        console.print(f"[red]Error during scan: {e}[/red]")
    finally:
        db.close()


@app.command()
def report(run_id: int, format: str = "markdown"):
    """Generate a report for a specific scan run."""
    console.print(f"[bold blue]Generating {format} report for run {run_id}...[/bold blue]")

    db = Database("apihunter.db")
    db.connect()
    db.initialize()
    queries = Queries(db)

    try:
        run = queries.get_run_by_id(run_id)
        if not run:
            console.print(f"[red]Run ID {run_id} not found.[/red]")
            return

        findings = queries.get_findings(run_id)

        if format == "markdown":
            content = render_markdown(findings)
            filename = f"report_{run_id}.md"
        elif format == "html":
            content = render_html(findings)
            filename = f"report_{run_id}.html"
        elif format == "sarif":
            content = render_sarif(findings)
            filename = f"report_{run_id}.sarif"
        else:
            console.print(f"[red]Unknown format: {format}[/red]")
            return

        with open(filename, "w") as f:
            f.write(content)

        console.print(f"[green]Report saved to {filename}[/green]")
    except Exception as e:
        console.print(f"[red]Error generating report: {e}[/red]")
    finally:
        db.close()


@app.command()
def version():
    """Show version."""
    console.print("apihunter 0.1.0")


if __name__ == "__main__":
    app()
