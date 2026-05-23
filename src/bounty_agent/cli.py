"""Top level CLI.

Subcommands:

* ``scan``: run a modular scan against an authorised target.
* ``legacy-scan``: run the original single-file agent (kept for parity).
* ``init-config``: emit a starter configuration file.
* ``schema``: print the JSON Schema of the ScanResult envelope.
* ``audit``: tail the audit log.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from bounty_agent import __version__, legacy
from bounty_agent.config import load_config
from bounty_agent.core import ScopeViolation, render_scan_result_json_schema
from bounty_agent.logging_setup import audit, configure_logging
from bounty_agent.orchestrator import BountyAgent, default_payload_registry
from bounty_agent.persistence import (
    ScanRepository,
    make_engine,
    make_session_factory,
)
from bounty_agent.reporting import write_reports

app = typer.Typer(
    name="bounty-agent",
    help="Responsible bug bounty research agent. Requires explicit authorization.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"bounty-agent {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = False,
) -> None:
    """Responsible bug bounty research agent."""
    _ = version  # consumed by the eager callback


def _confirm_authorisation(authorized: bool, banner: bool = True) -> None:
    if not authorized:
        err_console.print(
            "[bold red]Refusing to scan.[/bold red] "
            "Pass --authorized to confirm you have permission for this target."
        )
        raise typer.Exit(code=2)
    if banner:
        console.print(
            "[bold yellow]Authorised scan mode.[/bold yellow] "
            "Every request will go through the scope guard and be recorded in the audit log."
        )


@app.command("scan")
def scan_command(
    target: Annotated[str, typer.Argument(help="Authorized target URL.")],
    config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            exists=False,
            help="Path to a YAML config (default: config/default.yaml in cwd).",
        ),
    ] = None,
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized",
            help="Confirms you have explicit authorization to test the target.",
        ),
    ] = False,
    output_dir: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Directory for raw JSON output (overrides reporting.output_dir).",
        ),
    ] = None,
) -> None:
    """Run a modular scan."""
    _confirm_authorisation(authorized)
    config = load_config(config_path)
    configure_logging(
        level=config.logging.level,
        audit_log_path=config.logging.audit_log_path,
    )
    audit(
        "cli.scan.invoked",
        target=target,
        program=config.authorization.program,
        config_path=str(config_path) if config_path else None,
    )

    if not config.scope.allowlist:
        err_console.print(
            "[bold red]Refusing to scan.[/bold red] "
            "config.scope.allowlist is empty. Add the target host before running."
        )
        raise typer.Exit(code=3)

    payload_registry = default_payload_registry(config)
    agent = BountyAgent(config=config, payload_registry=payload_registry)

    try:
        result = asyncio.run(agent.scan(target))
    except ScopeViolation as exc:
        err_console.print(f"[bold red]Scope violation:[/bold red] {exc}")
        raise typer.Exit(code=4) from exc
    except KeyboardInterrupt:
        err_console.print("[yellow]Interrupted by user.[/yellow]")
        raise typer.Exit(code=130) from None

    _print_summary(result)

    out_dir = output_dir or Path(config.reporting.output_dir)
    written = write_reports(result, out_dir, config.reporting.formats)
    for fmt, path in written.items():
        console.print(f"[dim]{fmt}: {path}[/dim]")

    if config.persistence.enabled:
        repo = _build_repository(config)
        repo.save(result)
        console.print(f"[dim]scan persisted to {config.persistence.sqlite_path}[/dim]")


def _print_summary(result: object) -> None:
    """Render a Rich table summarising the scan."""
    from bounty_agent.core import ScanResult, Severity

    assert isinstance(result, ScanResult)
    table = Table(title=f"Scan {result.scan_id}")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Target", str(result.target))
    table.add_row("Started", result.started_at.isoformat())
    if result.finished_at:
        table.add_row("Finished", result.finished_at.isoformat())
    table.add_row(
        "WAF",
        ", ".join(result.waf_detection.detected_vendors) or "none detected",
    )
    table.add_row("Endpoints", str(len(result.endpoints)))
    counts = result.counts_by_severity()
    for severity in Severity:
        if counts[severity]:
            table.add_row(severity.value, str(counts[severity]))
    if result.errors:
        table.add_row("Errors", "\n".join(result.errors))
    console.print(table)


@app.command("legacy-scan")
def legacy_scan(
    target: Annotated[str, typer.Argument(help="Authorized target URL.")],
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized",
            help="Confirms you have explicit authorization to test the target.",
        ),
    ] = False,
) -> None:
    """Run the legacy single-file agent."""
    _confirm_authorisation(authorized, banner=False)
    try:
        results = asyncio.run(legacy.BountyAgent().analyze_target(target))
    except KeyboardInterrupt:
        err_console.print("[yellow]Interrupted by user.[/yellow]")
        raise typer.Exit(code=130) from None
    report = legacy.BountyAgent().generate_report(results)
    console.print(report)


@app.command("init-config")
def init_config_command(
    destination: Annotated[
        Path,
        typer.Option(
            "--destination",
            "-d",
            help="Where to write the new config (defaults to ./bounty-agent.yaml).",
        ),
    ] = Path("bounty-agent.yaml"),
    force: Annotated[
        bool,
        typer.Option("--force", help="Overwrite an existing file."),
    ] = False,
) -> None:
    """Copy the packaged default config to a new location."""
    source = _packaged_default_config()
    if destination.exists() and not force:
        err_console.print(
            f"[bold red]{destination} already exists.[/bold red] Use --force to overwrite."
        )
        raise typer.Exit(code=2)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    console.print(f"[green]Wrote[/green] {destination}")
    console.print("Now edit [bold]scope.allowlist[/bold] to add at least one authorised host.")


@app.command("schema")
def schema_command() -> None:
    """Print the JSON Schema of ScanResult."""
    console.print_json(render_scan_result_json_schema())


@app.command("audit")
def audit_command(
    config_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to a YAML config."),
    ] = None,
    tail: Annotated[
        int,
        typer.Option("--tail", "-n", help="Show the last N lines."),
    ] = 50,
) -> None:
    """Tail the configured audit log."""
    config = load_config(config_path)
    if not config.logging.audit_log_path:
        err_console.print("audit log is not configured")
        raise typer.Exit(code=2)
    path = Path(config.logging.audit_log_path)
    if not path.exists():
        err_console.print(f"audit log not found at {path}")
        raise typer.Exit(code=2)
    lines = path.read_text(encoding="utf-8").splitlines()[-tail:]
    for line in lines:
        try:
            console.print_json(json.dumps(json.loads(line)))
        except json.JSONDecodeError:
            console.print(line)


def _build_repository(config: object) -> ScanRepository:
    from bounty_agent.config import Config

    assert isinstance(config, Config)
    engine = make_engine(config.persistence.sqlite_path)
    factory = make_session_factory(engine)
    return ScanRepository(factory)


history_app = typer.Typer(name="history", help="Inspect scan history.", no_args_is_help=True)
app.add_typer(history_app)


@history_app.command("list")
def history_list(
    target: Annotated[str, typer.Argument(help="Target URL to look up.")],
    limit: Annotated[int, typer.Option("--limit", "-n")] = 10,
    config_path: Annotated[Path | None, typer.Option("--config", "-c")] = None,
) -> None:
    """List recent scans for a target."""
    config = load_config(config_path)
    if not config.persistence.enabled:
        err_console.print("persistence is disabled in the config")
        raise typer.Exit(code=2)
    repo = _build_repository(config)
    scans = repo.list_for_target(target, limit=limit)
    if not scans:
        console.print(f"no scans found for {target}")
        return
    table = Table(title=f"History for {target}")
    table.add_column("scan_id")
    table.add_column("started")
    table.add_column("findings")
    for scan in scans:
        table.add_row(
            str(scan.scan_id),
            scan.started_at.isoformat(),
            str(len(scan.findings)),
        )
    console.print(table)


@history_app.command("diff")
def history_diff(
    target: Annotated[str, typer.Argument(help="Target URL to diff.")],
    config_path: Annotated[Path | None, typer.Option("--config", "-c")] = None,
) -> None:
    """Diff the two most recent scans for a target."""
    config = load_config(config_path)
    if not config.persistence.enabled:
        err_console.print("persistence is disabled in the config")
        raise typer.Exit(code=2)
    repo = _build_repository(config)
    pair = repo.latest_two_for_target(target)
    if pair is None:
        err_console.print(f"need at least two scans for {target}")
        raise typer.Exit(code=1)
    baseline, current = pair
    diff = repo.diff(baseline, current)
    console.print(f"[bold]Resolved ({len(diff.resolved)}):[/bold]")
    for finding in diff.resolved:
        console.print(f"  - {finding.title} ({finding.severity.value})")
    console.print(f"\n[bold]New ({len(diff.new)}):[/bold]")
    for finding in diff.new:
        console.print(f"  + {finding.title} ({finding.severity.value})")
    console.print(f"\n[dim]Unchanged: {len(diff.unchanged)}[/dim]")


def _packaged_default_config() -> Path:
    """Return the path to the bundled default config in the repo layout."""
    here = Path(__file__).resolve()
    # ../../config/default.yaml relative to src/bounty_agent/cli.py
    repo_root = here.parents[2]
    candidate = repo_root / "config" / "default.yaml"
    if not candidate.exists():
        raise FileNotFoundError(f"packaged default config not found at {candidate}")
    return candidate


if __name__ == "__main__":
    sys.exit(app())
