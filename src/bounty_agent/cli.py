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
from bounty_agent.eval import evaluate as eval_run
from bounty_agent.eval import load_cases as eval_load_cases
from bounty_agent.llm import LLMClassifier, LLMConfig, apply_verdict
from bounty_agent.logging_setup import audit, configure_logging
from bounty_agent.orchestrator import BountyAgent, default_payload_registry
from bounty_agent.persistence import (
    NoopToolCache,
    ScanRepository,
    SqlToolCache,
    ToolCache,
    make_engine,
    make_session_factory,
)
from bounty_agent.recon.pipeline import run_recon_pipeline
from bounty_agent.reporting import write_reports
from bounty_agent.tools import IntrusiveToolBlocked, ToolRegistry

app = typer.Typer(
    name="bounty-agent",
    help=(
        "Bug bounty research agent. Scope guard is enforced; "
        "use scope.allowlist=['*'] to disable host filtering."
    ),
    no_args_is_help=True,
    add_completion=False,
)

console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"bounty-agent {__version__}")
        raise typer.Exit()


def _load_dotenv_if_present() -> None:
    """Load environment variables from a .env file in the working dir.

    Looks only at ``./.env`` (no ancestor walk) to keep behaviour
    predictable when invoked from inside a nested project. Variables
    already set in the real environment win (override=False), so a
    one-off ``export ANTHROPIC_API_KEY=...`` still beats whatever the
    file says. Silent no-op when no .env exists or the dotenv package
    is missing.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    env_file = Path.cwd() / ".env"
    if env_file.exists():
        load_dotenv(dotenv_path=env_file, override=False)


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
    _load_dotenv_if_present()


@app.command("scan")
def scan_command(  # noqa: PLR0912, PLR0915 - CLI entry point with many options is inherently branchy
    target: Annotated[str, typer.Argument(help="Target URL.")],
    config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            exists=False,
            help="Path to a YAML config (default: config/default.yaml in cwd).",
        ),
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Directory for raw JSON output (overrides reporting.output_dir).",
        ),
    ] = None,
    targets_file: Annotated[
        Path | None,
        typer.Option(
            "--targets-file",
            "-T",
            help="Skip recon and scan the URLs listed in this file (one per line).",
        ),
    ] = None,
    post_targets_file: Annotated[
        Path | None,
        typer.Option(
            "--post-targets",
            "-P",
            help=(
                "JSON file with POST/PUT/PATCH endpoints to body-fuzz. "
                "Format: list of {url, method, body, [categories], [headers]}. "
                "Fields whose body value equals '__FUZZ__' are payload-substituted."
            ),
        ),
    ] = None,
) -> None:
    """Run a modular scan."""
    config = load_config(config_path)
    configure_logging(
        level=config.logging.level,
        audit_log_path=config.logging.audit_log_path,
    )
    audit(
        "cli.scan.invoked",
        target=target,
        config_path=str(config_path) if config_path else None,
    )

    if not config.scope.allowlist:
        err_console.print(
            "[bold red]Refusing to scan.[/bold red] "
            "config.scope.allowlist is empty. Add at least one host (or '*') before running."
        )
        raise typer.Exit(code=3)

    payload_registry = default_payload_registry(config)
    tool_cache = _build_tool_cache(config)
    agent = BountyAgent(
        config=config,
        payload_registry=payload_registry,
        tool_cache=tool_cache,
    )

    preset_targets: list[str] | None = None
    if targets_file is not None:
        if not targets_file.exists():
            err_console.print(f"[bold red]Targets file not found:[/bold red] {targets_file}")
            raise typer.Exit(code=2)
        preset_targets = [
            line.strip()
            for line in targets_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if not preset_targets:
            err_console.print("[bold red]Targets file is empty.[/bold red] Add at least one URL.")
            raise typer.Exit(code=2)

    post_targets: list[dict[str, object]] | None = None
    if post_targets_file is not None:
        if not post_targets_file.exists():
            err_console.print(
                f"[bold red]POST targets file not found:[/bold red] {post_targets_file}"
            )
            raise typer.Exit(code=2)
        try:
            post_targets = json.loads(post_targets_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            err_console.print(f"[bold red]POST targets file is not valid JSON:[/bold red] {exc}")
            raise typer.Exit(code=2) from exc
        if not isinstance(post_targets, list):
            err_console.print(
                "[bold red]POST targets file must contain a JSON list "
                "of {url, method, body, ...} objects.[/bold red]"
            )
            raise typer.Exit(code=2)
        if not post_targets:
            err_console.print("[bold red]POST targets file is empty.[/bold red]")
            raise typer.Exit(code=2)

    try:
        result = asyncio.run(
            agent.scan(target, preset_targets=preset_targets, post_targets=post_targets)
        )
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
    target: Annotated[str, typer.Argument(help="Target URL.")],
) -> None:
    """Run the legacy single-file agent."""
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
    console.print("Now edit [bold]scope.allowlist[/bold] to add hosts (use ['*'] to allow any).")


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


def _build_tool_cache(config: object) -> ToolCache:
    from bounty_agent.config import Config

    assert isinstance(config, Config)
    if not config.tools_cache.enabled or not config.persistence.enabled:
        return NoopToolCache()
    engine = make_engine(config.persistence.sqlite_path)
    factory = make_session_factory(engine)
    return SqlToolCache(session_factory=factory)


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

    if diff.endpoints_added or diff.endpoints_removed:
        console.print(
            f"\n[bold]Surface delta:[/bold] +{len(diff.endpoints_added)} / "
            f"-{len(diff.endpoints_removed)}"
        )
        for url in diff.endpoints_added:
            console.print(f"  [green]+ {url}[/green]")
        for url in diff.endpoints_removed:
            console.print(f"  [red]- {url}[/red]")


def _packaged_default_config() -> Path:
    """Return the path to the bundled default config in the repo layout."""
    here = Path(__file__).resolve()
    # ../../config/default.yaml relative to src/bounty_agent/cli.py
    repo_root = here.parents[2]
    candidate = repo_root / "config" / "default.yaml"
    if not candidate.exists():
        raise FileNotFoundError(f"packaged default config not found at {candidate}")
    return candidate


@app.command("llm-classify")
def llm_classify_command(
    scan_id: Annotated[str, typer.Argument(help="Scan ID to reclassify.")],
    config_path: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    save: Annotated[
        bool,
        typer.Option("--save", help="Persist the reclassified scan back to SQLite."),
    ] = False,
) -> None:
    """Reclassify a stored scan's findings through Claude Haiku 4.5."""
    config = load_config(config_path)
    if not config.llm.enabled:
        err_console.print(
            "[bold red]LLM post-processor is disabled.[/bold red] "
            "Set llm.enabled=true in your config to use this command."
        )
        raise typer.Exit(code=2)
    if not config.persistence.enabled:
        err_console.print("[bold red]Persistence is required to load a scan by id.[/bold red]")
        raise typer.Exit(code=2)

    configure_logging(
        level=config.logging.level,
        audit_log_path=config.logging.audit_log_path,
    )

    repo = _build_repository(config)
    scan = repo.get(scan_id)
    if scan is None:
        err_console.print(f"scan {scan_id} not found")
        raise typer.Exit(code=2)

    classifier = LLMClassifier(
        LLMConfig(
            enabled=True,
            model=config.llm.model,
            max_tokens=config.llm.max_tokens,
            response_excerpt_chars=config.llm.response_excerpt_chars,
        )
    )

    table = Table(title=f"LLM classification ({len(scan.findings)} findings)")
    table.add_column("Title (original)")
    table.add_column("Verdict")
    table.add_column("Refined title")
    table.add_column("Severity")
    table.add_column("Conf")

    new_findings = []
    for finding in scan.findings:
        excerpt = (finding.evidence or {}).get("body_excerpt", "") or ""
        result = classifier.classify(finding, response_excerpt=str(excerpt))
        if result is None:
            new_findings.append(finding)
            table.add_row(finding.title, "skipped", "-", finding.severity.value, "-")
            continue
        verdict = result.verdict
        if verdict.true_positive:
            new_findings.append(apply_verdict(finding, verdict))
        # FP findings are dropped from the saved scan when --save is set.
        table.add_row(
            finding.title,
            "TP" if verdict.true_positive else "FP",
            verdict.refined_title,
            verdict.suggested_severity,
            f"{verdict.confidence:.2f}",
        )

    console.print(table)

    if save:
        updated = scan.model_copy(update={"findings": new_findings})
        repo.save(updated)
        console.print(
            f"[green]Saved {len(new_findings)} findings (was {len(scan.findings)})[/green]"
        )


@app.command("eval")
def eval_command(
    dataset_dir: Annotated[
        Path | None,
        typer.Option("--dataset", "-d", help="Directory of golden cases."),
    ] = None,
) -> None:
    """Run the analyzers against the golden dataset and print metrics."""
    directory = dataset_dir or _default_dataset_dir()
    if not directory.exists():
        err_console.print(f"[bold red]Dataset not found:[/bold red] {directory}")
        raise typer.Exit(code=2)
    cases = eval_load_cases(directory)
    report = eval_run(cases)

    table = Table(title=f"Golden eval ({len(cases)} cases)")
    table.add_column("Category")
    table.add_column("TP")
    table.add_column("FP")
    table.add_column("FN")
    table.add_column("Precision")
    table.add_column("Recall")
    table.add_column("F1")
    for category, metrics in sorted(report.per_category.items()):
        table.add_row(
            category,
            str(metrics.true_positive),
            str(metrics.false_positive),
            str(metrics.false_negative),
            f"{metrics.precision:.2f}",
            f"{metrics.recall:.2f}",
            f"{metrics.f1:.2f}",
        )
    overall = report.overall
    table.add_row(
        "OVERALL",
        str(overall.true_positive),
        str(overall.false_positive),
        str(overall.false_negative),
        f"{overall.precision:.2f}",
        f"{overall.recall:.2f}",
        f"{overall.f1:.2f}",
    )
    console.print(table)

    if report.failures:
        console.print("\n[bold yellow]Failures:[/bold yellow]")
        for failure in report.failures:
            console.print(f"  - {failure}")
        raise typer.Exit(code=1)


def _default_dataset_dir() -> Path:
    here = Path(__file__).resolve()
    repo_root = here.parents[2]
    return repo_root / "tests" / "golden"


@app.command("recon")
def recon_command(
    target: Annotated[str, typer.Argument(help="Target URL or domain.")],
    config_path: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the recon result as JSON to this path."),
    ] = None,
) -> None:
    """Run only the external recon pipeline and print discovered surface."""
    config = load_config(config_path)
    configure_logging(
        level=config.logging.level,
        audit_log_path=config.logging.audit_log_path,
    )
    if not config.scope.allowlist:
        err_console.print("[bold red]Refusing to scan.[/bold red] scope.allowlist is empty.")
        raise typer.Exit(code=3)

    scope = config.scope.as_policy()
    audit("cli.recon.invoked", target=target)
    cache = _build_tool_cache(config)

    try:
        result = asyncio.run(
            run_recon_pipeline(
                target=target,
                config=config,
                scope=scope,
                intrusive_ok=True,
                cache=cache,
            )
        )
    except KeyboardInterrupt:
        err_console.print("[yellow]Interrupted by user.[/yellow]")
        raise typer.Exit(code=130) from None

    table = Table(title=f"Recon for {target}")
    table.add_column("Bucket")
    table.add_column("Count")
    table.add_row("Subdomains", str(len(result.subdomains)))
    table.add_row("URLs", str(len(result.urls)))
    table.add_row("Port findings", str(len(result.findings)))
    table.add_row("Errors", str(len(result.errors)))
    console.print(table)

    if result.subdomains:
        console.print("\n[bold]Subdomains[/bold]")
        for host in result.subdomains:
            console.print(f"  {host}")
    if result.urls:
        console.print("\n[bold]URLs[/bold]")
        for url in result.urls:
            console.print(f"  {url}")
    if result.errors:
        console.print("\n[bold yellow]Errors[/bold yellow]")
        for error in result.errors:
            console.print(f"  - {error}")

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "target": target,
            "subdomains": result.subdomains,
            "urls": result.urls,
            "findings": [f.model_dump(mode="json") for f in result.findings],
            "errors": result.errors,
        }
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"[dim]written to {output}[/dim]")


tools_app = typer.Typer(name="tools", help="External tool wrappers.", no_args_is_help=True)
app.add_typer(tools_app)


@tools_app.command("list")
def tools_list() -> None:
    """List known external tools and whether their binary is installed."""
    registry = ToolRegistry()
    table = Table(title="External tools")
    table.add_column("name")
    table.add_column("intrusive")
    table.add_column("available")
    table.add_column("description")
    for descriptor in registry.describe():
        table.add_row(
            descriptor.name,
            "yes" if descriptor.intrusive else "no",
            "yes" if descriptor.available else "no",
            descriptor.description,
        )
    console.print(table)


@tools_app.command("run")
def tools_run(
    name: Annotated[str, typer.Argument(help="Tool name (see `tools list`).")],
    target: Annotated[str, typer.Argument(help="Domain or URL to feed the tool.")],
    config_path: Annotated[Path | None, typer.Option("--config", "-c")] = None,
) -> None:
    """Run a single tool against a target."""
    config = load_config(config_path)
    configure_logging(
        level=config.logging.level,
        audit_log_path=config.logging.audit_log_path,
    )
    scope = config.scope.as_policy() if config.scope.allowlist else None
    registry = ToolRegistry()
    try:
        result = asyncio.run(registry.run(name, target, scope=scope, intrusive_ok=True))
    except KeyError as exc:
        err_console.print(f"unknown tool: {name}")
        raise typer.Exit(code=2) from exc
    except IntrusiveToolBlocked as exc:
        err_console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=2) from exc

    if result.skipped:
        err_console.print(f"[yellow]skipped:[/yellow] {result.skipped_reason}")
        raise typer.Exit(code=3)

    console.print(f"[bold]{result.tool}[/bold] returned {len(result.items)} item(s):")
    for item in result.items:
        console.print(item)


if __name__ == "__main__":
    sys.exit(app())
