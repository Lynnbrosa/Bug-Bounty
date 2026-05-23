"""Top level CLI.

During the refactor this file exposes a single Typer app with one working
subcommand, ``legacy-scan``, that delegates to the original single-file
implementation kept in :mod:`bounty_agent.legacy`.

Real subcommands (``scan``, ``report``, ``history``, ``schema``,
``init-config``, ``audit``) are added in later phases.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Annotated

import typer
from rich.console import Console

from bounty_agent import __version__

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
    version: Annotated[  # noqa: ARG001
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
    """Run the legacy single-file agent. Kept for parity while refactor progresses."""
    if not authorized:
        err_console.print(
            "[bold red]Refusing to scan.[/bold red] "
            "Pass --authorized to confirm you have permission for this target."
        )
        raise typer.Exit(code=2)

    from bounty_agent import legacy

    try:
        results = asyncio.run(legacy.BountyAgent().analyze_target(target))
    except KeyboardInterrupt:
        err_console.print("[yellow]Interrupted by user.[/yellow]")
        raise typer.Exit(code=130) from None

    report = legacy.BountyAgent().generate_report(results)
    console.print(report)


@app.command("scan")
def scan(
    target: Annotated[str, typer.Argument(help="Authorized target URL.")],  # noqa: ARG001
) -> None:
    """Modular scan command. Not implemented yet, use ``legacy-scan`` for now."""
    err_console.print(
        "[yellow]The modular scan command is not implemented yet.[/yellow] "
        "Run [bold]bounty-agent legacy-scan <url> --authorized[/bold] in the meantime."
    )
    raise typer.Exit(code=64)


if __name__ == "__main__":
    sys.exit(app())
