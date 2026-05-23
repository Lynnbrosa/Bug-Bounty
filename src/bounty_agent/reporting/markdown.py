"""Markdown report rendering via jinja2."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from bounty_agent.core import ScanResult, Severity

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=select_autoescape(disabled_extensions=("j2",)),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_markdown(result: ScanResult) -> str:
    env = _environment()
    template = env.get_template("scan_report.md.j2")
    counts = result.counts_by_severity()
    # Show severities in the canonical ladder, including zeroes.
    ordered = {severity: counts[severity] for severity in Severity}
    return template.render(result=result, counts=ordered)


__all__ = ["render_markdown"]
