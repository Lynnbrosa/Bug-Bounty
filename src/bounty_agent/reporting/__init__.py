"""Report rendering: text, markdown, JSON."""

from collections.abc import Mapping
from pathlib import Path

from bounty_agent.core import ScanResult
from bounty_agent.reporting.json_report import render_json
from bounty_agent.reporting.markdown import render_markdown
from bounty_agent.reporting.text import render_text

_RENDERERS: Mapping[str, tuple[str, object]] = {
    "text": ("txt", render_text),
    "markdown": ("md", render_markdown),
    "json": ("json", render_json),
}


def write_reports(
    result: ScanResult,
    output_dir: Path,
    formats: tuple[str, ...],
) -> dict[str, Path]:
    """Write the configured formats to ``output_dir`` and return the paths."""
    output_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for fmt in formats:
        if fmt not in _RENDERERS:
            continue
        extension, renderer = _RENDERERS[fmt]
        text = renderer(result)  # type: ignore[operator]
        path = output_dir / f"scan-{result.scan_id}.{extension}"
        path.write_text(text, encoding="utf-8")
        written[fmt] = path
    return written


__all__ = [
    "render_json",
    "render_markdown",
    "render_text",
    "write_reports",
]
