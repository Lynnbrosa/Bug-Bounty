"""JSON report rendering."""

from __future__ import annotations

from bounty_agent.core import ScanResult


def render_json(result: ScanResult, indent: int = 2) -> str:
    """Render the scan result as canonical JSON."""
    return result.model_dump_json(indent=indent)


__all__ = ["render_json"]
