"""JSON Schema export for the ScanResult envelope.

Lets external consumers (dashboards, importers, CI gates) validate
artefacts without depending on the Python package.
"""

from __future__ import annotations

import json
from typing import Any

from bounty_agent.core.models import SCHEMA_VERSION, ScanResult


def scan_result_json_schema() -> dict[str, Any]:
    """Return the JSON Schema (draft 2020-12) for ``ScanResult``."""
    schema = ScanResult.model_json_schema()
    schema["$id"] = f"https://bounty-agent.dev/schemas/scan-result/{SCHEMA_VERSION}.json"
    schema["title"] = f"ScanResult v{SCHEMA_VERSION}"
    return schema


def render_scan_result_json_schema(indent: int = 2) -> str:
    """Render the schema as a JSON string."""
    return json.dumps(scan_result_json_schema(), indent=indent, sort_keys=True)


__all__ = ["render_scan_result_json_schema", "scan_result_json_schema"]
