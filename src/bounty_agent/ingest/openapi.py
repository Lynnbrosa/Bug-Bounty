"""OpenAPI 3.x ingestion.

Reads a spec and emits two artefacts:

* a ``targets.txt`` for every GET path (one URL per line, query
  parameters injected with placeholder values),
* a ``post-targets.json`` for every non-GET path, with body schemas
  converted to ``{OOB_URL}``-free templates that mark every fuzzable
  field with the standard ``__FUZZ__`` marker.

The agent then consumes those files via ``--targets-file`` and
``--post-targets``. No new code path is needed; the importer is a
one-shot CLI subcommand the operator runs before scanning.

The parser is intentionally permissive: missing schemas become empty
bodies, unresolvable $refs are skipped with a console warning. The
output is meant to be reviewed by the operator before kicking off a
scan, not consumed blindly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from bounty_agent.fuzzing import FUZZ_MARKER

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")


@dataclass(frozen=True)
class IngestResult:
    """Outcome of one ingest run."""

    targets: list[str] = field(default_factory=list)
    post_targets: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def load_openapi_document(path: Path) -> dict[str, Any]:
    """Read a JSON or YAML OpenAPI document. Raises on parse failure."""
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level must be a mapping")
    return data


def ingest_openapi_spec(
    document: dict[str, Any],
    base_url: str | None = None,
) -> IngestResult:
    """Walk the spec and produce targets + post-targets.

    ``base_url`` overrides the document's ``servers[0].url``. Useful
    when the spec ships with a placeholder like ``http://api.example``
    and the operator is scanning a real deployment.
    """
    result_targets: list[str] = []
    result_post: list[dict[str, Any]] = []
    warnings: list[str] = []

    server = base_url or _first_server_url(document)
    if not server:
        warnings.append(
            "No base URL: pass --base-url or add a servers[] entry to the spec."
        )
        server = ""
    server = server.rstrip("/")

    paths = document.get("paths") or {}
    if not isinstance(paths, dict):
        warnings.append("`paths` is missing or not an object.")
        return IngestResult(targets=[], post_targets=[], warnings=warnings)

    for raw_path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            url = _build_url(server, str(raw_path), operation)
            if method == "get":
                result_targets.append(url)
            else:
                body_template = _body_template(operation, document, warnings)
                result_post.append(
                    {
                        "url": url,
                        "method": method.upper(),
                        "body": body_template,
                    }
                )

    return IngestResult(
        targets=sorted(set(result_targets)),
        post_targets=result_post,
        warnings=warnings,
    )


def _first_server_url(document: dict[str, Any]) -> str | None:
    servers = document.get("servers")
    if not isinstance(servers, list) or not servers:
        return None
    first = servers[0]
    if not isinstance(first, dict):
        return None
    url = first.get("url")
    return str(url) if isinstance(url, str) else None


def _build_url(server: str, path: str, operation: dict[str, Any]) -> str:
    """Build a fully-formed URL, substituting path params with placeholders."""
    rendered_path = path
    parameters = operation.get("parameters") or []
    if not isinstance(parameters, list):
        parameters = []
    query_pairs: list[str] = []
    for raw in parameters:
        if not isinstance(raw, dict):
            continue
        name = raw.get("name")
        param_in = raw.get("in")
        if not isinstance(name, str) or not isinstance(param_in, str):
            continue
        if param_in == "path":
            rendered_path = rendered_path.replace("{" + name + "}", "1")
        elif param_in == "query":
            query_pairs.append(f"{name}=1")
    suffix = ("?" + "&".join(query_pairs)) if query_pairs else ""
    if not rendered_path.startswith("/"):
        rendered_path = "/" + rendered_path
    return f"{server}{rendered_path}{suffix}"


def _body_template(
    operation: dict[str, Any],
    document: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    request_body = operation.get("requestBody")
    if not isinstance(request_body, dict):
        return {}
    content = request_body.get("content")
    if not isinstance(content, dict):
        return {}
    # Prefer application/json; fall back to any object-shaped schema.
    json_content = content.get("application/json") or next(
        (v for v in content.values() if isinstance(v, dict)),
        None,
    )
    if not isinstance(json_content, dict):
        return {}
    schema = json_content.get("schema")
    if not isinstance(schema, dict):
        return {}
    return _schema_to_template(schema, document, warnings)


def _schema_to_template(
    schema: dict[str, Any],
    document: dict[str, Any],
    warnings: list[str],
    depth: int = 0,
) -> dict[str, Any]:
    max_depth = 5
    if depth > max_depth:
        return {}
    if "$ref" in schema:
        resolved = _resolve_ref(schema["$ref"], document)
        if resolved is None:
            warnings.append(f"Unresolvable $ref: {schema['$ref']}")
            return {}
        return _schema_to_template(resolved, document, warnings, depth=depth + 1)
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return {}
    template: dict[str, Any] = {}
    for prop_name, prop_schema in properties.items():
        if not isinstance(prop_schema, dict):
            continue
        # Mark string fields as fuzzable; everything else gets a typed
        # baseline literal so the request still validates.
        prop_type = prop_schema.get("type")
        if prop_type == "string":
            template[prop_name] = FUZZ_MARKER
        elif prop_type in {"integer", "number"}:
            template[prop_name] = 1
        elif prop_type == "boolean":
            template[prop_name] = True
        elif prop_type == "array":
            template[prop_name] = []
        elif prop_type == "object" or "properties" in prop_schema:
            template[prop_name] = _schema_to_template(
                prop_schema, document, warnings, depth=depth + 1
            )
        else:
            # Unknown / oneOf / anyOf: default to FUZZ_MARKER so the
            # operator at least exercises something.
            template[prop_name] = FUZZ_MARKER
    return template


def _resolve_ref(ref: str, document: dict[str, Any]) -> dict[str, Any] | None:
    """Resolve a local ``#/...`` JSON pointer. External refs not supported."""
    if not ref.startswith("#/"):
        return None
    cursor: Any = document
    for part in ref[2:].split("/"):
        if isinstance(cursor, dict) and part in cursor:
            cursor = cursor[part]
        else:
            return None
    return cursor if isinstance(cursor, dict) else None


__all__ = ["IngestResult", "ingest_openapi_spec", "load_openapi_document"]
