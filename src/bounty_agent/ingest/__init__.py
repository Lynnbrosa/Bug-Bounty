"""Importers that turn third-party API descriptions into scan targets.

Currently supports OpenAPI 3.x (YAML or JSON). Postman collection v2.1
is a future addition; the public ``ingest_openapi_spec`` returns plain
data structures so a sibling Postman importer can produce the same
shape.
"""

from bounty_agent.ingest.openapi import (
    IngestResult,
    ingest_openapi_spec,
    load_openapi_document,
)

__all__ = ["IngestResult", "ingest_openapi_spec", "load_openapi_document"]
