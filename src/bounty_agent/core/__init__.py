"""Core domain models, scope guard and JSON Schema export."""

from bounty_agent.core.models import (
    SCHEMA_VERSION,
    Finding,
    FindingSource,
    ScanResult,
    Severity,
    TargetContext,
    WafDetection,
)
from bounty_agent.core.schema import (
    render_scan_result_json_schema,
    scan_result_json_schema,
)
from bounty_agent.core.scope import ScopeDecision, ScopePolicy, ScopeViolation

__all__ = [
    "SCHEMA_VERSION",
    "Finding",
    "FindingSource",
    "ScanResult",
    "ScopeDecision",
    "ScopePolicy",
    "ScopeViolation",
    "Severity",
    "TargetContext",
    "WafDetection",
    "render_scan_result_json_schema",
    "scan_result_json_schema",
]
