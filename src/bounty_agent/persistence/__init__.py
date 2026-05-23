"""SQLite-backed persistence for scans, findings and audit trail."""

from bounty_agent.persistence.db import make_engine, make_session_factory
from bounty_agent.persistence.models import Base, FindingRow, ScanRow, ToolCacheRow
from bounty_agent.persistence.repository import ScanDiff, ScanRepository
from bounty_agent.persistence.tool_cache import (
    NoopToolCache,
    SqlToolCache,
    ToolCache,
)

__all__ = [
    "Base",
    "FindingRow",
    "NoopToolCache",
    "ScanDiff",
    "ScanRepository",
    "ScanRow",
    "SqlToolCache",
    "ToolCache",
    "ToolCacheRow",
    "make_engine",
    "make_session_factory",
]
