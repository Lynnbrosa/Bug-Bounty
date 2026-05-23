"""SQLite-backed cache for passive tool output.

Subfinder and waybackurls query public OSINT APIs whose answers change
slowly. This cache layer remembers the items returned for a given
(tool, target) pair and short-circuits the binary invocation for the
duration of ``ttl_seconds``.

The cache is opt-in via ``config.tools_cache.enabled`` and falls back
to a noop implementation when disabled.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Protocol

from sqlalchemy import select

from bounty_agent.persistence.models import ToolCacheRow

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


class ToolCache(Protocol):
    """Read/write protocol for tool caches."""

    def get(self, tool: str, target: str) -> list[str] | None: ...
    def set(self, tool: str, target: str, items: list[str], ttl_seconds: int) -> None: ...


@dataclass
class SqlToolCache:
    """SQLite implementation of :class:`ToolCache`."""

    session_factory: Callable[[], Session]

    def get(self, tool: str, target: str) -> list[str] | None:
        with self.session_factory() as session:
            row = session.execute(
                select(ToolCacheRow).where(
                    ToolCacheRow.tool == tool,
                    ToolCacheRow.target == target,
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            cached_at = row.cached_at
            if cached_at.tzinfo is None:
                # SQLite drops the offset; assume the value we wrote was UTC.
                cached_at = cached_at.replace(tzinfo=UTC)
            expires = cached_at + timedelta(seconds=row.ttl_seconds)
            if expires <= _utcnow():
                return None
            try:
                items = json.loads(row.items_json)
            except json.JSONDecodeError:
                return None
            if not isinstance(items, list):
                return None
            return [str(x) for x in items]

    def set(self, tool: str, target: str, items: list[str], ttl_seconds: int) -> None:
        with self.session_factory() as session:
            existing = session.execute(
                select(ToolCacheRow).where(
                    ToolCacheRow.tool == tool,
                    ToolCacheRow.target == target,
                )
            ).scalar_one_or_none()
            now = _utcnow()
            if existing is not None:
                existing.items_json = json.dumps(items)
                existing.cached_at = now
                existing.ttl_seconds = ttl_seconds
            else:
                session.add(
                    ToolCacheRow(
                        tool=tool,
                        target=target,
                        items_json=json.dumps(items),
                        cached_at=now,
                        ttl_seconds=ttl_seconds,
                    )
                )
            session.commit()


class NoopToolCache:
    """Disabled cache: always misses, never writes."""

    def get(self, tool: str, target: str) -> list[str] | None:  # noqa: ARG002
        return None

    def set(
        self,
        tool: str,  # noqa: ARG002 - protocol signature
        target: str,  # noqa: ARG002
        items: list[str],  # noqa: ARG002
        ttl_seconds: int,  # noqa: ARG002
    ) -> None:
        return None


def _utcnow() -> datetime:
    return datetime.now(UTC)


__all__ = ["NoopToolCache", "SqlToolCache", "ToolCache"]
