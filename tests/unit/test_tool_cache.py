"""Tests for the SQLite tool cache."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from bounty_agent.persistence import (
    NoopToolCache,
    SqlToolCache,
    make_engine,
    make_session_factory,
)
from bounty_agent.persistence.models import ToolCacheRow


@pytest.fixture
def cache(tmp_path: Path) -> SqlToolCache:
    engine = make_engine(tmp_path / "cache.sqlite")
    factory = make_session_factory(engine)
    return SqlToolCache(session_factory=factory)


def test_miss_returns_none(cache: SqlToolCache) -> None:
    assert cache.get("subfinder", "example.com") is None


def test_set_then_get(cache: SqlToolCache) -> None:
    cache.set("subfinder", "example.com", ["a.example.com", "b.example.com"], 3600)
    assert cache.get("subfinder", "example.com") == ["a.example.com", "b.example.com"]


def test_set_overwrites(cache: SqlToolCache) -> None:
    cache.set("subfinder", "example.com", ["a"], 3600)
    cache.set("subfinder", "example.com", ["b", "c"], 3600)
    assert cache.get("subfinder", "example.com") == ["b", "c"]


def test_expired_entries_return_none(cache: SqlToolCache) -> None:
    # Force an entry with a past cached_at and short TTL.
    with cache.session_factory() as session:
        session.add(
            ToolCacheRow(
                tool="subfinder",
                target="example.com",
                items_json='["stale"]',
                cached_at=datetime.now(UTC) - timedelta(hours=2),
                ttl_seconds=60,
            )
        )
        session.commit()
    assert cache.get("subfinder", "example.com") is None


def test_different_targets_are_isolated(cache: SqlToolCache) -> None:
    cache.set("subfinder", "a.example", ["x"], 3600)
    cache.set("subfinder", "b.example", ["y"], 3600)
    assert cache.get("subfinder", "a.example") == ["x"]
    assert cache.get("subfinder", "b.example") == ["y"]


def test_noop_cache_never_hits() -> None:
    noop = NoopToolCache()
    noop.set("subfinder", "example.com", ["a"], 3600)
    assert noop.get("subfinder", "example.com") is None
