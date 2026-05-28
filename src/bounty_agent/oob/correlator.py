"""Pos-scan correlator.

The fuzzer registers an :class:`OobToken` whenever it substitutes a
``{OOB_URL}`` placeholder. After the scan finishes, the orchestrator
asks the correlator for the list of callbacks that landed on the
server and pairs them back to their issuing tokens. Each match
becomes a :class:`Finding` with severity ``CRITICAL`` and
``confidence=1.0`` — the backend literally dialled out to us.

The correlator supports two callback sources:

* **Local mode**: the OOB server is running on the same machine and
  persisting to a JSONL log. The correlator opens that log via a
  :class:`CallbackLog`. Useful for development and self-hosted
  single-machine setups.

* **Remote mode**: the OOB server is on a VPS. The correlator polls
  it via :class:`OobClient`. This is the canonical bounty-hunting
  deployment.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from bounty_agent.core import Finding, FindingSource, Severity
from bounty_agent.logging_setup import audit, get_logger
from bounty_agent.oob.client import OobClient
from bounty_agent.oob.server import CallbackEvent, CallbackLog
from bounty_agent.oob.tokens import OobToken

if TYPE_CHECKING:
    from bounty_agent.oob.tokens import TokenRegistry


logger = get_logger(__name__)


@dataclass(frozen=True)
class OobCorrelationConfig:
    """Knobs for one correlation pass."""

    poll_url: str | None = None
    local_log_path: Path | None = None
    wait_seconds: int = 30


class OobCorrelator:
    """Pair CallbackEvents with the OobTokens that issued them."""

    def __init__(self, config: OobCorrelationConfig) -> None:
        self.config = config

    async def correlate(
        self,
        registry: TokenRegistry,
        scan_started_at: datetime,
    ) -> list[Finding]:
        """Wait, fetch callbacks, return findings.

        Waits :attr:`wait_seconds` after being called so callbacks
        that fire late on a slow backend still get caught. The wait
        is interruptible (``asyncio.sleep``).
        """
        wait = max(0, self.config.wait_seconds)
        if wait > 0:
            audit("oob.correlator_waiting", seconds=wait)
            logger.info("oob.correlator_waiting", seconds=wait)
            await asyncio.sleep(wait)

        events = await self._fetch_events(since=scan_started_at)
        if not events:
            audit("oob.correlator_done", matches=0, events=0)
            return []

        findings: list[Finding] = []
        matched = 0
        for event in events:
            token_record = registry.lookup(event.token)
            if token_record is None:
                # Callback for an unknown token: someone else's scan,
                # an old token from a prior run, or scanner reuse of
                # the server. Not a finding for us.
                continue
            matched += 1
            findings.append(_finding_from_match(event, token_record))

        audit("oob.correlator_done", matches=matched, events=len(events))
        return findings

    async def _fetch_events(self, since: datetime) -> list[CallbackEvent]:
        if self.config.poll_url:
            client = OobClient(self.config.poll_url)
            return await client.poll(since=since)
        if self.config.local_log_path:
            log = CallbackLog(persist_path=self.config.local_log_path)
            return log.since(since)
        return []


def _finding_from_match(event: CallbackEvent, token_record: OobToken) -> Finding:
    """Build the CRITICAL finding from one matched callback."""
    delta_seconds = round((event.timestamp - token_record.created_at).total_seconds(), 3)
    return Finding(
        url=token_record.target_url,  # type: ignore[arg-type]
        source=FindingSource.FUZZING,
        severity=Severity.CRITICAL,
        title=(f"Out-of-band callback confirmed: blind {token_record.category}"),
        description=(
            "The target backend dialled the OOB callback server after "
            "receiving an injected payload. This is a direct, "
            "verified-by-side-channel confirmation of a blind "
            f"{token_record.category} vulnerability — confidence 1.0."
        ),
        payload=token_record.payload,
        evidence={
            "token": event.token,
            "callback_method": event.method,
            "callback_path": event.path,
            "callback_host": event.host,
            "callback_src_ip": event.src_ip,
            "callback_user_agent": event.user_agent,
            "callback_protocol": event.protocol,
            "callback_timestamp": event.timestamp.isoformat(),
            "issued_at": token_record.created_at.isoformat(),
            "time_to_callback_seconds": delta_seconds,
            "tool": "oob",
        },
    )


def utcnow() -> datetime:
    """Single timezone-aware now() for the module."""
    return datetime.now(UTC)


__all__ = ["OobCorrelationConfig", "OobCorrelator", "utcnow"]
