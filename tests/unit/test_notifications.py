"""Tests for the webhook notifier."""

from __future__ import annotations

import httpx
import respx

from bounty_agent.core import (
    AuthorizationRecord,
    Finding,
    FindingSource,
    ScanResult,
    Severity,
)
from bounty_agent.notifications import WebhookNotifier


def _result(severity: Severity) -> ScanResult:
    return ScanResult(
        target="https://example.com/",
        authorization=AuthorizationRecord(acknowledged=True),
        findings=[
            Finding(
                url="https://example.com/",
                source=FindingSource.FUZZING,
                severity=severity,
                title="x",
            )
        ],
    )


async def test_no_post_when_no_high_severity(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post("https://example.invalid/hook").mock(return_value=httpx.Response(200))
    notifier = WebhookNotifier(webhook_url="https://example.invalid/hook")
    sent = await notifier.notify(_result(Severity.LOW))
    assert sent is False
    assert not route.called


async def test_posts_payload_for_high_severity(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post("https://example.invalid/hook").mock(return_value=httpx.Response(200))
    notifier = WebhookNotifier(webhook_url="https://example.invalid/hook")
    sent = await notifier.notify(_result(Severity.CRITICAL))
    assert sent is True
    assert route.called
    sent_payload = route.calls.last.request.read().decode("utf-8")
    assert "CRITICAL" in sent_payload


async def test_network_error_returns_false(respx_mock: respx.MockRouter) -> None:
    respx_mock.post("https://example.invalid/hook").mock(side_effect=httpx.ConnectError("boom"))
    notifier = WebhookNotifier(webhook_url="https://example.invalid/hook")
    sent = await notifier.notify(_result(Severity.HIGH))
    assert sent is False
