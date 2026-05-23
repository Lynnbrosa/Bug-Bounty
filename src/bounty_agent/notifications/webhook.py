"""Optional webhook notifications for high severity findings.

The agent never sends data automatically: callers must build a
:class:`WebhookNotifier` from the config and explicitly invoke it.
The payload follows the Slack incoming webhook shape, which most
chat tools accept either natively or via a connector.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

from bounty_agent.core import Severity
from bounty_agent.logging_setup import audit, get_logger

if TYPE_CHECKING:
    from bounty_agent.core import Finding, ScanResult


logger = get_logger(__name__)

_DEFAULT_THRESHOLD: tuple[Severity, ...] = (Severity.CRITICAL, Severity.HIGH)
_HTTP_OK_MIN = 200
_HTTP_OK_MAX = 300


class WebhookNotifier:
    """Posts a summary of the scan to a Slack-shaped webhook."""

    def __init__(
        self,
        webhook_url: str,
        severity_threshold: tuple[Severity, ...] = _DEFAULT_THRESHOLD,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.webhook_url = webhook_url
        self.severity_threshold = severity_threshold
        self.timeout_seconds = timeout_seconds

    async def notify(self, result: ScanResult) -> bool:
        """Send a message if any finding meets ``severity_threshold``.

        Returns ``True`` if a message was sent and accepted, ``False``
        otherwise. Never raises.
        """
        candidates = self._candidates(result.findings)
        if not candidates:
            return False
        payload = self._build_payload(result, candidates)
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(self.webhook_url, json=payload)
        except httpx.RequestError as exc:
            logger.warning("notifications.failed", error=str(exc))
            audit(
                "notifications.failed",
                scan_id=str(result.scan_id),
                error=str(exc),
            )
            return False

        success = _HTTP_OK_MIN <= response.status_code < _HTTP_OK_MAX
        audit(
            "notifications.sent" if success else "notifications.failed",
            scan_id=str(result.scan_id),
            status_code=response.status_code,
            findings=len(candidates),
        )
        return success

    def _candidates(self, findings: list[Finding] | object) -> list[Finding]:
        from bounty_agent.core import Finding as _F

        return [
            f
            for f in findings  # type: ignore[union-attr]
            if isinstance(f, _F) and f.severity in self.severity_threshold
        ]

    def _build_payload(self, result: ScanResult, findings: list[Finding]) -> dict[str, object]:
        lines = [f"*{f.severity.value.upper()}* {f.title} - {f.url}" for f in findings]
        return {
            "text": (f"Bounty agent: {len(findings)} high-severity finding(s) on {result.target}"),
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "\n".join(lines),
                    },
                }
            ],
        }


__all__ = ["WebhookNotifier"]
