"""Webhook notifier for scan deltas.

Posts a small JSON payload to the configured webhook URL whenever a
:class:`ScanDiff` shows new or closed findings. The shape is generic
enough to consume in Slack incoming webhooks, Discord webhooks or any
custom HTTP endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from bounty_agent.continuous.diff import ScanDiff
from bounty_agent.core import ScanResult
from bounty_agent.logging_setup import audit, get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class WebhookNotifier:
    """One-shot HTTP POST notifier."""

    url: str
    request_timeout_seconds: float = 5.0

    async def notify(self, scan: ScanResult, diff: ScanDiff) -> bool:
        """Send the diff. Returns True on 2xx, False on any other outcome."""
        if not diff.has_changes:
            return True  # nothing to say; treat as success
        payload = {
            "target": str(scan.target),
            "scan_id": str(scan.scan_id),
            "summary": {
                "new": len(diff.new),
                "repeated": len(diff.repeated),
                "closed": len(diff.closed),
            },
            "new_findings": [
                {
                    "url": str(f.url),
                    "title": f.title,
                    "severity": f.severity.value,
                }
                for f in diff.new
            ],
            "closed_findings": [
                {
                    "url": str(f.url),
                    "title": f.title,
                    "severity": f.severity.value,
                }
                for f in diff.closed
            ],
        }
        try:
            async with httpx.AsyncClient(timeout=self.request_timeout_seconds) as client:
                response = await client.post(self.url, json=payload)
        except httpx.HTTPError as exc:
            logger.warning("webhook.failed", url=self.url, error=str(exc))
            audit("webhook.failed", url=self.url, error=str(exc))
            return False
        success_max = 300
        ok = response.status_code < success_max
        audit(
            "webhook.posted",
            url=self.url,
            status_code=response.status_code,
            new=len(diff.new),
            closed=len(diff.closed),
            ok=ok,
        )
        return ok


__all__ = ["WebhookNotifier"]
