"""HTTP polling client for a remote OOB server.

Used when the scanner runs on a different machine from the callback
receiver. The client hits the server's ``/__oob/callbacks`` endpoint
and decodes the JSON into :class:`CallbackEvent` instances.

For local-only deployments, the orchestrator can also read the
callback log directly from disk via
:meth:`bounty_agent.oob.server.CallbackLog` constructed with the same
``persist_path``. The client is only needed for cross-machine setups.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import httpx

from bounty_agent.logging_setup import get_logger
from bounty_agent.oob.server import CallbackEvent

logger = get_logger(__name__)


class OobClient:
    """HTTP polling against ``/__oob/callbacks``."""

    def __init__(
        self,
        server_url: str,
        request_timeout_seconds: float = 10.0,
    ) -> None:
        # Normalise: drop a trailing slash so we can append the path.
        self.server_url = server_url.rstrip("/")
        self.request_timeout_seconds = request_timeout_seconds

    async def poll(self, since: datetime | None = None) -> list[CallbackEvent]:
        """Fetch callbacks newer than ``since`` (inclusive)."""
        params: dict[str, str] = {}
        if since is not None:
            params["since"] = since.isoformat()
        url = f"{self.server_url}/__oob/callbacks"
        try:
            async with httpx.AsyncClient(timeout=self.request_timeout_seconds) as client:
                response = await client.get(url, params=params)
        except httpx.HTTPError as exc:
            logger.warning("oob.poll_failed", url=url, error=str(exc))
            return []

        if response.status_code != 200:  # noqa: PLR2004 - HTTP 200 is the literal contract
            logger.warning(
                "oob.poll_unexpected_status",
                url=url,
                status=response.status_code,
                body_excerpt=response.text[:120],
            )
            return []
        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            logger.warning("oob.poll_invalid_json", error=str(exc))
            return []
        events_raw = payload.get("events", []) if isinstance(payload, dict) else []
        events: list[CallbackEvent] = []
        for raw in events_raw:
            event = _event_from_dict(raw)
            if event is not None:
                events.append(event)
        return events


def _event_from_dict(raw: Any) -> CallbackEvent | None:  # noqa: ANN401 - JSON shape
    if not isinstance(raw, dict):
        return None
    try:
        return CallbackEvent(
            token=str(raw["token"]),
            protocol=str(raw["protocol"]),
            src_ip=str(raw["src_ip"]),
            method=str(raw["method"]),
            path=str(raw["path"]),
            host=str(raw["host"]),
            user_agent=str(raw.get("user_agent", "")),
            timestamp=datetime.fromisoformat(str(raw["timestamp"])),
        )
    except (KeyError, ValueError, TypeError) as exc:
        logger.info("oob.event_decode_failed", error=str(exc))
        return None


__all__ = ["OobClient"]
