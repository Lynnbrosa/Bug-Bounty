"""Logging configuration for bounty-agent.

Two streams are produced:

* Application log: human friendly via Rich on TTY, JSON lines otherwise.
* Audit log: append-only JSONL file with one record per security-
  relevant event (scan started, authorization recorded, scope decision,
  request issued, finding stored). Never goes through Rich.

The audit log is the trail you keep for legal or program defence in
case a scan is questioned. It does not depend on the application log
configuration and is safe to ship to a SIEM.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from collections.abc import MutableMapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import structlog
from rich.logging import RichHandler

AUDIT_LOGGER_NAME = "bounty_agent.audit"


def _utc_iso(
    _: Any,  # noqa: ANN401 - structlog processor signature is dynamic
    __: str,
    event_dict: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """Stamp every record with an ISO 8601 UTC timestamp."""
    event_dict.setdefault("timestamp", datetime.now(UTC).isoformat())
    return event_dict


def configure_logging(
    level: str = "INFO",
    audit_log_path: Path | str | None = None,
    json_to_stderr: bool = False,
) -> None:
    """Configure structlog and the audit log handler.

    Idempotent: safe to call multiple times in tests.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(log_level)

    if json_to_stderr or not sys.stderr.isatty():
        stream_handler: logging.Handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(logging.Formatter("%(message)s"))
    else:
        stream_handler = RichHandler(
            rich_tracebacks=True,
            show_time=False,
            show_path=False,
            markup=False,
        )
    root.addHandler(stream_handler)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            _utc_iso,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            (
                structlog.processors.JSONRenderer()
                if json_to_stderr or not sys.stderr.isatty()
                else structlog.dev.ConsoleRenderer(colors=True)
            ),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    _configure_audit_logger(audit_log_path)


def _configure_audit_logger(audit_log_path: Path | str | None) -> None:
    audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)
    for handler in list(audit_logger.handlers):
        audit_logger.removeHandler(handler)
        handler.close()
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False

    if audit_log_path is None:
        return

    path = Path(audit_log_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(path, mode="a", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    audit_logger.addHandler(handler)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a structlog-bound logger."""
    return cast("structlog.stdlib.BoundLogger", structlog.get_logger(name))


def bind_scan_context(scan_id: UUID, target: str) -> None:
    """Bind ``scan_id`` and ``target`` into the contextvar context.

    Every subsequent log line in the current async task carries both.
    """
    structlog.contextvars.bind_contextvars(scan_id=str(scan_id), target=target)


def clear_scan_context() -> None:
    """Clear the contextvar context."""
    structlog.contextvars.clear_contextvars()


def audit(event: str, **fields: Any) -> None:  # noqa: ANN401 - audit fields are user-supplied JSON values
    """Write a structured event to the audit log.

    Always JSON, always append-only, never mixed with application log.
    Silently noops if the audit logger has no handler configured.
    """
    audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)
    if not audit_logger.handlers:
        return
    payload: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event": event,
        **fields,
    }
    audit_logger.info(json.dumps(payload, ensure_ascii=False, default=str))


__all__ = [
    "AUDIT_LOGGER_NAME",
    "audit",
    "bind_scan_context",
    "clear_scan_context",
    "configure_logging",
    "get_logger",
]
