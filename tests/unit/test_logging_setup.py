"""Tests for logging configuration and audit log."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from uuid import uuid4

import pytest

from bounty_agent.logging_setup import (
    AUDIT_LOGGER_NAME,
    audit,
    bind_scan_context,
    clear_scan_context,
    configure_logging,
    get_logger,
)


@pytest.fixture(autouse=True)
def _reset_logging() -> None:
    """Reset application + audit logging between tests."""
    yield
    logging.getLogger().handlers.clear()
    audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)
    for handler in list(audit_logger.handlers):
        audit_logger.removeHandler(handler)
        handler.close()
    clear_scan_context()


def test_configure_logging_is_idempotent(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.log"
    configure_logging(level="DEBUG", audit_log_path=audit_path, json_to_stderr=True)
    configure_logging(level="DEBUG", audit_log_path=audit_path, json_to_stderr=True)
    audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)
    assert len(audit_logger.handlers) == 1


def test_audit_writes_jsonl_when_configured(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.log"
    configure_logging(level="INFO", audit_log_path=audit_path, json_to_stderr=True)

    scan_id = uuid4()
    audit("scan.started", scan_id=str(scan_id), target="https://example.com/")
    audit("authorization.recorded", program="HackerOne / acme")

    for handler in logging.getLogger(AUDIT_LOGGER_NAME).handlers:
        handler.flush()

    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["event"] == "scan.started"
    assert first["scan_id"] == str(scan_id)
    assert first["target"] == "https://example.com/"
    assert "timestamp" in first

    second = json.loads(lines[1])
    assert second["event"] == "authorization.recorded"


def test_audit_noops_when_not_configured() -> None:
    configure_logging(level="INFO", audit_log_path=None, json_to_stderr=True)
    audit("orphan.event", x=1)
    audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)
    assert audit_logger.handlers == []


def test_scan_context_binding_emits_in_application_log(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging(level="INFO", audit_log_path=tmp_path / "audit.log", json_to_stderr=True)

    logger = get_logger("bounty_agent.test")
    scan_id = uuid4()
    bind_scan_context(scan_id=scan_id, target="https://example.com/")
    logger.info("hello")

    captured = capsys.readouterr().err.strip().splitlines()
    assert captured, "expected at least one log line on stderr"
    payload = json.loads(captured[-1])
    assert payload["event"] == "hello"
    assert payload["scan_id"] == str(scan_id)
    assert payload["target"] == "https://example.com/"


def test_audit_log_is_append_only(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.log"
    configure_logging(level="INFO", audit_log_path=audit_path, json_to_stderr=True)
    audit("first")
    for handler in logging.getLogger(AUDIT_LOGGER_NAME).handlers:
        handler.flush()

    configure_logging(level="INFO", audit_log_path=audit_path, json_to_stderr=True)
    audit("second")
    for handler in logging.getLogger(AUDIT_LOGGER_NAME).handlers:
        handler.flush()

    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    assert [json.loads(line)["event"] for line in lines] == ["first", "second"]
