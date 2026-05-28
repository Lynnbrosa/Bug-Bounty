"""Tests for the OOB callback server: extractor + log + end-to-end."""

from __future__ import annotations

import socket
import threading
import time
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

from bounty_agent.oob import CallbackEvent, CallbackLog, OobServer
from bounty_agent.oob.server import extract_token


class TestExtractToken:
    def test_simple_match(self) -> None:
        assert extract_token("abc123.callback.example", "callback.example") == "abc123"

    def test_case_insensitive_root_but_preserves_token_case(self) -> None:
        assert extract_token("aBcDeF.Callback.Example", "callback.example") == "aBcDeF"

    def test_with_port(self) -> None:
        assert extract_token("abc123.callback.example:8080", "callback.example") == "abc123"

    def test_wrong_root_returns_none(self) -> None:
        assert extract_token("abc123.other.example", "callback.example") is None

    def test_root_only_returns_none(self) -> None:
        assert extract_token("callback.example", "callback.example") is None

    def test_multi_level_label_rejected(self) -> None:
        # foo.bar.callback.example has two labels (foo.bar) above the
        # root; we only accept single-label tokens to keep correlation
        # unambiguous.
        assert extract_token("foo.bar.callback.example", "callback.example") is None

    def test_empty_root(self) -> None:
        assert extract_token("anything.example.com", "") is None


class TestCallbackLog:
    def test_append_and_read_all(self) -> None:
        log = CallbackLog()
        event = CallbackEvent(
            token="x",
            protocol="http",
            src_ip="1.2.3.4",
            method="GET",
            path="/",
            host="x.callback.example",
            user_agent="ua",
            timestamp=datetime.now(UTC),
        )
        log.append(event)
        assert log.all_events() == [event]

    def test_since_filters_by_timestamp(self) -> None:
        log = CallbackLog()
        now = datetime.now(UTC)
        old = CallbackEvent(
            "a", "http", "1.1.1.1", "GET", "/", "h", "u", now - timedelta(minutes=5)
        )
        new = CallbackEvent("b", "http", "1.1.1.1", "GET", "/", "h", "u", now)
        log.append(old)
        log.append(new)
        recent = log.since(now - timedelta(minutes=1))
        assert recent == [new]

    def test_persist_and_reload(self, tmp_path: Path) -> None:
        path = tmp_path / "callbacks.jsonl"
        first = CallbackLog(persist_path=path)
        event = CallbackEvent(
            token="x",
            protocol="http",
            src_ip="1.2.3.4",
            method="GET",
            path="/",
            host="x.callback.example",
            user_agent="ua",
            timestamp=datetime.now(UTC),
        )
        first.append(event)
        # New instance loads from disk.
        second = CallbackLog(persist_path=path)
        assert len(second.all_events()) == 1
        assert second.all_events()[0].token == "x"


def _find_free_port() -> int:
    """Find a free local port the OS won't reuse immediately."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestOobServerEndToEnd:
    """Spin up a real server on localhost and POST to it."""

    def test_get_with_valid_host_records_callback(self) -> None:
        port = _find_free_port()
        log = CallbackLog()
        server = OobServer(("127.0.0.1", port), root_domain="callback.test", log=log)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # Use an explicit Host header so we don't need real DNS.
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/probe",
                headers={"Host": "abc123.callback.test"},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                assert resp.status == 200
            # Tiny grace period for the thread that handled the request.
            time.sleep(0.05)
            events = log.all_events()
            assert len(events) == 1
            assert events[0].token == "abc123"
            assert events[0].method == "GET"
            assert events[0].path == "/probe"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_request_with_wrong_host_is_logged_with_no_token(self) -> None:
        port = _find_free_port()
        log = CallbackLog()
        server = OobServer(("127.0.0.1", port), root_domain="callback.test", log=log)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/probe",
                headers={"Host": "wrong.example.com"},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                assert resp.status == 200
            time.sleep(0.05)
            # Server still responds 200 (no info leak) but doesn't
            # record an event because the token couldn't be extracted.
            assert log.all_events() == []
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
