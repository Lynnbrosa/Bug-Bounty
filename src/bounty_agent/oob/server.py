"""HTTP listener that records every incoming request as a callback.

The scanner expects a deployment where a wildcard DNS record points
``*.callback.<owned-domain>`` at this server. When a target processes
an OOB payload like ``http://abc123xyz.callback.example/probe``, the
target's backend resolves the domain (via the wildcard) and HTTPs the
server. The server extracts ``abc123xyz`` from the Host header, logs
it, and the scanner correlates that token back to the payload that
issued it.

This module implements only the HTTP receiver. DNS-level callback
detection (queries that never reach an HTTP handler — common in
hardened environments that block egress HTTP but allow DNS) is a
future addition.

Lightweight by design: no auth, no rate-limiting, no TLS. Run behind
a reverse proxy (nginx/Caddy) for production deployments.
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Self


@dataclass(frozen=True)
class CallbackEvent:
    """One recorded HTTP request against the OOB server."""

    token: str
    protocol: str  # "http" for v1. "dns" reserved for the next phase.
    src_ip: str
    method: str
    path: str
    host: str
    user_agent: str
    timestamp: datetime

    def to_jsonl(self) -> str:
        payload = asdict(self)
        payload["timestamp"] = self.timestamp.isoformat()
        return json.dumps(payload)

    @classmethod
    def from_jsonl(cls, line: str) -> Self:
        data = json.loads(line)
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)


class CallbackLog:
    """Thread-safe append-only log of received callbacks.

    The log is the source of truth that the scanner polls. Events are
    held in memory AND optionally appended to disk so a long-running
    server survives restarts. Reads are filtered by timestamp so a
    polling client can ask "anything new since 5 seconds ago".
    """

    def __init__(self, persist_path: Path | None = None) -> None:
        self._events: list[CallbackEvent] = []
        self._lock = threading.Lock()
        self._persist_path = persist_path
        if persist_path is not None and persist_path.exists():
            self._load_from_disk(persist_path)

    def append(self, event: CallbackEvent) -> None:
        with self._lock:
            self._events.append(event)
        if self._persist_path is not None:
            self._append_to_disk(event)

    def since(self, ts: datetime) -> list[CallbackEvent]:
        """Return every event whose timestamp is >= ``ts``."""
        with self._lock:
            return [e for e in self._events if e.timestamp >= ts]

    def all_events(self) -> list[CallbackEvent]:
        with self._lock:
            return list(self._events)

    def _load_from_disk(self, path: Path) -> None:
        with path.open(encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                try:
                    self._events.append(CallbackEvent.from_jsonl(line))
                except (ValueError, KeyError, json.JSONDecodeError):
                    continue

    def _append_to_disk(self, event: CallbackEvent) -> None:
        assert self._persist_path is not None
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        with self._persist_path.open("a", encoding="utf-8") as fh:
            fh.write(event.to_jsonl() + "\n")


def extract_token(host_header: str, root_domain: str) -> str | None:
    """Pull the leftmost label out of ``<token>.<root_domain>``.

    Returns ``None`` if the host doesn't end in the configured root
    domain, the prefix is empty, or the label is malformed. The match
    is case-insensitive on the root portion; the token itself keeps
    its original casing (base64url is case-sensitive).
    """
    host_normalised = host_header.split(":", 1)[0].strip().lower()
    root_normalised = root_domain.strip().lower().lstrip(".")
    if not root_normalised:
        return None
    suffix = "." + root_normalised
    if not host_normalised.endswith(suffix):
        return None
    label_lc = host_normalised[: -len(suffix)]
    if not label_lc or "." in label_lc:
        # We only accept a single-level token label. Deeper hierarchies
        # (foo.bar.callback.example) are ignored to keep correlation
        # unambiguous.
        return None
    # Recover the original-case token by slicing the original header.
    return host_header.split(":", 1)[0][: len(label_lc)]


class _CallbackHandler(BaseHTTPRequestHandler):
    """Per-request handler. Logs the request, returns 200 with a marker."""

    server: OobServer  # narrows from BaseHTTPServer

    # Suppress the default access-log to stderr — we have our own log.
    def log_message(self, format: str, *args: object) -> None:  # noqa: ARG002
        # ``format`` and ``args`` mandated by the stdlib signature; we
        # silently drop them because we never want CallbackEvents to
        # also appear on stderr.
        return

    def do_GET(self) -> None:
        self._record_and_respond()

    def do_POST(self) -> None:
        self._record_and_respond()

    def do_PUT(self) -> None:
        self._record_and_respond()

    def do_DELETE(self) -> None:
        self._record_and_respond()

    def _record_and_respond(self) -> None:
        host = self.headers.get("Host", "")
        token = extract_token(host, self.server.root_domain)
        if token is not None:
            event = CallbackEvent(
                token=token,
                protocol="http",
                src_ip=self.client_address[0],
                method=self.command,
                path=self.path,
                host=host,
                user_agent=self.headers.get("User-Agent", ""),
                timestamp=datetime.now(UTC),
            )
            self.server.log.append(event)
        body = b'{"ok":true}\n'
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class OobServer(ThreadingHTTPServer):
    """Self-contained HTTP listener with a CallbackLog.

    Use the runner ``serve_forever()`` from the stdlib, or pass to the
    CLI wrapper which exposes ``bounty-agent oob serve``.
    """

    daemon_threads = True

    def __init__(
        self,
        bind: tuple[str, int],
        root_domain: str,
        log: CallbackLog | None = None,
    ) -> None:
        super().__init__(bind, _CallbackHandler)
        self.root_domain = root_domain
        self.log = log or CallbackLog()


__all__ = ["CallbackEvent", "CallbackLog", "OobServer", "extract_token"]
