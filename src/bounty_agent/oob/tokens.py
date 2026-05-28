"""Token registry for OOB callback correlation.

Each blind payload sent during a scan embeds a short URL-safe token.
When the OOB server later receives a request whose Host header (or
URL path) contains that token, we know which payload caused it.

Both sides of this pairing — the registry of pending tokens and the
log of received callbacks — are persisted to JSONL so a long-running
server can survive restarts and a scanner can be run against a remote
server it doesn't own.
"""

from __future__ import annotations

import json
import secrets
import threading
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Self
from uuid import UUID

#: Placeholder substituted in payloads at fuzz time. Each substitution
#: mints a unique token, so every payload-issued callback is
#: traceable back to the exact (target_url, payload) pair.
OOB_PLACEHOLDER = "{OOB_URL}"

# 16 chars of url-safe-base64 = 96 bits of entropy. Long enough to
# rule out collisions across many parallel scans, short enough to fit
# in a subdomain label (max 63 chars).
_TOKEN_BYTES = 12


def generate_token() -> str:
    """Return a fresh URL-safe-base64 token."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


@dataclass(frozen=True)
class OobToken:
    """One pending callback token + the payload context that issued it."""

    token: str
    scan_id: str | None
    target_url: str
    payload: str
    category: str
    created_at: datetime

    def to_jsonl(self) -> str:
        """Serialise to one JSONL line."""
        payload = asdict(self)
        payload["created_at"] = self.created_at.isoformat()
        return json.dumps(payload)

    @classmethod
    def from_jsonl(cls, line: str) -> Self:
        data = json.loads(line)
        data["created_at"] = datetime.fromisoformat(data["created_at"])
        return cls(**data)


class TokenRegistry:
    """In-memory + JSONL-backed registry of pending callback tokens.

    Thread-safe: ``register`` and ``lookup`` are guarded by an internal
    lock so the same instance can be shared between the scanner thread
    (writes) and the correlator (reads). Persistence is append-only;
    nothing is ever deleted from the file so an operator can replay
    the registry against a callback log from a previous run.
    """

    def __init__(self, persist_path: Path | None = None) -> None:
        self._tokens: dict[str, OobToken] = {}
        self._lock = threading.Lock()
        self._persist_path = persist_path
        if persist_path is not None and persist_path.exists():
            self._load_from_disk(persist_path)

    def register(
        self,
        target_url: str,
        payload: str,
        category: str,
        scan_id: UUID | None = None,
    ) -> OobToken:
        """Mint a new token and persist it. Returns the full record."""
        token = OobToken(
            token=generate_token(),
            scan_id=str(scan_id) if scan_id is not None else None,
            target_url=target_url,
            payload=payload,
            category=category,
            created_at=datetime.now(UTC),
        )
        with self._lock:
            self._tokens[token.token] = token
        if self._persist_path is not None:
            self._append_to_disk(token)
        return token

    def lookup(self, token: str) -> OobToken | None:
        """Return the OobToken for ``token`` or ``None`` if unknown."""
        with self._lock:
            return self._tokens.get(token)

    def all_tokens(self) -> list[OobToken]:
        """Snapshot of every token currently in the registry."""
        with self._lock:
            return list(self._tokens.values())

    def _load_from_disk(self, path: Path) -> None:
        with path.open(encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                try:
                    token = OobToken.from_jsonl(line)
                except (ValueError, KeyError, json.JSONDecodeError):
                    continue
                self._tokens[token.token] = token

    def _append_to_disk(self, token: OobToken) -> None:
        assert self._persist_path is not None
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        with self._persist_path.open("a", encoding="utf-8") as fh:
            fh.write(token.to_jsonl() + "\n")


__all__ = ["OOB_PLACEHOLDER", "OobToken", "TokenRegistry", "generate_token"]
