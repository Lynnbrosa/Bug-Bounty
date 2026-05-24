"""Scope guard.

Every URL that the agent is about to touch must pass through
``ScopePolicy.check``. The policy is loaded once from the configuration
file and is the only authority on whether a host or path is in scope.

Design rules:

* Default deny. An empty allowlist means no scan can run.
* Hostnames are matched case-insensitively. ``*.example.com`` matches
  any subdomain of ``example.com`` but not the apex.
* The literal ``"*"`` in the allowlist is a global wildcard: every
  host is allowed. Use deliberately to disable host-level filtering
  while keeping scheme/shape/path-denylist checks.
* Paths in the denylist are matched as prefixes. ``/admin`` blocks
  ``/admin`` and ``/admin/anything``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Self
from urllib.parse import urlparse


class ScopeViolation(Exception):
    """Raised when a URL is rejected by the scope policy."""

    def __init__(self, url: str, reason: str) -> None:
        super().__init__(f"{url}: {reason}")
        self.url = url
        self.reason = reason


@dataclass(frozen=True)
class ScopeDecision:
    """Result of a scope check."""

    url: str
    allowed: bool
    reason: str

    @property
    def denied(self) -> bool:
        return not self.allowed


@dataclass(frozen=True)
class ScopePolicy:
    """Immutable scope policy loaded from the configuration."""

    allowlist: tuple[str, ...]
    path_denylist: tuple[str, ...] = ()

    @classmethod
    def from_iterables(
        cls,
        allowlist: list[str] | tuple[str, ...],
        path_denylist: list[str] | tuple[str, ...] = (),
    ) -> Self:
        return cls(
            allowlist=tuple(p.strip().lower() for p in allowlist if p.strip()),
            path_denylist=tuple(p.strip() for p in path_denylist if p.strip()),
        )

    def host_allowed(self, host: str) -> bool:
        normalized = host.strip().lower()
        if not normalized:
            return False
        for pattern in self.allowlist:
            if pattern == "*":
                return True
            if pattern.startswith("*."):
                suffix = pattern[2:]
                if normalized.endswith("." + suffix):
                    return True
            elif pattern == normalized:
                return True
        return False

    def path_denied(self, path: str) -> bool:
        normalized = path or "/"
        for prefix in self.path_denylist:
            if normalized == prefix or normalized.startswith(prefix.rstrip("/") + "/"):
                return True
        return False

    def evaluate(self, url: str) -> ScopeDecision:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return ScopeDecision(url, allowed=False, reason="scheme must be http or https")
        if not parsed.hostname:
            return ScopeDecision(url, allowed=False, reason="missing hostname")
        if not self.allowlist:
            return ScopeDecision(
                url, allowed=False, reason="allowlist is empty, refusing by default"
            )
        if not self.host_allowed(parsed.hostname):
            return ScopeDecision(
                url,
                allowed=False,
                reason=f"host '{parsed.hostname}' not in allowlist",
            )
        if self.path_denied(parsed.path):
            return ScopeDecision(
                url,
                allowed=False,
                reason=f"path '{parsed.path}' is in denylist",
            )
        return ScopeDecision(url, allowed=True, reason="ok")

    def check(self, url: str) -> ScopeDecision:
        """Evaluate and raise if denied. Use this at the entry of any HTTP call."""
        decision = self.evaluate(url)
        if decision.denied:
            raise ScopeViolation(url, decision.reason)
        return decision


__all__ = ["ScopeDecision", "ScopePolicy", "ScopeViolation"]
