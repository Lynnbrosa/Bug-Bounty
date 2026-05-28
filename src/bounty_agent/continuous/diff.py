"""Structured diff between two ScanResult instances.

Used by the continuous-scan loop to decide which findings are NEW
since the last run (those are the ones we notify on; previously
reported findings stay quiet).

The diff is keyed by a stable hash of (url, title, severity, payload),
which lets us recognise that "Possible SQL injection at /search?q=x"
is the same finding across runs even when the UUID rotates.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from bounty_agent.core import Finding, ScanResult


def _stable_key(finding: Finding) -> str:
    """Hash that's identity-stable across scans."""
    parts = (
        str(finding.url),
        finding.title.strip().lower(),
        finding.severity.value,
        (finding.payload or "").strip(),
    )
    raw = "|".join(parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


@dataclass(frozen=True)
class ScanDiff:
    """Three buckets: brand-new findings, repeated, and disappeared."""

    new: list[Finding] = field(default_factory=list)
    repeated: list[Finding] = field(default_factory=list)
    closed: list[Finding] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new) or bool(self.closed)


def diff_scans(previous: ScanResult | None, current: ScanResult) -> ScanDiff:
    """Compute the diff between two scans against the same target.

    ``previous`` may be ``None`` (first run); every finding is new in
    that case.
    """
    if previous is None:
        return ScanDiff(new=list(current.findings), repeated=[], closed=[])

    prev_keys = {_stable_key(f): f for f in previous.findings}
    curr_keys = {_stable_key(f): f for f in current.findings}

    new: list[Finding] = []
    repeated: list[Finding] = []
    for key, finding in curr_keys.items():
        if key in prev_keys:
            repeated.append(finding)
        else:
            new.append(finding)

    closed = [f for key, f in prev_keys.items() if key not in curr_keys]
    return ScanDiff(new=new, repeated=repeated, closed=closed)


__all__ = ["ScanDiff", "diff_scans"]
