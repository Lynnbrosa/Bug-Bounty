"""Scan repository.

Persists :class:`ScanResult` envelopes to SQLite and supports querying
history and computing diffs between two scans of the same target.

The diff is the smallest useful query for "did this patch fix what we
reported": for a target, take the most recent two scans and compute
``new``, ``resolved`` and ``unchanged`` partitions keyed by finding
title plus URL.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from bounty_agent.core import (
    Finding,
    FindingSource,
    ScanResult,
    Severity,
    WafDetection,
)
from bounty_agent.persistence.models import FindingRow, ScanRow

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


_DIFF_WINDOW = 2


@dataclass(frozen=True)
class ScanDiff:
    """Comparison between two scans."""

    new: list[Finding]
    resolved: list[Finding]
    unchanged: list[Finding]


class ScanRepository:
    """Synchronous SQLAlchemy 2.0 repository for ScanResult."""

    def __init__(self, session_factory: object) -> None:
        # We accept any callable that returns a Session to keep the API
        # simple and easy to fake in tests.
        self._session_factory = session_factory

    def _session(self) -> Session:
        return self._session_factory()  # type: ignore[no-any-return,operator]

    def save(self, result: ScanResult) -> None:
        """Persist ``result`` (idempotent on ``scan_id``)."""
        with self._session() as session:
            existing = session.get(ScanRow, str(result.scan_id))
            if existing is not None:
                session.delete(existing)
                session.commit()
            row = self._to_row(result)
            session.add(row)
            session.commit()

    def get(self, scan_id: str) -> ScanResult | None:
        with self._session() as session:
            row = session.get(ScanRow, scan_id)
            if row is None:
                return None
            return self._from_row(row)

    def list_for_target(self, target: str, limit: int = 50) -> list[ScanResult]:
        with self._session() as session:
            stmt = (
                select(ScanRow)
                .where(ScanRow.target == target)
                .order_by(ScanRow.started_at.desc())
                .limit(limit)
                .options(selectinload(ScanRow.findings))
            )
            rows = session.scalars(stmt).all()
            return [self._from_row(r) for r in rows]

    def latest_two_for_target(self, target: str) -> tuple[ScanResult, ScanResult] | None:
        scans = self.list_for_target(target, limit=_DIFF_WINDOW)
        if len(scans) < _DIFF_WINDOW:
            return None
        # list_for_target returns newest first.
        return scans[1], scans[0]

    def diff(self, baseline: ScanResult, current: ScanResult) -> ScanDiff:
        baseline_keys = {_key(f): f for f in baseline.findings}
        current_keys = {_key(f): f for f in current.findings}
        new = [f for k, f in current_keys.items() if k not in baseline_keys]
        resolved = [f for k, f in baseline_keys.items() if k not in current_keys]
        unchanged = [f for k, f in current_keys.items() if k in baseline_keys]
        return ScanDiff(new=new, resolved=resolved, unchanged=unchanged)

    @staticmethod
    def _to_row(result: ScanResult) -> ScanRow:
        return ScanRow(
            id=str(result.scan_id),
            target=str(result.target),
            schema_version=result.schema_version,
            program=result.authorization.program,
            started_at=result.started_at,
            finished_at=result.finished_at,
            raw_json=result.model_dump_json(),
            findings=[
                FindingRow(
                    id=str(f.id),
                    scan_id=str(result.scan_id),
                    url=str(f.url),
                    source=f.source.value,
                    severity=f.severity.value,
                    title=f.title,
                    description=f.description,
                    payload=f.payload,
                    contextual_score=f.contextual_score,
                    discovered_at=f.discovered_at,
                    evidence_json=json.dumps(f.evidence, default=str),
                )
                for f in result.findings
            ],
        )

    @staticmethod
    def _from_row(row: ScanRow) -> ScanResult:
        # The full envelope was serialised at write time; reuse it.
        return ScanResult.model_validate_json(row.raw_json)


def _key(finding: Finding) -> tuple[str, str, str]:
    return (finding.title, str(finding.url), finding.source.value)


# Convenience exports so consumers do not need to dig into the schema layer.
__all__ = [
    "Finding",
    "FindingSource",
    "ScanDiff",
    "ScanRepository",
    "Severity",
    "WafDetection",
]
