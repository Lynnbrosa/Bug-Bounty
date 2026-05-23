"""Tests for the persistence layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from bounty_agent.core import (
    AuthorizationRecord,
    Finding,
    FindingSource,
    ScanResult,
    Severity,
)
from bounty_agent.persistence import (
    ScanRepository,
    make_engine,
    make_session_factory,
)


@pytest.fixture
def repo(tmp_path: Path) -> ScanRepository:
    engine = make_engine(tmp_path / "test.sqlite")
    factory = make_session_factory(engine)
    return ScanRepository(factory)


def _authorization() -> AuthorizationRecord:
    return AuthorizationRecord(acknowledged=True, program="acme")


def _result(
    *,
    target: str = "https://example.com/",
    finding_titles: tuple[str, ...] = (),
) -> ScanResult:
    findings = [
        Finding(
            url=target,  # type: ignore[arg-type]
            source=FindingSource.FUZZING,
            severity=Severity.HIGH,
            title=title,
        )
        for title in finding_titles
    ]
    return ScanResult(
        target=target,  # type: ignore[arg-type]
        authorization=_authorization(),
        findings=findings,
    )


class TestRoundTrip:
    def test_save_and_get(self, repo: ScanRepository) -> None:
        result = _result(finding_titles=("Issue A", "Issue B"))
        repo.save(result)
        loaded = repo.get(str(result.scan_id))
        assert loaded is not None
        assert loaded.scan_id == result.scan_id
        assert {f.title for f in loaded.findings} == {"Issue A", "Issue B"}

    def test_save_is_idempotent(self, repo: ScanRepository) -> None:
        result = _result(finding_titles=("A",))
        repo.save(result)
        repo.save(result)  # second save replaces the first
        loaded = repo.get(str(result.scan_id))
        assert loaded is not None
        assert len(loaded.findings) == 1


class TestListing:
    def test_list_for_target_returns_newest_first(self, repo: ScanRepository) -> None:
        first = _result(finding_titles=("A",))
        second = _result(finding_titles=("B",))
        repo.save(first)
        repo.save(second)
        scans = repo.list_for_target("https://example.com/")
        assert [s.scan_id for s in scans] == [second.scan_id, first.scan_id]

    def test_list_for_target_respects_limit(self, repo: ScanRepository) -> None:
        for i in range(5):
            repo.save(_result(finding_titles=(f"T{i}",)))
        assert len(repo.list_for_target("https://example.com/", limit=3)) == 3


class TestEndpointDiff:
    def test_endpoints_added_and_removed(self, repo: ScanRepository) -> None:
        from bounty_agent.core import (
            AuthorizationRecord as _Auth,
        )
        from bounty_agent.core import (
            ScanResult as _SR,
        )

        baseline = _SR(
            target="https://example.com/",
            authorization=_Auth(acknowledged=True),
            endpoints=["https://example.com/", "https://example.com/api"],  # type: ignore[list-item]
        )
        current = _SR(
            target="https://example.com/",
            authorization=_Auth(acknowledged=True),
            endpoints=["https://example.com/api", "https://example.com/v2"],  # type: ignore[list-item]
        )
        diff = repo.diff(baseline, current)
        assert diff.endpoints_added == ["https://example.com/v2"]
        assert diff.endpoints_removed == ["https://example.com/"]


class TestDiff:
    def test_new_resolved_unchanged_partitions(self, repo: ScanRepository) -> None:
        baseline = _result(finding_titles=("kept", "resolved-only"))
        current = _result(finding_titles=("kept", "new-only"))
        diff = repo.diff(baseline, current)
        new_titles = {f.title for f in diff.new}
        resolved_titles = {f.title for f in diff.resolved}
        unchanged_titles = {f.title for f in diff.unchanged}
        assert new_titles == {"new-only"}
        assert resolved_titles == {"resolved-only"}
        assert unchanged_titles == {"kept"}

    def test_latest_two_for_target(self, repo: ScanRepository) -> None:
        first = _result(finding_titles=("a",))
        second = _result(finding_titles=("b",))
        repo.save(first)
        repo.save(second)
        pair = repo.latest_two_for_target("https://example.com/")
        assert pair is not None
        baseline, current = pair
        assert baseline.scan_id == first.scan_id
        assert current.scan_id == second.scan_id

    def test_latest_two_returns_none_with_one_scan(self, repo: ScanRepository) -> None:
        repo.save(_result(finding_titles=("only",)))
        assert repo.latest_two_for_target("https://example.com/") is None


class TestMissing:
    def test_get_returns_none_for_unknown_scan(self, repo: ScanRepository) -> None:
        assert repo.get("00000000-0000-0000-0000-000000000000") is None

    def test_list_for_unknown_target_returns_empty(self, repo: ScanRepository) -> None:
        assert repo.list_for_target("https://unknown.example/") == []
