"""Tests for the core Pydantic models and JSON Schema export."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from bounty_agent.core import (
    SCHEMA_VERSION,
    AuthorizationRecord,
    Finding,
    FindingSource,
    ScanResult,
    Severity,
    WafDetection,
    scan_result_json_schema,
)


def _make_finding(severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        url="https://example.com/api/search",
        source=FindingSource.FUZZING,
        severity=severity,
        title="Possible SQL injection",
        description="Reflected error message",
        payload="' OR '1'='1",
    )


class TestSeverity:
    def test_base_score_mapping(self) -> None:
        assert Severity.CRITICAL.base_score == 9.0
        assert Severity.HIGH.base_score == 7.0
        assert Severity.MEDIUM.base_score == 5.0
        assert Severity.LOW.base_score == 3.0
        assert Severity.INFO.base_score == 1.0

    def test_str_value(self) -> None:
        assert Severity.HIGH == "high"
        assert Severity.CRITICAL.value == "critical"


class TestFinding:
    def test_minimal_finding(self) -> None:
        finding = _make_finding()
        assert finding.severity is Severity.HIGH
        assert finding.discovered_at.tzinfo is UTC
        assert finding.contextual_score is None

    def test_title_is_stripped(self) -> None:
        finding = Finding(
            url="https://example.com/",
            source=FindingSource.NUCLEI,
            severity=Severity.LOW,
            title="   leading/trailing   ",
        )
        assert finding.title == "leading/trailing"

    def test_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValidationError):
            Finding(  # type: ignore[call-arg]
                url="https://example.com/",
                source=FindingSource.NUCLEI,
                severity=Severity.LOW,
                title="x",
                bogus="not allowed",
            )

    def test_rejects_non_http_url(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                url="ftp://example.com/",  # type: ignore[arg-type]
                source=FindingSource.NUCLEI,
                severity=Severity.LOW,
                title="x",
            )

    def test_contextual_score_bounds(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                url="https://example.com/",
                source=FindingSource.NUCLEI,
                severity=Severity.LOW,
                title="x",
                contextual_score=11.0,
            )


class TestScanResult:
    def _authorization(self) -> AuthorizationRecord:
        return AuthorizationRecord(acknowledged=True, program="HackerOne / acme")

    def test_defaults(self) -> None:
        result = ScanResult(
            target="https://example.com/",
            authorization=self._authorization(),
        )
        assert result.schema_version == SCHEMA_VERSION
        assert result.findings == []
        assert isinstance(result.started_at, datetime)
        assert result.started_at.tzinfo is UTC
        assert result.waf_detection == WafDetection()

    def test_counts_by_severity(self) -> None:
        result = ScanResult(
            target="https://example.com/",
            authorization=self._authorization(),
            findings=[
                _make_finding(Severity.HIGH),
                _make_finding(Severity.HIGH),
                _make_finding(Severity.LOW),
            ],
        )
        counts = result.counts_by_severity()
        assert counts[Severity.HIGH] == 2
        assert counts[Severity.LOW] == 1
        assert counts[Severity.CRITICAL] == 0

    def test_findings_by_source(self) -> None:
        nuclei = Finding(
            url="https://example.com/",
            source=FindingSource.NUCLEI,
            severity=Severity.MEDIUM,
            title="t",
        )
        result = ScanResult(
            target="https://example.com/",
            authorization=self._authorization(),
            findings=[nuclei, _make_finding()],
        )
        assert result.findings_by_source(FindingSource.NUCLEI) == [nuclei]


class TestJsonSchemaExport:
    def test_schema_has_id_and_title(self) -> None:
        schema = scan_result_json_schema()
        assert schema["$id"].endswith(f"{SCHEMA_VERSION}.json")
        assert "ScanResult" in schema["title"]
        assert "properties" in schema
        assert "findings" in schema["properties"]

    def test_schema_is_json_serialisable(self) -> None:
        from bounty_agent.core.schema import render_scan_result_json_schema

        text = render_scan_result_json_schema()
        assert text.startswith("{")
        assert SCHEMA_VERSION in text
