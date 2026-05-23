"""Tests for the report renderers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bounty_agent.core import (
    AuthorizationRecord,
    Finding,
    FindingSource,
    ScanResult,
    Severity,
    WafDetection,
)
from bounty_agent.reporting import (
    render_json,
    render_markdown,
    render_text,
    write_reports,
)


@pytest.fixture
def result() -> ScanResult:
    findings = [
        Finding(
            url="https://example.com/api/search?q=test",
            source=FindingSource.FUZZING,
            severity=Severity.HIGH,
            title="Possible SQL injection",
            description="DB error reflected in body.",
            payload="' OR '1'='1",
            evidence={"matched_marker": "MySQL", "status_code": 200},
        ),
        Finding(
            url="https://example.com/",
            source=FindingSource.NUCLEI,
            severity=Severity.INFO,
            title="HTTP Missing Security Headers",
        ),
    ]
    return ScanResult(
        target="https://example.com/",
        authorization=AuthorizationRecord(
            acknowledged=True, program="HackerOne / acme", contact="sec@acme.example"
        ),
        waf_detection=WafDetection(
            detected_vendors=["Cloudflare"], likely_protected=True, status_code=200
        ),
        findings=findings,
    )


class TestRenderText:
    def test_includes_target_and_findings(self, result: ScanResult) -> None:
        text = render_text(result)
        assert "BUG BOUNTY SCAN REPORT" in text
        assert "https://example.com/" in text
        assert "Possible SQL injection" in text
        assert "[HIGH]" in text

    def test_empty_findings_section(self) -> None:
        result = ScanResult(
            target="https://example.com/",
            authorization=AuthorizationRecord(acknowledged=True),
        )
        text = render_text(result)
        assert "No findings reported." in text


class TestRenderJson:
    def test_round_trips(self, result: ScanResult) -> None:
        text = render_json(result)
        data = json.loads(text)
        assert data["target"] == "https://example.com/"
        assert len(data["findings"]) == 2
        assert data["schema_version"] == "1"


class TestRenderMarkdown:
    def test_includes_headings_and_table(self, result: ScanResult) -> None:
        md = render_markdown(result)
        assert "# Bug Bounty Scan Report" in md
        assert "## Findings" in md
        assert "| Severity | Count |" in md
        # Severities table includes all ladder entries
        assert "high" in md
        assert "info" in md

    def test_includes_payload_evidence(self, result: ScanResult) -> None:
        md = render_markdown(result)
        assert "' OR '1'='1" in md
        assert "matched_marker" in md

    def test_handles_waf_error(self) -> None:
        result = ScanResult(
            target="https://example.com/",
            authorization=AuthorizationRecord(acknowledged=True),
            waf_detection=WafDetection(error="connection refused"),
        )
        md = render_markdown(result)
        assert "connection refused" in md


class TestWriteReports:
    def test_writes_requested_formats(self, tmp_path: Path, result: ScanResult) -> None:
        written = write_reports(result, tmp_path, ("text", "markdown", "json"))
        assert set(written.keys()) == {"text", "markdown", "json"}
        for path in written.values():
            assert path.exists()
            assert path.stat().st_size > 0

    def test_ignores_unknown_formats(self, tmp_path: Path, result: ScanResult) -> None:
        written = write_reports(result, tmp_path, ("text", "bogus"))
        assert set(written.keys()) == {"text"}
