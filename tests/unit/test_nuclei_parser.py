"""Tests for the nuclei JSONL parser."""

from __future__ import annotations

from pathlib import Path

from bounty_agent.core import FindingSource, Severity
from bounty_agent.scanners.nuclei import parse_nuclei_jsonl

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "nuclei_output.jsonl"


def _load_fixture() -> str:
    return FIXTURE_PATH.read_text(encoding="utf-8")


class TestParseNucleiJsonl:
    def test_parses_well_formed_lines(self) -> None:
        findings = parse_nuclei_jsonl(_load_fixture())
        # 4 valid JSON lines in the fixture, 1 plain text line skipped.
        assert len(findings) == 4

    def test_severity_normalisation(self) -> None:
        findings = parse_nuclei_jsonl(_load_fixture())
        by_title = {f.title: f for f in findings}
        assert by_title["HTTP Missing Security Headers"].severity is Severity.INFO
        assert by_title["Generic Error-based SQL Injection"].severity is Severity.CRITICAL
        assert by_title["Exposed .env File"].severity is Severity.HIGH
        # unknown severity falls back to info
        assert by_title["With non-standard severity"].severity is Severity.INFO

    def test_url_falls_back_to_host_when_matched_at_missing(self) -> None:
        line = (
            '{"template-id":"x","info":{"name":"n","severity":"low"},'
            '"host":"https://only-host.example/"}'
        )
        findings = parse_nuclei_jsonl(line)
        assert len(findings) == 1
        assert str(findings[0].url).startswith("https://only-host.example")

    def test_url_falls_back_to_fallback_url(self) -> None:
        line = '{"template-id":"x","info":{"name":"n","severity":"low"}}'
        findings = parse_nuclei_jsonl(line, fallback_url="https://fallback.example/")
        assert len(findings) == 1
        assert "fallback.example" in str(findings[0].url)

    def test_line_without_any_url_is_skipped(self) -> None:
        line = '{"template-id":"x","info":{"name":"n","severity":"low"}}'
        findings = parse_nuclei_jsonl(line)
        assert findings == []

    def test_source_is_nuclei(self) -> None:
        findings = parse_nuclei_jsonl(_load_fixture())
        assert all(f.source is FindingSource.NUCLEI for f in findings)

    def test_evidence_contains_template_id(self) -> None:
        findings = parse_nuclei_jsonl(_load_fixture())
        sqli = next(f for f in findings if f.title.startswith("Generic Error"))
        assert sqli.evidence["template_id"] == "sqli-error-based"
        assert sqli.evidence["matcher_name"] == "mysql"

    def test_empty_input_returns_empty_list(self) -> None:
        assert parse_nuclei_jsonl("") == []
        assert parse_nuclei_jsonl("\n\n   \n") == []
