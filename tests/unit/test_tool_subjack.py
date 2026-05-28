"""Tests for the subjack wrapper (parser-only)."""

from __future__ import annotations

from bounty_agent.core import Severity
from bounty_agent.tools.subjack import Subjack


class TestSubjackParseText:
    def test_extracts_vulnerable_line(self) -> None:
        tool = Subjack()
        stdout = (
            "[Not Vulnerable] safe.example.com\n"
            "[Vulnerable] takeover.example.com -> AWS/S3\n"
            "[Vulnerable] gh.example.com -> Github\n"
        )
        result = tool.parse_stdout(stdout, "example.com")
        assert sorted(result.items) == ["gh.example.com", "takeover.example.com"]
        assert len(result.findings) == 2

    def test_finding_marked_high(self) -> None:
        tool = Subjack()
        stdout = "[Vulnerable] s3.example.com -> AWS/S3\n"
        result = tool.parse_stdout(stdout, "example.com")
        assert result.findings[0].severity == Severity.HIGH
        assert "AWS/S3" in result.findings[0].title

    def test_skips_not_vulnerable(self) -> None:
        tool = Subjack()
        stdout = "[Not Vulnerable] safe.example.com\n"
        result = tool.parse_stdout(stdout, "example.com")
        assert result.findings == []

    def test_handles_blank_lines(self) -> None:
        tool = Subjack()
        result = tool.parse_stdout("\n  \n\n", "example.com")
        assert result.findings == []


class TestSubjackParseJsonl:
    def test_vulnerable_json_entry(self) -> None:
        tool = Subjack()
        stdout = '{"vulnerable": true, "subdomain": "x.example.com", "service": "Heroku"}\n'
        result = tool.parse_stdout(stdout, "example.com")
        assert result.items == ["x.example.com"]
        assert "Heroku" in result.findings[0].title

    def test_not_vulnerable_json_entry(self) -> None:
        tool = Subjack()
        stdout = '{"vulnerable": false, "subdomain": "safe.example.com"}\n'
        result = tool.parse_stdout(stdout, "example.com")
        assert result.findings == []
