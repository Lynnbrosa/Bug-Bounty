"""Tests for the trufflehog wrapper (parser-only)."""

from __future__ import annotations

from bounty_agent.core import Severity
from bounty_agent.tools.trufflehog import TruffleHog, _redact


class TestTruffleHogParse:
    def test_detects_unverified_secret(self) -> None:
        tool = TruffleHog()
        stdout = '{"DetectorName":"AWS","Raw":"AKIAIOSFODNN7EXAMPLE","Verified":false}\n'
        result = tool.parse_stdout(stdout, "https://example.com/dump")
        assert result.items == ["AWS"]
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH

    def test_verified_secret_is_critical(self) -> None:
        tool = TruffleHog()
        stdout = '{"DetectorName":"Stripe","Raw":"sk_live_xxxxxxxxxxxx","Verified":true}\n'
        result = tool.parse_stdout(stdout, "https://example.com/leak")
        assert result.findings[0].severity == Severity.CRITICAL

    def test_lowercase_keys_also_accepted(self) -> None:
        tool = TruffleHog()
        stdout = '{"detector":"GitHub","raw":"ghp_xxxxxxxxxxxxxxxxxxxx"}\n'
        result = tool.parse_stdout(stdout, "https://example.com/")
        assert result.items == ["GitHub"]

    def test_redacts_secret_in_evidence(self) -> None:
        tool = TruffleHog()
        stdout = '{"DetectorName":"AWS","Raw":"AKIAIOSFODNN7EXAMPLE","Verified":false}\n'
        result = tool.parse_stdout(stdout, "https://example.com/")
        excerpt = result.findings[0].evidence["secret_excerpt"]
        assert "..." in excerpt
        # The full secret must not be present in the redacted form.
        assert "AKIAIOSFODNN7EXAMPLE" not in excerpt

    def test_skips_lines_without_raw(self) -> None:
        tool = TruffleHog()
        stdout = '{"DetectorName":"AWS","Verified":false}\n'
        result = tool.parse_stdout(stdout, "https://example.com/")
        assert result.findings == []

    def test_invalid_json_skipped(self) -> None:
        tool = TruffleHog()
        stdout = "not json\n{also not}\n"
        result = tool.parse_stdout(stdout, "https://example.com/")
        assert result.findings == []


class TestRedact:
    def test_short_secret_fully_redacted(self) -> None:
        assert _redact("short") == "<redacted>"

    def test_long_secret_keeps_first_and_last_4(self) -> None:
        assert _redact("AKIAIOSFODNN7EXAMPLE") == "AKIA...MPLE"


class TestTruffleHogArgs:
    def test_no_verification_by_default(self) -> None:
        tool = TruffleHog()
        args = tool.build_args("https://example.com/")
        assert "--no-verification" in args
        assert "--json" in args
