"""Tests for the arjun wrapper (parser-only)."""

from __future__ import annotations

from bounty_agent.tools.arjun import Arjun


class TestArjunParse:
    def test_flat_params_dict(self) -> None:
        tool = Arjun()
        stdout = '{"params": ["q", "debug", "preview"], "method": "GET"}'
        result = tool.parse_stdout(stdout, "https://example.com/")
        assert sorted(result.items) == ["debug", "preview", "q"]

    def test_url_nested_dict(self) -> None:
        tool = Arjun()
        stdout = (
            '{"https://example.com/search": '
            '{"params": ["a", "b"], "method": "GET"}, '
            '"https://example.com/api": {"params": ["x"], "method": "GET"}}'
        )
        result = tool.parse_stdout(stdout, "https://example.com/")
        assert sorted(result.items) == ["a", "b", "x"]

    def test_empty_stdout(self) -> None:
        tool = Arjun()
        result = tool.parse_stdout("", "https://example.com/")
        assert result.items == []

    def test_invalid_json(self) -> None:
        tool = Arjun()
        result = tool.parse_stdout("not json at all", "https://example.com/")
        assert result.items == []


class TestArjunArgs:
    def test_default_args(self) -> None:
        tool = Arjun()
        args = tool.build_args("https://example.com/search")
        assert "-u" in args
        assert "https://example.com/search" in args
        assert "-oJ" in args
        # JSON to stdout
        idx = args.index("-oJ")
        assert args[idx + 1] == "-"
