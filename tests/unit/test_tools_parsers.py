"""Tests for the per-tool stdout parsers.

The parsers are pure functions of stdout text, so we can exercise them
without monkeypatching shutil.which or asyncio.subprocess. The
subprocess plumbing is covered separately in test_tools_base.py.
"""

from __future__ import annotations

from bounty_agent.tools import (
    Dnsx,
    HttpxProber,
    Katana,
    Naabu,
    Subfinder,
    Waybackurls,
)


class TestSubfinder:
    def test_parses_lines_dedup_sorted(self) -> None:
        stdout = "api.example.com\nadmin.example.com\napi.example.com\n"
        result = Subfinder().parse_stdout(stdout, "example.com")
        assert result.items == ["admin.example.com", "api.example.com"]
        assert result.tool == "subfinder"

    def test_args_use_hostname_when_url_given(self) -> None:
        assert Subfinder().build_args("https://example.com/path") == [
            "-d",
            "example.com",
            "-silent",
        ]


class TestWaybackurls:
    def test_parses_lines(self) -> None:
        stdout = "https://example.com/a?x=1\nhttps://example.com/b\nhttps://example.com/a?x=1\n"
        result = Waybackurls().parse_stdout(stdout, "example.com")
        assert result.items == [
            "https://example.com/a?x=1",
            "https://example.com/b",
        ]

    def test_args_use_hostname(self) -> None:
        assert Waybackurls().build_args("https://example.com/") == ["example.com"]


class TestHttpxProber:
    def test_parses_jsonl(self) -> None:
        stdout = (
            '{"url":"https://example.com/","input":"https://example.com/"}\n'
            "not-json\n"
            '{"url":"https://example.com/api","input":"https://example.com/api"}\n'
        )
        result = HttpxProber().parse_stdout(stdout, "https://example.com/")
        assert result.items == [
            "https://example.com/",
            "https://example.com/api",
        ]


class TestDnsx:
    def test_parses_jsonl_hosts(self) -> None:
        stdout = (
            '{"host":"api.example.com","a":["1.2.3.4"]}\n'
            '{"host":"admin.example.com","a":["1.2.3.5"]}\n'
        )
        result = Dnsx().parse_stdout(stdout, "example.com")
        assert result.items == ["api.example.com", "admin.example.com"]


class TestKatana:
    def test_parses_jsonl_endpoints(self) -> None:
        stdout = (
            '{"request":{"endpoint":"https://example.com/a"}}\n'
            '{"endpoint":"https://example.com/b"}\n'
            '{"request":{"endpoint":"https://example.com/a"}}\n'
        )
        result = Katana().parse_stdout(stdout, "https://example.com/")
        # Preserves discovery order and deduplicates.
        assert result.items == [
            "https://example.com/a",
            "https://example.com/b",
        ]

    def test_intrusive_flag_set(self) -> None:
        assert Katana().intrusive is True


class TestNaabu:
    def test_parses_jsonl_host_port(self) -> None:
        stdout = (
            '{"host":"example.com","ip":"1.2.3.4","port":80}\n'
            '{"host":"example.com","ip":"1.2.3.4","port":443}\n'
        )
        result = Naabu().parse_stdout(stdout, "example.com")
        assert result.items == ["example.com:80", "example.com:443"]

    def test_intrusive_flag_set(self) -> None:
        assert Naabu().intrusive is True
