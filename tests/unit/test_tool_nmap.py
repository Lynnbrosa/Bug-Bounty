"""Tests for the nmap wrapper (parser-only — no subprocess)."""

from __future__ import annotations

from bounty_agent.core import Severity
from bounty_agent.tools.nmap import Nmap, NmapPort

_SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5"/>
        <script id="ssh-hostkey" output="2048 aa:bb:cc..."/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.41"/>
        <script id="http-server-header" output="Apache/2.4.41 (Ubuntu)"/>
        <script id="http-title" output="My Site"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql" product="MySQL" version="5.7.33"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class TestNmapParse:
    def test_extracts_open_ports_only(self) -> None:
        tool = Nmap()
        result = tool.parse_stdout(_SAMPLE_XML, "https://example.com/")
        # Closed port (443) is dropped.
        assert sorted(result.items) == [
            "example.com:22/tcp",
            "example.com:3306/tcp",
            "example.com:80/tcp",
        ]

    def test_emits_finding_per_open_port(self) -> None:
        tool = Nmap()
        result = tool.parse_stdout(_SAMPLE_XML, "https://example.com/")
        ports_in_findings = {
            f.evidence["port"] for f in result.findings if f.title.startswith("Open port")
        }
        assert ports_in_findings == {22, 80, 3306}

    def test_mysql_port_marked_medium(self) -> None:
        tool = Nmap()
        result = tool.parse_stdout(_SAMPLE_XML, "https://example.com/")
        mysql_port = next(f for f in result.findings if f.title.startswith("Open port 3306"))
        assert mysql_port.severity == Severity.MEDIUM

    def test_http_port_marked_info(self) -> None:
        tool = Nmap()
        result = tool.parse_stdout(_SAMPLE_XML, "https://example.com/")
        http_port = next(f for f in result.findings if f.title.startswith("Open port 80"))
        assert http_port.severity == Severity.INFO

    def test_notable_nse_script_emits_extra_finding(self) -> None:
        tool = Nmap()
        result = tool.parse_stdout(_SAMPLE_XML, "https://example.com/")
        scripts = [f for f in result.findings if "NSE:" in f.title]
        ids = {f.evidence["script"] for f in scripts}
        # http-server-header, http-title, ssh-hostkey are all in _NOTABLE_SCRIPTS.
        assert "http-server-header" in ids
        assert "ssh-hostkey" in ids

    def test_invalid_xml_returns_empty_result(self) -> None:
        tool = Nmap()
        result = tool.parse_stdout("<not-valid-xml", "https://example.com/")
        assert result.items == []
        assert result.findings == []


class TestNmapArgs:
    def test_extracts_host_from_url(self) -> None:
        tool = Nmap()
        args = tool.build_args("https://example.com/path/here")
        assert args[-1] == "example.com"

    def test_includes_default_top_1000(self) -> None:
        tool = Nmap()
        args = tool.build_args("https://example.com/")
        assert "--top-ports" in args
        assert "1000" in args

    def test_xml_to_stdout(self) -> None:
        tool = Nmap()
        args = tool.build_args("https://example.com/")
        assert "-oX" in args
        # The XML output flag must be followed by the literal "-"
        idx = args.index("-oX")
        assert args[idx + 1] == "-"


class TestNmapPortBanner:
    def test_product_and_version(self) -> None:
        p = NmapPort(
            port=22,
            protocol="tcp",
            state="open",
            service="ssh",
            product="OpenSSH",
            version="8.2p1",
            scripts={},
        )
        assert p.banner() == "OpenSSH 8.2p1"

    def test_service_only_fallback(self) -> None:
        p = NmapPort(
            port=22,
            protocol="tcp",
            state="open",
            service="ssh",
            product="",
            version="",
            scripts={},
        )
        assert p.banner() == "ssh"

    def test_unknown_when_blank(self) -> None:
        p = NmapPort(
            port=0,
            protocol="tcp",
            state="open",
            service="",
            product="",
            version="",
            scripts={},
        )
        assert p.banner() == "unknown"
