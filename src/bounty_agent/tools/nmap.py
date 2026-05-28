"""nmap wrapper.

Service version detection + default NSE script category. Slower and
more intrusive than naabu, but yields the structured data that lets
us promote raw port findings into severity-rated observations:

- Service name + version (``Apache 2.4.41``) instead of bare port
- NSE script outputs (mod_status, robots.txt, http-title, ssl-cert,
  vuln scripts when enabled)
- Banner disclosure for SSH, SMTP, FTP, etc.

Runs with ``-sV -sC --top-ports 1000 -oX -`` by default:

- ``-sV``: probe service/version
- ``-sC``: default NSE category (safe scripts only, no vuln/exploit)
- ``--top-ports 1000``: balance coverage vs runtime
- ``-oX -``: XML to stdout; we parse with the stdlib ElementTree

NSE ``vuln`` category is OFF by default because some scripts perform
mild exploitation. Opt-in via :attr:`scripts` (e.g.
``scripts="default,vuln,http-enum"``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

from bounty_agent.core import Finding, FindingSource, Severity
from bounty_agent.tools.base import BaseSubprocessTool, ToolResult


@dataclass(frozen=True)
class NmapPort:
    """One discovered port + service."""

    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    scripts: dict[str, str]

    def banner(self) -> str:
        """Human-friendly description for findings."""
        parts: list[str] = []
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        if not parts and self.service:
            parts.append(self.service)
        return " ".join(parts).strip() or "unknown"


class Nmap(BaseSubprocessTool):
    name: ClassVar[str] = "nmap"
    description: ClassVar[str] = "Service-version port scanner with NSE default scripts."
    intrusive: ClassVar[bool] = True
    binary: ClassVar[str] = "nmap"
    timeout_seconds: ClassVar[int] = 600

    # Default knobs. Subclass or instance-override if needed.
    top_ports: ClassVar[str] = "1000"
    scripts: ClassVar[str] = "default"
    max_rtt_timeout: ClassVar[str] = "2s"
    # When True, append --script vuln to enable the vuln NSE category.
    enable_vuln_scripts: ClassVar[bool] = False

    def build_args(self, target: str) -> list[str]:
        host = _extract_host(target)
        script_arg = self.scripts
        if self.enable_vuln_scripts and "vuln" not in script_arg:
            script_arg = f"{script_arg},vuln"
        return [
            "-sV",
            "-sC" if script_arg == "default" else f"--script={script_arg}",
            "--top-ports",
            self.top_ports,
            "--max-rtt-timeout",
            self.max_rtt_timeout,
            "-T4",  # aggressive timing template
            "-Pn",  # skip host discovery (host already known to be alive)
            "-oX",
            "-",  # XML to stdout
            host,
        ]

    def parse_stdout(self, stdout: str, target: str) -> ToolResult:
        """Parse the XML output into items + findings."""
        items: list[str] = []
        findings: list[Finding] = []
        try:
            root = ET.fromstring(stdout)  # noqa: S314 - nmap output, not user-controlled
        except ET.ParseError:
            return ToolResult(tool=self.name, target=target, items=items)

        host = _extract_host(target)
        base_url = target if target.startswith(("http://", "https://")) else f"https://{host}"

        for port_elem in root.iter("port"):
            port_info = _parse_port(port_elem)
            if port_info.state != "open":
                continue
            items.append(f"{host}:{port_info.port}/{port_info.protocol}")
            findings.extend(_findings_for_port(base_url, host, port_info))

        return ToolResult(
            tool=self.name,
            target=target,
            items=items,
            findings=findings,
        )


# Subset of NSE scripts that almost always mean "the operator should
# look at this": exposed status pages, default-credential hits, version
# banners that disclose internal infra. We promote those to LOW; the
# operator (or LLM classifier) can re-rate.
_NOTABLE_SCRIPTS: frozenset[str] = frozenset(
    {
        "http-title",
        "http-server-header",
        "http-robots.txt",
        "http-enum",
        "http-headers",
        "http-methods",
        "http-trace",
        "http-open-proxy",
        "http-vuln-cve2017-5638",
        "http-shellshock",
        "http-csrf",
        "ssl-cert",
        "ssl-enum-ciphers",
        "ssh-hostkey",
        "ftp-anon",
        "smb-os-discovery",
        "smb-vuln-ms17-010",
        "ms-sql-info",
        "mysql-info",
        "postgres-info",
        "redis-info",
        "mongodb-info",
        "smtp-commands",
        "smtp-open-relay",
        "dns-recursion",
    }
)


def _findings_for_port(base_url: str, host: str, info: NmapPort) -> list[Finding]:
    findings: list[Finding] = []
    severity = _severity_for_service(info)
    title = f"Open port {info.port}/{info.protocol} ({info.banner()})"
    findings.append(
        Finding(
            url=base_url,  # type: ignore[arg-type]
            source=FindingSource.MANUAL,
            severity=severity,
            title=title,
            description=(
                "nmap reported an open port with a fingerprinted service. "
                "Confirm whether the service should be reachable from the "
                "public internet and patch to the current vendor release."
            ),
            evidence={
                "host": host,
                "port": info.port,
                "protocol": info.protocol,
                "service": info.service,
                "product": info.product,
                "version": info.version,
                "tool": "nmap",
            },
        )
    )
    for script_id, output in info.scripts.items():
        if script_id not in _NOTABLE_SCRIPTS:
            continue
        findings.append(
            Finding(
                url=base_url,  # type: ignore[arg-type]
                source=FindingSource.MANUAL,
                severity=_severity_for_script(script_id),
                title=f"nmap NSE: {script_id}",
                description=(
                    f"NSE script {script_id!r} returned output against "
                    f"{host}:{info.port}. Review for misconfiguration "
                    "or version-based CVEs."
                ),
                evidence={
                    "host": host,
                    "port": info.port,
                    "script": script_id,
                    "output_excerpt": output[:600],
                    "tool": "nmap",
                },
            )
        )
    return findings


def _severity_for_service(info: NmapPort) -> Severity:
    """Heuristic: anything exposing admin protocols is MEDIUM, web is INFO."""
    high_risk_services = {
        "telnet",
        "ftp",
        "vnc",
        "rdp",
        "smb",
        "redis",
        "mongodb",
        "mysql",
        "postgresql",
        "memcached",
    }
    web_services = {"http", "https", "http-proxy"}
    service = info.service.lower()
    if service in high_risk_services:
        return Severity.MEDIUM
    if service in web_services:
        return Severity.INFO
    return Severity.LOW


def _severity_for_script(script_id: str) -> Severity:
    """Scripts named with vuln/cve/shellshock are higher confidence."""
    sid = script_id.lower()
    if "vuln" in sid or "cve" in sid or "shellshock" in sid or "ms17-010" in sid:
        return Severity.HIGH
    if sid in {"ssl-enum-ciphers", "http-open-proxy", "smtp-open-relay", "ftp-anon"}:
        return Severity.MEDIUM
    return Severity.LOW


def _parse_port(port_elem: ET.Element) -> NmapPort:
    port_num = int(port_elem.attrib.get("portid", "0"))
    protocol = port_elem.attrib.get("protocol", "tcp")
    state_elem = port_elem.find("state")
    state = state_elem.attrib.get("state", "") if state_elem is not None else ""
    service_elem = port_elem.find("service")
    service = service_elem.attrib.get("name", "") if service_elem is not None else ""
    product = service_elem.attrib.get("product", "") if service_elem is not None else ""
    version = service_elem.attrib.get("version", "") if service_elem is not None else ""
    scripts: dict[str, str] = {}
    for script_elem in port_elem.iter("script"):
        sid = script_elem.attrib.get("id", "")
        output = script_elem.attrib.get("output", "")
        if sid:
            scripts[sid] = output
    return NmapPort(
        port=port_num,
        protocol=protocol,
        state=state,
        service=service,
        product=product,
        version=version,
        scripts=scripts,
    )


def _extract_host(value: str) -> str:
    parsed = urlparse(value)
    return parsed.hostname or value


__all__ = ["Nmap", "NmapPort"]
