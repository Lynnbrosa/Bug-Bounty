"""naabu wrapper (projectdiscovery/naabu).

TCP port scanner. Intrusive: sends SYN/CONNECT probes to the target.
Default port list intentionally narrow (top 100) to limit footprint;
override at instance level if needed.
"""

from __future__ import annotations

import json
from typing import ClassVar
from urllib.parse import urlparse

from bounty_agent.tools.base import BaseSubprocessTool, ToolResult


class Naabu(BaseSubprocessTool):
    name: ClassVar[str] = "naabu"
    description: ClassVar[str] = "TCP port scanner (top-ports by default)."
    intrusive: ClassVar[bool] = True
    binary: ClassVar[str] = "naabu"
    timeout_seconds: ClassVar[int] = 300

    top_ports: ClassVar[str] = "100"
    rate_limit: ClassVar[int] = 200

    def build_args(self, target: str) -> list[str]:
        host = _extract_host(target)
        return [
            "-host",
            host,
            "-top-ports",
            self.top_ports,
            "-rate",
            str(self.rate_limit),
            "-json",
            "-silent",
        ]

    def parse_stdout(self, stdout: str, target: str) -> ToolResult:
        items: list[str] = []
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = data.get("host") or data.get("ip")
            port = data.get("port")
            if host and port:
                items.append(f"{host}:{port}")
        return ToolResult(tool=self.name, target=target, items=items)


def _extract_host(value: str) -> str:
    parsed = urlparse(value)
    return parsed.hostname or value


__all__ = ["Naabu"]
