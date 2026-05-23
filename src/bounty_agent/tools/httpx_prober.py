"""httpx wrapper (projectdiscovery/httpx).

Probes which hosts/URLs respond to HTTP(S). Lightly active: one request
per host. Use after subfinder/waybackurls to narrow the surface to
endpoints that actually exist.

Note: the binary lives at the same name as the Python package
``httpx``. We rename the wrapper to ``HttpxProber`` to avoid confusion.
"""

from __future__ import annotations

import json
from typing import ClassVar

from bounty_agent.tools.base import BaseSubprocessTool, ToolResult


class HttpxProber(BaseSubprocessTool):
    name: ClassVar[str] = "httpx"
    description: ClassVar[str] = "Probe which hosts/URLs respond to HTTP(S)."
    intrusive: ClassVar[bool] = False
    binary: ClassVar[str] = "httpx"
    timeout_seconds: ClassVar[int] = 180

    def build_args(self, target: str) -> list[str]:
        # Stream a single host via -u; emit JSONL on stdout.
        return ["-u", target, "-json", "-silent", "-no-color"]

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
            url = data.get("url") or data.get("input")
            if url:
                items.append(url)
        return ToolResult(tool=self.name, target=target, items=items)


__all__ = ["HttpxProber"]
