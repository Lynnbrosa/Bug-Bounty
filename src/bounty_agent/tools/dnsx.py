"""dnsx wrapper (projectdiscovery/dnsx).

DNS resolution toolkit. Useful to validate that subdomains returned by
subfinder actually resolve. Hits DNS resolvers, not the target itself,
so scope check is off by default.
"""

from __future__ import annotations

import json
from typing import ClassVar

from bounty_agent.tools.base import BaseSubprocessTool, ToolResult


class Dnsx(BaseSubprocessTool):
    name: ClassVar[str] = "dnsx"
    description: ClassVar[str] = "DNS resolution and probing."
    intrusive: ClassVar[bool] = False
    binary: ClassVar[str] = "dnsx"
    timeout_seconds: ClassVar[int] = 120
    requires_scope_check: ClassVar[bool] = False

    def build_args(self, target: str) -> list[str]:
        return ["-d", target, "-json", "-silent", "-a", "-resp"]

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
            host = data.get("host")
            if host:
                items.append(host)
        return ToolResult(tool=self.name, target=target, items=items)


__all__ = ["Dnsx"]
