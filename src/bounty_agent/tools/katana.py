"""katana wrapper (projectdiscovery/katana).

Active crawler. Renders HTML and (with headless mode) JavaScript to
discover URLs that static path enumeration would miss. Marked
intrusive: callers must opt in explicitly through the registry.
"""

from __future__ import annotations

import json
from typing import ClassVar

from bounty_agent.tools.base import BaseSubprocessTool, ToolResult


class Katana(BaseSubprocessTool):
    name: ClassVar[str] = "katana"
    description: ClassVar[str] = "Active crawler for HTML and JavaScript-rendered URLs."
    intrusive: ClassVar[bool] = True
    binary: ClassVar[str] = "katana"
    timeout_seconds: ClassVar[int] = 300

    # Reasonable defaults that respect target health. Override at the
    # subclass or instance level for noisier sweeps.
    max_depth: ClassVar[int] = 2
    rate_limit: ClassVar[int] = 10

    def build_args(self, target: str) -> list[str]:
        return [
            "-u",
            target,
            "-jsonl",
            "-silent",
            "-d",
            str(self.max_depth),
            "-rl",
            str(self.rate_limit),
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
            request = data.get("request") or {}
            endpoint = request.get("endpoint") or data.get("endpoint")
            if endpoint:
                items.append(endpoint)
        # Deduplicate while preserving discovery order.
        seen: set[str] = set()
        unique: list[str] = []
        for url in items:
            if url not in seen:
                seen.add(url)
                unique.append(url)
        return ToolResult(tool=self.name, target=target, items=unique)


__all__ = ["Katana"]
