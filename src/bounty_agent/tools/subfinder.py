"""subfinder wrapper (projectdiscovery).

Passive subdomain enumeration. No traffic sent to the target. Output
is line-delimited (one subdomain per line). When a ScopePolicy is
supplied, results outside the allowed hosts are filtered out before
being returned.
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import urlparse

from bounty_agent.core import ScopePolicy
from bounty_agent.tools.base import BaseSubprocessTool, ToolResult


class Subfinder(BaseSubprocessTool):
    name: ClassVar[str] = "subfinder"
    description: ClassVar[str] = "Passive subdomain enumeration."
    intrusive: ClassVar[bool] = False
    binary: ClassVar[str] = "subfinder"
    timeout_seconds: ClassVar[int] = 180
    # Subfinder hits public OSINT APIs, not the target itself.
    requires_scope_check: ClassVar[bool] = False

    def build_args(self, target: str) -> list[str]:
        domain = _extract_domain(target)
        return ["-d", domain, "-silent"]

    def parse_stdout(self, stdout: str, target: str) -> ToolResult:
        items = sorted({line.strip() for line in stdout.splitlines() if line.strip()})
        return ToolResult(tool=self.name, target=target, items=items)

    async def run(
        self,
        target: str,
        scope: ScopePolicy | None = None,
    ) -> ToolResult:
        result = await super().run(target, scope=None)
        if scope is None or result.skipped:
            return result
        filtered = [host for host in result.items if scope.host_allowed(host)]
        return ToolResult(
            tool=result.tool,
            target=result.target,
            items=filtered,
            findings=result.findings,
            stderr=result.stderr,
            return_code=result.return_code,
            skipped_reason=result.skipped_reason,
        )


def _extract_domain(value: str) -> str:
    parsed = urlparse(value)
    return parsed.hostname or value


__all__ = ["Subfinder"]
