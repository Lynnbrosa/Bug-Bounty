"""waybackurls wrapper (tomnomnom/waybackurls).

Queries the Wayback Machine and CommonCrawl for historical URLs of a
domain. Zero requests to the target. Output is line-delimited (one URL
per line). Scope filtering keeps only URLs whose host is allowed.
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import urlparse

from bounty_agent.core import ScopePolicy
from bounty_agent.tools.base import BaseSubprocessTool, ToolResult


class Waybackurls(BaseSubprocessTool):
    name: ClassVar[str] = "waybackurls"
    description: ClassVar[str] = "Historical URLs from Wayback Machine and CommonCrawl."
    intrusive: ClassVar[bool] = False
    binary: ClassVar[str] = "waybackurls"
    timeout_seconds: ClassVar[int] = 120
    requires_scope_check: ClassVar[bool] = False

    def build_args(self, target: str) -> list[str]:
        # waybackurls reads the domain from stdin in some builds, but
        # also accepts it as an argument in modern versions.
        return [_extract_domain(target)]

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
        filtered = [url for url in result.items if _url_in_scope(url, scope)]
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


def _url_in_scope(url: str, scope: ScopePolicy) -> bool:
    try:
        scope.check(url)
    except Exception:
        return False
    return True


__all__ = ["Waybackurls"]
