"""Shared plumbing for external CLI tool wrappers.

Every tool wrapper in this package implements the :class:`Tool`
protocol and inherits from :class:`BaseSubprocessTool` to get:

* binary detection via ``shutil.which``,
* async invocation with ``asyncio.create_subprocess_exec`` and timeout,
* scope guard plumbing,
* audit log on start, finish, timeout and skip,
* a uniform :class:`ToolResult` envelope.

Subclasses only implement ``build_args`` and ``parse_stdout``.
"""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass, field
from typing import ClassVar, Protocol, runtime_checkable

from bounty_agent.core import Finding, ScopePolicy
from bounty_agent.logging_setup import audit, get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class ToolResult:
    """Outcome of one tool invocation."""

    tool: str
    target: str
    items: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    stderr: str = ""
    return_code: int = 0
    skipped_reason: str | None = None

    @property
    def skipped(self) -> bool:
        return self.skipped_reason is not None


class ToolError(Exception):
    """Base error for tool wrappers."""


class ToolNotInstalledError(ToolError):
    """Raised when the underlying binary is not on PATH."""


class ToolTimeoutError(ToolError):
    """Raised when a tool exceeds its timeout."""


@runtime_checkable
class Tool(Protocol):
    """Contract every tool wrapper implements."""

    name: ClassVar[str]
    description: ClassVar[str]
    intrusive: ClassVar[bool]

    def is_available(self) -> bool: ...
    async def run(
        self,
        target: str,
        scope: ScopePolicy | None = None,
    ) -> ToolResult: ...


class BaseSubprocessTool:
    """Default implementation that wraps an external CLI."""

    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    intrusive: ClassVar[bool] = False
    binary: ClassVar[str] = ""
    timeout_seconds: ClassVar[int] = 120
    requires_scope_check: ClassVar[bool] = True

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def build_args(self, target: str) -> list[str]:
        raise NotImplementedError

    def parse_stdout(self, stdout: str, target: str) -> ToolResult:
        raise NotImplementedError

    async def run(
        self,
        target: str,
        scope: ScopePolicy | None = None,
    ) -> ToolResult:
        if self.requires_scope_check and scope is not None:
            scope.check(target)

        if not self.is_available():
            audit(
                "tool.skipped",
                tool=self.name,
                target=target,
                reason="binary not installed",
            )
            return ToolResult(
                tool=self.name,
                target=target,
                skipped_reason=f"{self.binary} not on PATH",
            )

        args = [self.binary, *self.build_args(target)]
        audit("tool.started", tool=self.name, target=target, args=args)
        logger.info("tool.starting", tool=self.name, target=target)

        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=float(self.timeout_seconds),
            )
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            audit(
                "tool.timeout",
                tool=self.name,
                target=target,
                timeout_seconds=self.timeout_seconds,
            )
            raise ToolTimeoutError(
                f"{self.name} exceeded {self.timeout_seconds}s on {target}"
            ) from exc

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        result = self.parse_stdout(stdout, target)

        result = ToolResult(
            tool=self.name,
            target=target,
            items=result.items,
            findings=result.findings,
            stderr=stderr,
            return_code=process.returncode if process.returncode is not None else -1,
        )
        audit(
            "tool.finished",
            tool=self.name,
            target=target,
            items=len(result.items),
            findings=len(result.findings),
            return_code=result.return_code,
        )
        return result


__all__ = [
    "BaseSubprocessTool",
    "Tool",
    "ToolError",
    "ToolNotInstalledError",
    "ToolResult",
    "ToolTimeoutError",
]
