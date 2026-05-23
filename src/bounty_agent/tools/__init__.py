"""External tool wrappers and registry.

Each wrapper implements the :class:`Tool` protocol and is keyed in the
registry by its ``name`` class variable. Callers ask the registry for
a tool by name and run it through the uniform :meth:`Tool.run` async
entry point.

Intrusive tools (those that actively interact with the target beyond
a single probe) are gated: ``ToolRegistry.run`` refuses to invoke them
unless ``intrusive_ok=True`` is passed by the caller. This is the same
explicit-opt-in pattern used by the rest of the agent (``--authorized``
at the CLI, ``acknowledged: true`` in the config).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from bounty_agent.core import ScopePolicy
from bounty_agent.logging_setup import audit
from bounty_agent.tools.base import (
    BaseSubprocessTool,
    Tool,
    ToolError,
    ToolNotInstalledError,
    ToolResult,
    ToolTimeoutError,
)
from bounty_agent.tools.dnsx import Dnsx
from bounty_agent.tools.httpx_prober import HttpxProber
from bounty_agent.tools.katana import Katana
from bounty_agent.tools.naabu import Naabu
from bounty_agent.tools.subfinder import Subfinder
from bounty_agent.tools.waybackurls import Waybackurls


@dataclass(frozen=True)
class ToolDescriptor:
    """Metadata used by the CLI ``tools list`` command."""

    name: str
    description: str
    intrusive: bool
    available: bool


class IntrusiveToolBlocked(ToolError):
    """Raised when an intrusive tool is invoked without explicit opt-in."""


class ToolRegistry:
    """Registry of known tool wrappers."""

    _DEFAULT_TOOLS: ClassVar[tuple[type[BaseSubprocessTool], ...]] = (
        Subfinder,
        Waybackurls,
        HttpxProber,
        Dnsx,
        Katana,
        Naabu,
    )

    def __init__(
        self,
        tools: tuple[type[BaseSubprocessTool], ...] | None = None,
    ) -> None:
        self._classes = {cls.name: cls for cls in (tools or self._DEFAULT_TOOLS)}

    def names(self) -> list[str]:
        return sorted(self._classes.keys())

    def get(self, name: str) -> BaseSubprocessTool:
        if name not in self._classes:
            raise KeyError(f"unknown tool: {name}")
        return self._classes[name]()

    def describe(self) -> list[ToolDescriptor]:
        out: list[ToolDescriptor] = []
        for name in self.names():
            tool = self.get(name)
            out.append(
                ToolDescriptor(
                    name=tool.name,
                    description=tool.description,
                    intrusive=tool.intrusive,
                    available=tool.is_available(),
                )
            )
        return out

    async def run(
        self,
        name: str,
        target: str,
        scope: ScopePolicy | None = None,
        intrusive_ok: bool = False,
    ) -> ToolResult:
        tool = self.get(name)
        if tool.intrusive and not intrusive_ok:
            audit(
                "tool.refused",
                tool=name,
                target=target,
                reason="intrusive without explicit opt-in",
            )
            raise IntrusiveToolBlocked(f"{name} is intrusive; pass intrusive_ok=True to allow it")
        return await tool.run(target, scope=scope)


__all__ = [
    "BaseSubprocessTool",
    "Dnsx",
    "HttpxProber",
    "IntrusiveToolBlocked",
    "Katana",
    "Naabu",
    "Subfinder",
    "Tool",
    "ToolDescriptor",
    "ToolError",
    "ToolNotInstalledError",
    "ToolRegistry",
    "ToolResult",
    "ToolTimeoutError",
    "Waybackurls",
]
