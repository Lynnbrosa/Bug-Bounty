"""Tests for the ToolRegistry."""

from __future__ import annotations

from typing import ClassVar

import pytest

from bounty_agent.tools import IntrusiveToolBlocked, ToolRegistry
from bounty_agent.tools.base import BaseSubprocessTool, ToolResult


class _StubPassive(BaseSubprocessTool):
    name: ClassVar[str] = "stub-passive"
    description: ClassVar[str] = "stub passive"
    intrusive: ClassVar[bool] = False
    binary: ClassVar[str] = "stub-passive-binary"

    def build_args(self, target: str) -> list[str]:
        return [target]

    def parse_stdout(self, stdout: str, target: str) -> ToolResult:
        return ToolResult(tool=self.name, target=target, items=[stdout.strip()])


class _StubActive(_StubPassive):
    name: ClassVar[str] = "stub-active"
    intrusive: ClassVar[bool] = True
    binary: ClassVar[str] = "stub-active-binary"


def test_default_registry_lists_all_six_tools() -> None:
    registry = ToolRegistry()
    assert set(registry.names()) == {
        "subfinder",
        "waybackurls",
        "httpx",
        "dnsx",
        "katana",
        "naabu",
    }


def test_get_unknown_tool_raises() -> None:
    registry = ToolRegistry()
    with pytest.raises(KeyError):
        registry.get("not-a-tool")


def test_describe_reports_intrusive_flag() -> None:
    registry = ToolRegistry()
    descriptors = {d.name: d for d in registry.describe()}
    assert descriptors["katana"].intrusive is True
    assert descriptors["naabu"].intrusive is True
    assert descriptors["subfinder"].intrusive is False


async def test_registry_refuses_intrusive_without_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/stub")
    registry = ToolRegistry(tools=(_StubPassive, _StubActive))
    with pytest.raises(IntrusiveToolBlocked):
        await registry.run("stub-active", "https://example.com/")


async def test_registry_allows_intrusive_when_opted_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/stub")

    class _FakeProcess:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return b"hello\n", b""

        def kill(self) -> None: ...
        async def wait(self) -> int:
            return 0

    async def _factory(*_args: object, **_kwargs: object) -> _FakeProcess:
        return _FakeProcess()

    monkeypatch.setattr("bounty_agent.tools.base.asyncio.create_subprocess_exec", _factory)

    registry = ToolRegistry(tools=(_StubPassive, _StubActive))
    result = await registry.run("stub-active", "https://example.com/", intrusive_ok=True)
    assert result.items == ["hello"]
