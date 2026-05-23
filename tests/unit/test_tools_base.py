"""Tests for the shared BaseSubprocessTool plumbing."""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar

import pytest

from bounty_agent.core import ScopePolicy, ScopeViolation
from bounty_agent.tools.base import (
    BaseSubprocessTool,
    ToolResult,
    ToolTimeoutError,
)


class _Echo(BaseSubprocessTool):
    name: ClassVar[str] = "echo-tool"
    description: ClassVar[str] = "test echo"
    intrusive: ClassVar[bool] = False
    binary: ClassVar[str] = "echo-tool-binary"
    timeout_seconds: ClassVar[int] = 5

    def build_args(self, target: str) -> list[str]:
        return ["--target", target]

    def parse_stdout(self, stdout: str, target: str) -> ToolResult:
        items = [line for line in stdout.splitlines() if line]
        return ToolResult(tool=self.name, target=target, items=items)


class _ActiveEcho(_Echo):
    name: ClassVar[str] = "active-echo"
    intrusive: ClassVar[bool] = True
    requires_scope_check: ClassVar[bool] = True


class _FakeProcess:
    def __init__(
        self,
        stdout: bytes = b"",
        stderr: bytes = b"",
        return_code: int = 0,
        hang: bool = False,
    ) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = return_code
        self._hang = hang
        self.killed = False

    async def communicate(self) -> tuple[bytes, bytes]:
        if self._hang:
            await asyncio.sleep(3600)
        return self._stdout, self._stderr

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        return self.returncode


def _fake_subprocess(process: _FakeProcess) -> Any:
    async def factory(*_args: Any, **_kwargs: Any) -> _FakeProcess:
        return process

    return factory


class TestAvailability:
    def test_missing_binary_returns_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda _: None)
        tool = _Echo()
        result = asyncio.run(tool.run("example.com"))
        assert result.skipped
        assert "echo-tool-binary" in (result.skipped_reason or "")


class TestSuccessPath:
    def test_parses_stdout_into_items(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/echo")
        monkeypatch.setattr(
            "bounty_agent.tools.base.asyncio.create_subprocess_exec",
            _fake_subprocess(_FakeProcess(stdout=b"a\nb\nc\n")),
        )
        tool = _Echo()
        result = asyncio.run(tool.run("example.com"))
        assert result.items == ["a", "b", "c"]
        assert result.return_code == 0
        assert not result.skipped


class TestScopeIntegration:
    def test_active_tool_respects_scope(self) -> None:
        scope = ScopePolicy.from_iterables(["allowed.example"])
        tool = _ActiveEcho()
        with pytest.raises(ScopeViolation):
            asyncio.run(tool.run("https://denied.example/", scope=scope))


class TestTimeout:
    def test_timeout_kills_process(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/echo")
        fake = _FakeProcess(hang=True)
        monkeypatch.setattr(
            "bounty_agent.tools.base.asyncio.create_subprocess_exec",
            _fake_subprocess(fake),
        )

        async def fast_wait_for(
            awaitable: Any,
            timeout: float,  # noqa: ARG001,ASYNC109 - mirrors asyncio.wait_for
        ) -> Any:
            awaitable.close()
            raise TimeoutError

        monkeypatch.setattr("bounty_agent.tools.base.asyncio.wait_for", fast_wait_for)
        tool = _Echo()
        with pytest.raises(ToolTimeoutError):
            asyncio.run(tool.run("example.com"))
        assert fake.killed
