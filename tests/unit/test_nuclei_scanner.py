"""Tests for the NucleiScanner async wrapper.

The nuclei binary itself is not required: we monkeypatch ``shutil.which``
and ``asyncio.create_subprocess_exec`` so the wrapper logic can be
exercised in isolation.
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import uuid4

import pytest

from bounty_agent.core import ScopePolicy
from bounty_agent.scanners.nuclei import (
    NucleiConfig,
    NucleiNotInstalledError,
    NucleiScanner,
    NucleiTimeoutError,
)


class _FakeProcess:
    def __init__(
        self,
        stdout: bytes = b"",
        stderr: bytes = b"",
        return_code: int = 0,
        delay: float = 0.0,
        hang: bool = False,
    ) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = return_code
        self._delay = delay
        self._hang = hang
        self._killed = False

    async def communicate(self) -> tuple[bytes, bytes]:
        if self._hang:
            await asyncio.sleep(3600)
        if self._delay:
            await asyncio.sleep(self._delay)
        return self._stdout, self._stderr

    def kill(self) -> None:
        self._killed = True

    async def wait(self) -> int:
        return self.returncode


def _fake_subprocess_factory(process: _FakeProcess) -> Any:
    async def _factory(*_args: Any, **_kwargs: Any) -> _FakeProcess:
        return process

    return _factory


@pytest.fixture
def fixture_jsonl() -> str:
    return (
        '{"template-id":"x","info":{"name":"Demo","severity":"high"},'
        '"matched-at":"https://allowed.example/"}\n'
    )


class TestScopeIntegration:
    async def test_scope_violation_is_raised(self) -> None:
        scope = ScopePolicy.from_iterables(["allowed.example"])
        scanner = NucleiScanner(NucleiConfig(), scope=scope)
        from bounty_agent.core import ScopeViolation

        with pytest.raises(ScopeViolation):
            await scanner.scan("https://denied.example/")

    async def test_scope_none_skips_check(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fixture_jsonl: str,
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "bounty_agent.scanners.nuclei.asyncio.create_subprocess_exec",
            _fake_subprocess_factory(_FakeProcess(stdout=fixture_jsonl.encode())),
        )
        scanner = NucleiScanner(NucleiConfig(timeout_seconds=1), scope=None)
        result = await scanner.scan("https://any.example/")
        assert len(result.findings) == 1


class TestBinaryDiscovery:
    async def test_missing_binary_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda _: None)
        scanner = NucleiScanner(NucleiConfig())
        with pytest.raises(NucleiNotInstalledError):
            await scanner.scan("https://example.com/")


class TestSuccessPath:
    async def test_returns_parsed_findings(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fixture_jsonl: str,
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "bounty_agent.scanners.nuclei.asyncio.create_subprocess_exec",
            _fake_subprocess_factory(_FakeProcess(stdout=fixture_jsonl.encode())),
        )
        scanner = NucleiScanner(NucleiConfig(timeout_seconds=1))
        result = await scanner.scan("https://example.com/", scan_id=uuid4())
        assert result.return_code == 0
        assert len(result.findings) == 1
        assert result.findings[0].title == "Demo"


class TestTimeout:
    async def test_timeout_kills_process_and_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/nuclei")
        fake = _FakeProcess(hang=True)
        monkeypatch.setattr(
            "bounty_agent.scanners.nuclei.asyncio.create_subprocess_exec",
            _fake_subprocess_factory(fake),
        )
        # Patch wait_for to raise immediately so the test stays fast.
        original_wait_for = asyncio.wait_for

        async def fast_wait_for(
            awaitable: Any,
            timeout: float,  # noqa: ARG001,ASYNC109 - mirrors asyncio.wait_for
        ) -> Any:
            awaitable.close()
            raise TimeoutError

        monkeypatch.setattr(
            "bounty_agent.scanners.nuclei.asyncio.wait_for", fast_wait_for
        )

        scanner = NucleiScanner(NucleiConfig(timeout_seconds=1))
        with pytest.raises(NucleiTimeoutError):
            await scanner.scan("https://example.com/")
        assert fake._killed

        # Restore for any subsequent test in the same module.
        monkeypatch.setattr(
            "bounty_agent.scanners.nuclei.asyncio.wait_for", original_wait_for
        )


class TestCommandBuilder:
    def test_command_includes_all_flags(self) -> None:
        scanner = NucleiScanner(
            NucleiConfig(
                templates_path="/tmp/templates",
                severity=("critical", "high"),
                concurrency=2,
                rate_limit=5,
                timeout_seconds=30,
            )
        )
        cmd = scanner._build_command("https://example.com/")
        assert cmd[0] == "nuclei"
        assert "-u" in cmd
        assert "https://example.com/" in cmd
        assert "-jsonl" in cmd
        assert "-silent" in cmd
        # severity joined
        idx = cmd.index("-severity")
        assert cmd[idx + 1] == "critical,high"
