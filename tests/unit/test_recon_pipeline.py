"""Tests for the external tool recon pipeline."""

from __future__ import annotations

from typing import ClassVar
from uuid import uuid4

import pytest

from bounty_agent.config import Config
from bounty_agent.core import ScopePolicy
from bounty_agent.recon.pipeline import run_recon_pipeline
from bounty_agent.tools import ToolRegistry
from bounty_agent.tools.base import BaseSubprocessTool, ToolResult


def _config(**tools_overrides: bool) -> Config:
    return Config(
        scope={"allowlist": ["example.com", "*.example.com"]},  # type: ignore[arg-type]
        tools=tools_overrides,  # type: ignore[arg-type]
    )


def _scope() -> ScopePolicy:
    return ScopePolicy.from_iterables(["example.com", "*.example.com"])


class _StubTool(BaseSubprocessTool):
    """Subclass that returns a hard-coded ToolResult without subprocess."""

    canned_items: ClassVar[list[str]] = []

    def build_args(self, target: str) -> list[str]:
        return [target]

    def parse_stdout(
        self,
        stdout: str,  # noqa: ARG002 - protocol signature
        target: str,
    ) -> ToolResult:
        return ToolResult(tool=self.name, target=target, items=list(self.canned_items))

    async def run(  # type: ignore[override]
        self,
        target: str,
        scope: ScopePolicy | None = None,  # noqa: ARG002
    ) -> ToolResult:
        return ToolResult(
            tool=self.name,
            target=target,
            items=list(self.canned_items),
        )


def _make_stub(
    name_: str,
    items: list[str],
    intrusive_: bool = False,
) -> type[_StubTool]:
    class _S(_StubTool):
        name: ClassVar[str] = name_
        description: ClassVar[str] = f"stub for {name_}"
        intrusive: ClassVar[bool] = intrusive_
        binary: ClassVar[str] = f"{name_}-stub"
        canned_items: ClassVar[list[str]] = items

    return _S


def _registry_with(*tools: type[_StubTool]) -> ToolRegistry:
    return ToolRegistry(tools=tools)


class TestPassivePath:
    async def test_subfinder_and_waybackurls_compose(self) -> None:
        subfinder = _make_stub(
            "subfinder",
            ["api.example.com", "admin.example.com"],
        )
        wayback = _make_stub(
            "waybackurls",
            [
                "https://example.com/api?q=1",
                "https://example.com/old",
            ],
        )

        # httpx echoes back the URL it was asked to probe so we can see
        # which candidates the pipeline forwarded.
        class _Echo(_StubTool):
            name: ClassVar[str] = "httpx"
            description: ClassVar[str] = "stub"
            intrusive: ClassVar[bool] = False
            binary: ClassVar[str] = "httpx-stub"
            canned_items: ClassVar[list[str]] = []

            async def run(  # type: ignore[override]
                self,
                target: str,
                scope: ScopePolicy | None = None,  # noqa: ARG002
            ) -> ToolResult:
                return ToolResult(
                    tool=self.name,
                    target=target,
                    items=[target],
                )

        registry = _registry_with(subfinder, wayback, _Echo)
        result = await run_recon_pipeline(
            target="https://example.com/",
            config=_config(subfinder=True, waybackurls=True, httpx=True),
            scope=_scope(),
            registry=registry,
            scan_id=uuid4(),
        )

        assert "api.example.com" in result.subdomains
        assert "admin.example.com" in result.subdomains
        # httpx returned every candidate URL it probed: the original
        # target, the two subdomains and the in-scope wayback URLs.
        assert "https://example.com/" in result.urls
        assert "https://api.example.com" in result.urls
        assert "https://example.com/api?q=1" in result.urls


class TestIntrusiveGate:
    async def test_katana_skipped_without_opt_in(self) -> None:
        registry = _registry_with(
            _make_stub("katana", ["https://example.com/a"], intrusive_=True),
        )
        result = await run_recon_pipeline(
            target="https://example.com/",
            config=_config(katana=True, httpx=False),
            scope=_scope(),
            registry=registry,
            intrusive_ok=False,
        )
        # Without opt-in, katana never contributes URLs.
        assert result.urls == []

    async def test_katana_runs_with_opt_in(self) -> None:
        registry = _registry_with(
            _make_stub("katana", ["https://example.com/a"], intrusive_=True),
        )
        result = await run_recon_pipeline(
            target="https://example.com/",
            config=_config(katana=True, httpx=False),
            scope=_scope(),
            registry=registry,
            intrusive_ok=True,
        )
        assert "https://example.com/a" in result.urls


class TestNaabu:
    async def test_naabu_emits_info_findings(self) -> None:
        registry = _registry_with(
            _make_stub(
                "naabu",
                ["example.com:80", "example.com:443"],
                intrusive_=True,
            ),
        )
        result = await run_recon_pipeline(
            target="https://example.com/",
            config=_config(naabu=True, httpx=False),
            scope=_scope(),
            registry=registry,
            intrusive_ok=True,
        )
        titles = [f.title for f in result.findings]
        assert any("80" in t for t in titles)
        assert any("443" in t for t in titles)
        assert all(f.severity.value == "info" for f in result.findings)


class TestCache:
    async def test_cache_hit_short_circuits_tool(self) -> None:
        """If the cache has fresh data the wrapper is never invoked."""

        class _ExplodingSubfinder(_StubTool):
            name: ClassVar[str] = "subfinder"
            description: ClassVar[str] = "boom"
            intrusive: ClassVar[bool] = False
            binary: ClassVar[str] = "subfinder-stub"
            canned_items: ClassVar[list[str]] = []

            async def run(  # type: ignore[override]
                self,
                target: str,  # noqa: ARG002
                scope: ScopePolicy | None = None,  # noqa: ARG002
            ) -> ToolResult:
                raise AssertionError("subfinder should have been cached")

        class _InMemoryCache:
            def __init__(self) -> None:
                self.store: dict[tuple[str, str], list[str]] = {}

            def get(self, tool: str, target: str) -> list[str] | None:
                return self.store.get((tool, target))

            def set(self, tool: str, target: str, items: list[str], ttl_seconds: int) -> None:
                _ = ttl_seconds
                self.store[(tool, target)] = items

        cache = _InMemoryCache()
        cache.set("subfinder", "https://example.com/", ["pre.example.com"], 3600)

        registry = _registry_with(_ExplodingSubfinder)
        result = await run_recon_pipeline(
            target="https://example.com/",
            config=_config(subfinder=True, httpx=False),
            scope=_scope(),
            registry=registry,
            cache=cache,  # type: ignore[arg-type]
        )
        assert "pre.example.com" in result.subdomains

    async def test_cache_miss_writes_back(self) -> None:
        class _InMemoryCache:
            def __init__(self) -> None:
                self.store: dict[tuple[str, str], list[str]] = {}

            def get(self, tool: str, target: str) -> list[str] | None:
                return self.store.get((tool, target))

            def set(self, tool: str, target: str, items: list[str], ttl_seconds: int) -> None:
                _ = ttl_seconds
                self.store[(tool, target)] = items

        cache = _InMemoryCache()
        registry = _registry_with(
            _make_stub("subfinder", ["fresh.example.com"]),
        )
        await run_recon_pipeline(
            target="https://example.com/",
            config=_config(subfinder=True, httpx=False),
            scope=_scope(),
            registry=registry,
            cache=cache,  # type: ignore[arg-type]
        )
        assert cache.store[("subfinder", "https://example.com/")] == ["fresh.example.com"]


class TestFailures:
    async def test_unknown_tool_in_registry_does_not_crash(self) -> None:
        # No subfinder in this registry; flag asks for it.
        registry = _registry_with(_make_stub("waybackurls", []))
        result = await run_recon_pipeline(
            target="https://example.com/",
            config=_config(subfinder=True, waybackurls=True, httpx=False),
            scope=_scope(),
            registry=registry,
        )
        # We collected an error and kept going.
        assert any("subfinder" in err for err in result.errors)


@pytest.fixture(autouse=True)
def _close_event_loop_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Quiet RuntimeWarning chatter when the test loop tears down."""
    _ = monkeypatch
    yield
