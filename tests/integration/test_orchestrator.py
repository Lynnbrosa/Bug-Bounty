"""Integration test for the high-level orchestrator.

Wires the real orchestrator to a real httpx.AsyncClient backed by respx,
a real ScopePolicy and PayloadRegistry, and a stub NucleiScanner. This
exercises the production code path without touching the network or the
nuclei binary.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from bounty_agent.config import Config
from bounty_agent.core import ScanResult, ScopePolicy, ScopeViolation
from bounty_agent.fuzzing import PayloadRegistry
from bounty_agent.orchestrator import BountyAgent
from bounty_agent.scanners import NucleiResult, NucleiScanner


class _StubNuclei(NucleiScanner):
    """Drop-in replacement that never touches subprocess.

    Subclasses NucleiScanner so type checks pass; overrides ``scan`` to
    return a deterministic empty result.
    """

    def __init__(self) -> None:
        from bounty_agent.scanners import NucleiConfig

        super().__init__(NucleiConfig(), scope=None)
        self.calls: list[str] = []

    async def scan(  # type: ignore[override]
        self,
        url: str,
        scan_id: object = None,  # noqa: ARG002 - mirrors NucleiScanner.scan
    ) -> NucleiResult:
        self.calls.append(url)
        return NucleiResult(findings=[], stderr="", return_code=0)


@pytest.fixture
def config() -> Config:
    project_root = Path(__file__).resolve().parents[2]
    config = Config(
        scope={"allowlist": ["allowed.example"]},  # type: ignore[arg-type]
        agent={  # type: ignore[arg-type]
            "min_delay_seconds": 0.0,
            "max_delay_seconds": 0.0,
            "max_requests_per_minute": 1000,
            "request_timeout_seconds": 5.0,
        },
        fuzzing={"enabled": True, "categories": ["sql_injection"]},  # type: ignore[arg-type]
        nuclei={"enabled": True},  # type: ignore[arg-type]
        waf={"detect": True},  # type: ignore[arg-type]
    )
    _ = project_root  # for future extensibility
    return config


@pytest.fixture
def payloads() -> PayloadRegistry:
    return PayloadRegistry.from_mapping({"sql_injection": ["' OR '1'='1"]})


async def test_orchestrator_runs_waf_fuzz_and_nuclei(
    respx_mock: respx.MockRouter,
    config: Config,
    payloads: PayloadRegistry,
) -> None:
    # Every request to the allowed host gets a SQL error so the fuzzer
    # produces a finding; the absence of payload returns a clean baseline.
    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.query:
            return httpx.Response(
                200,
                text="You have an error in your SQL syntax",
                headers={"content-type": "text/html"},
            )
        return httpx.Response(200, text="ok", headers={"cf-ray": "abc"})

    respx_mock.get(host="allowed.example").mock(side_effect=responder)

    stub_nuclei = _StubNuclei()
    scope = ScopePolicy.from_iterables(["allowed.example"])
    agent = BountyAgent(
        config=config,
        payload_registry=payloads,
        scope=scope,
        nuclei=stub_nuclei,
    )

    result = await agent.scan("https://allowed.example/")
    assert isinstance(result, ScanResult)
    assert result.target.host == "allowed.example"
    assert result.authorization is not None
    assert "Cloudflare" in result.waf_detection.detected_vendors
    assert any(f.title.startswith("Possible SQL injection") for f in result.findings)
    # No tools are installed in the test environment, so the recon
    # pipeline falls back to the original target as the only endpoint.
    assert [str(u) for u in result.endpoints] == ["https://allowed.example/"]
    # Nuclei stub was invoked exactly once with the right target.
    assert stub_nuclei.calls == ["https://allowed.example/"]


async def test_orchestrator_refuses_out_of_scope(
    config: Config,
    payloads: PayloadRegistry,
) -> None:
    scope = ScopePolicy.from_iterables(["allowed.example"])
    agent = BountyAgent(
        config=config,
        payload_registry=payloads,
        scope=scope,
        nuclei=_StubNuclei(),
    )
    with pytest.raises(ScopeViolation):
        await agent.scan("https://denied.example/")
