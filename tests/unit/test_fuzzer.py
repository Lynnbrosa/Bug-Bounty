"""Tests for the ResponsibleFuzzer end-to-end via respx."""

from __future__ import annotations

import httpx
import pytest
import respx

from bounty_agent.core import ScopePolicy, ScopeViolation
from bounty_agent.fuzzing import (
    FuzzerConfig,
    PayloadRegistry,
    ResponsibleFuzzer,
    SqlInjectionAnalyzer,
)


@pytest.fixture
def fast_config() -> FuzzerConfig:
    """Configuration tuned for tests: no real delays, no retries."""
    return FuzzerConfig(
        min_delay_seconds=0.0,
        max_delay_seconds=0.0,
        max_requests_per_minute=1000,
        request_timeout_seconds=5.0,
        retry_attempts=1,
        rotate_user_agents=False,
    )


class TestInjectParam:
    def test_appends_when_no_existing_query(self) -> None:
        url = ResponsibleFuzzer._inject_param("https://example.com/api", "q", "x")
        assert url == "https://example.com/api?q=x"

    def test_replaces_existing_value(self) -> None:
        url = ResponsibleFuzzer._inject_param(
            "https://example.com/api?q=old&page=1", "q", "new"
        )
        assert "q=new" in url
        assert "page=1" in url


class TestFuzzEndpoint:
    async def test_returns_findings_on_sql_error(
        self,
        respx_mock: respx.MockRouter,
        fast_config: FuzzerConfig,
    ) -> None:
        registry = PayloadRegistry.from_mapping({"sql_injection": ["' OR '1'='1"]})
        scope = ScopePolicy.from_iterables(["allowed.example"])
        fuzzer = ResponsibleFuzzer(
            config=fast_config,
            registry=registry,
            scope=scope,
            analyzers=(SqlInjectionAnalyzer(),),
        )

        def _responder(request: httpx.Request) -> httpx.Response:
            if request.url.query:
                return httpx.Response(
                    200, text="You have an error in your SQL syntax"
                )
            return httpx.Response(200, text="ok")

        respx_mock.get(url__startswith="https://allowed.example/search").mock(
            side_effect=_responder
        )

        async with httpx.AsyncClient() as client:
            findings = await fuzzer.fuzz_endpoint(
                client,
                "https://allowed.example/search",
                param="q",
                category="sql_injection",
            )
        assert len(findings) == 1
        assert findings[0].title.startswith("Possible SQL injection")

    async def test_empty_category_returns_empty(
        self,
        fast_config: FuzzerConfig,
    ) -> None:
        fuzzer = ResponsibleFuzzer(
            config=fast_config,
            registry=PayloadRegistry.from_mapping({}),
            scope=None,
        )
        async with httpx.AsyncClient() as client:
            findings = await fuzzer.fuzz_endpoint(
                client, "https://example.com/", "q", "sql_injection"
            )
        assert findings == []

    async def test_scope_violation_raises(self, fast_config: FuzzerConfig) -> None:
        fuzzer = ResponsibleFuzzer(
            config=fast_config,
            registry=PayloadRegistry.from_mapping({"sql_injection": ["x"]}),
            scope=ScopePolicy.from_iterables(["allowed.example"]),
            analyzers=(SqlInjectionAnalyzer(),),
        )
        async with httpx.AsyncClient() as client:
            with pytest.raises(ScopeViolation):
                await fuzzer.fuzz_endpoint(
                    client, "https://denied.example/", "q", "sql_injection"
                )

    async def test_transport_error_yields_no_finding(
        self,
        respx_mock: respx.MockRouter,
        fast_config: FuzzerConfig,
    ) -> None:
        registry = PayloadRegistry.from_mapping({"sql_injection": ["x"]})
        fuzzer = ResponsibleFuzzer(
            config=fast_config,
            registry=registry,
            scope=None,
            analyzers=(SqlInjectionAnalyzer(),),
        )
        respx_mock.get(url__startswith="https://example.com/").mock(
            side_effect=httpx.ConnectError("boom")
        )
        async with httpx.AsyncClient() as client:
            findings = await fuzzer.fuzz_endpoint(
                client, "https://example.com/", "q", "sql_injection"
            )
        assert findings == []
