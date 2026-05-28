"""Tests for the ResponsibleFuzzer end-to-end via respx."""

from __future__ import annotations

import httpx
import pytest
import respx

from bounty_agent.core import ScopePolicy, ScopeViolation
from bounty_agent.fuzzing import (
    FUZZ_MARKER,
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
        url = ResponsibleFuzzer._inject_param("https://example.com/api?q=old&page=1", "q", "new")
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
                return httpx.Response(200, text="You have an error in your SQL syntax")
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
                await fuzzer.fuzz_endpoint(client, "https://denied.example/", "q", "sql_injection")

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


class TestInjectPathSegment:
    def test_replaces_numeric_id(self) -> None:
        url = ResponsibleFuzzer._inject_path_segment("https://example.com/api/Users/1", "999")
        assert url == "https://example.com/api/Users/999"

    def test_handles_root_path(self) -> None:
        url = ResponsibleFuzzer._inject_path_segment("https://example.com/", "x")
        assert url == "https://example.com/x"


class TestLastPathSegmentIsId:
    def test_numeric_tail_is_id(self) -> None:
        assert ResponsibleFuzzer._last_path_segment_is_id("https://e.example/api/Users/42")

    def test_trailing_slash_still_works(self) -> None:
        assert ResponsibleFuzzer._last_path_segment_is_id("https://e.example/api/Users/42/")

    def test_slug_is_not_id(self) -> None:
        assert not ResponsibleFuzzer._last_path_segment_is_id("https://e.example/api/Users/alice")

    def test_empty_path_is_not_id(self) -> None:
        assert not ResponsibleFuzzer._last_path_segment_is_id("https://e.example/")


class TestFuzzPathSegment:
    async def test_fuzzes_numeric_tail(
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

        captured: list[str] = []

        def _responder(request: httpx.Request) -> httpx.Response:
            captured.append(str(request.url))
            # The baseline request hits the literal /Users/1; the payload
            # request replaces "1" with the injected SQL fragment.
            if request.url.path.endswith("/Users/1"):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="You have an error in your SQL syntax")

        respx_mock.get(url__startswith="https://allowed.example/api/Users").mock(
            side_effect=_responder
        )

        async with httpx.AsyncClient() as client:
            findings = await fuzzer.fuzz_path_segment(
                client,
                "https://allowed.example/api/Users/1",
                category="sql_injection",
            )

        # The baseline request goes to /api/Users/1; the payload request
        # replaces the tail segment.
        assert any("/api/Users/1" in url for url in captured)
        assert any("OR" in url and "/api/Users/" in url for url in captured)
        assert len(findings) == 1

    async def test_skips_non_numeric_tail(
        self,
        fast_config: FuzzerConfig,
    ) -> None:
        registry = PayloadRegistry.from_mapping({"sql_injection": ["x"]})
        fuzzer = ResponsibleFuzzer(
            config=fast_config,
            registry=registry,
            scope=None,
            analyzers=(SqlInjectionAnalyzer(),),
        )
        async with httpx.AsyncClient() as client:
            findings = await fuzzer.fuzz_path_segment(
                client,
                "https://example.com/api/Users/alice",
                category="sql_injection",
            )
        assert findings == []


class TestFuzzJsonBody:
    async def test_substitutes_marker_with_payload(
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

        bodies: list[dict] = []

        def _responder(request: httpx.Request) -> httpx.Response:
            import json

            bodies.append(json.loads(request.content))
            # Return SQL error when the email field contains the payload.
            if "OR" in bodies[-1].get("email", ""):
                return httpx.Response(500, text="SQLITE_ERROR: near 'OR': syntax error")
            return httpx.Response(200, text="ok")

        respx_mock.post("https://allowed.example/login").mock(side_effect=_responder)

        async with httpx.AsyncClient() as client:
            findings = await fuzzer.fuzz_json_body(
                client,
                "https://allowed.example/login",
                method="POST",
                body_template={"email": FUZZ_MARKER, "password": "x"},
                category="sql_injection",
            )
        # We expect at least the baseline + 1 payload request.
        assert len(bodies) >= 2
        assert any("OR" in b["email"] for b in bodies)
        # Non-marked fields keep their literal value.
        assert all(b["password"] == "x" for b in bodies)
        assert len(findings) == 1

    async def test_no_marker_returns_empty(
        self,
        fast_config: FuzzerConfig,
    ) -> None:
        fuzzer = ResponsibleFuzzer(
            config=fast_config,
            registry=PayloadRegistry.from_mapping({"sql_injection": ["x"]}),
            scope=None,
            analyzers=(SqlInjectionAnalyzer(),),
        )
        async with httpx.AsyncClient() as client:
            findings = await fuzzer.fuzz_json_body(
                client,
                "https://example.com/login",
                method="POST",
                body_template={"email": "literal", "password": "literal"},
                category="sql_injection",
            )
        assert findings == []


class TestFuzzerOobSubstitution:
    async def test_substitutes_oob_url_and_registers_token(
        self,
        respx_mock: respx.MockRouter,
        fast_config: FuzzerConfig,
    ) -> None:
        from bounty_agent.oob import TokenRegistry

        registry = PayloadRegistry.from_mapping(
            {"sql_injection": ["1' AND UTL_HTTP.REQUEST('http://{OOB_URL}/x')--"]}
        )
        token_registry = TokenRegistry()
        fuzzer = ResponsibleFuzzer(
            config=fast_config,
            registry=registry,
            scope=None,
            analyzers=(SqlInjectionAnalyzer(),),
            oob_token_registry=token_registry,
            oob_domain="callback.test",
        )
        captured: list[str] = []

        def _responder(request: httpx.Request) -> httpx.Response:
            captured.append(str(request.url))
            return httpx.Response(200, text="ok")

        respx_mock.get(url__startswith="https://example.com/search").mock(side_effect=_responder)

        async with httpx.AsyncClient() as client:
            await fuzzer.fuzz_endpoint(
                client,
                "https://example.com/search",
                param="q",
                category="sql_injection",
            )

        # A token should have been minted and stored.
        tokens = token_registry.all_tokens()
        assert len(tokens) == 1
        token = tokens[0]
        # The URL the fuzzer requested must contain <token>.callback.test
        # instead of the {OOB_URL} placeholder.
        assert any(f"{token.token}.callback.test" in url for url in captured), (
            f"token not substituted into request URL: {captured}"
        )
        assert not any("{OOB_URL}" in url for url in captured), (
            "placeholder leaked into outbound request"
        )

    async def test_oob_disabled_leaves_placeholder_as_is(
        self,
        respx_mock: respx.MockRouter,
        fast_config: FuzzerConfig,
    ) -> None:
        # When the OOB integration is not wired, payloads with the
        # placeholder are sent verbatim. (The fuzzer is policy-light:
        # we don't want to silently swallow operator-authored
        # payloads.)
        registry = PayloadRegistry.from_mapping({"sql_injection": ["payload-{OOB_URL}-marker"]})
        fuzzer = ResponsibleFuzzer(
            config=fast_config,
            registry=registry,
            scope=None,
            analyzers=(SqlInjectionAnalyzer(),),
        )
        captured: list[str] = []

        def _responder(request: httpx.Request) -> httpx.Response:
            captured.append(str(request.url))
            return httpx.Response(200, text="ok")

        respx_mock.get(url__startswith="https://example.com/").mock(side_effect=_responder)

        async with httpx.AsyncClient() as client:
            await fuzzer.fuzz_endpoint(
                client,
                "https://example.com/search",
                param="q",
                category="sql_injection",
            )
        # Placeholder is URL-encoded when sent on the wire but should
        # remain (encoded as %7B / %7D) in the captured outbound URL.
        assert any("%7BOOB_URL%7D" in url or "{OOB_URL}" in url for url in captured)
