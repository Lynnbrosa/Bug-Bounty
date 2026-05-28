"""Tests for the CORS misconfiguration probe."""

from __future__ import annotations

import httpx
import respx

from bounty_agent.core import Severity
from bounty_agent.scanners.cors import CorsProbeScanner


class TestCorsScanner:
    async def test_reflected_origin_with_credentials_is_high(
        self, respx_mock: respx.MockRouter
    ) -> None:
        def _responder(request: httpx.Request) -> httpx.Response:
            origin = request.headers.get("origin", "")
            return httpx.Response(
                200,
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                },
                text="ok",
            )

        respx_mock.get("https://target.example/").mock(side_effect=_responder)
        scanner = CorsProbeScanner(request_timeout_seconds=2.0)
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://target.example/"])
        # We expect at least the reflected_origin probe to fire as HIGH.
        reflected = [f for f in findings if "reflected_origin" in f.title]
        assert reflected
        assert reflected[0].severity == Severity.HIGH

    async def test_null_origin_accepted_is_finding(self, respx_mock: respx.MockRouter) -> None:
        def _responder(request: httpx.Request) -> httpx.Response:
            origin = request.headers.get("origin", "")
            if origin == "null":
                return httpx.Response(
                    200,
                    headers={
                        "Access-Control-Allow-Origin": "null",
                        "Access-Control-Allow-Credentials": "true",
                    },
                )
            return httpx.Response(200)

        respx_mock.get("https://target.example/").mock(side_effect=_responder)
        scanner = CorsProbeScanner(request_timeout_seconds=2.0)
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://target.example/"])
        names = {f.title for f in findings}
        assert any("null_origin" in n for n in names)

    async def test_no_acao_returns_empty(self, respx_mock: respx.MockRouter) -> None:
        respx_mock.get("https://target.example/").mock(return_value=httpx.Response(200, text="ok"))
        scanner = CorsProbeScanner(request_timeout_seconds=2.0)
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://target.example/"])
        assert findings == []

    async def test_reflection_without_credentials_downgraded_to_medium(
        self, respx_mock: respx.MockRouter
    ) -> None:
        def _responder(request: httpx.Request) -> httpx.Response:
            origin = request.headers.get("origin", "")
            return httpx.Response(
                200,
                headers={"Access-Control-Allow-Origin": origin},
                text="ok",
            )

        respx_mock.get("https://target.example/").mock(side_effect=_responder)
        scanner = CorsProbeScanner(request_timeout_seconds=2.0)
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://target.example/"])
        reflected = [f for f in findings if "reflected_origin" in f.title]
        # No credentials -> severity downgraded.
        assert reflected
        assert reflected[0].severity == Severity.MEDIUM
