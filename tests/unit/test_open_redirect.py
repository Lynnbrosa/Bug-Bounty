"""Tests for the open-redirect probe."""

from __future__ import annotations

import httpx
import respx

from bounty_agent.scanners.open_redirect import OpenRedirectScanner


class TestOpenRedirectScanner:
    async def test_redirect_to_attacker_host_is_flagged(self, respx_mock: respx.MockRouter) -> None:
        def _responder(request: httpx.Request) -> httpx.Response:
            # Reflect any "url" param into the Location header.
            url_value = request.url.params.get("url", "")
            return httpx.Response(302, headers={"Location": url_value})

        respx_mock.get(url__startswith="https://target.example/login").mock(side_effect=_responder)
        scanner = OpenRedirectScanner(request_timeout_seconds=2.0)
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://target.example/login?url=x"])
        # At least one finding fires (the absolute_url payload).
        assert any("attacker.example" in f.evidence["location_header"] for f in findings)

    async def test_safe_redirect_no_finding(self, respx_mock: respx.MockRouter) -> None:
        respx_mock.get(url__startswith="https://target.example/").mock(
            return_value=httpx.Response(
                302, headers={"Location": "https://target.example/dashboard"}
            )
        )
        scanner = OpenRedirectScanner(request_timeout_seconds=2.0)
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://target.example/login?url=x"])
        assert findings == []

    async def test_no_redirect_status_no_finding(self, respx_mock: respx.MockRouter) -> None:
        respx_mock.get(url__startswith="https://target.example/").mock(
            return_value=httpx.Response(200, text="ok")
        )
        scanner = OpenRedirectScanner(request_timeout_seconds=2.0)
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://target.example/login?url=x"])
        assert findings == []
