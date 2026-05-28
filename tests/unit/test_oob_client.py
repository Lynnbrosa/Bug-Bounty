"""Tests for OobClient HTTP polling."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import respx

from bounty_agent.oob import OobClient


class TestOobClient:
    async def test_polls_and_decodes_events(self, respx_mock: respx.MockRouter) -> None:
        respx_mock.get("http://oob.example/__oob/callbacks").mock(
            return_value=httpx.Response(
                200,
                json={
                    "events": [
                        {
                            "token": "abc123",
                            "protocol": "http",
                            "src_ip": "1.2.3.4",
                            "method": "GET",
                            "path": "/probe",
                            "host": "abc123.callback.example",
                            "user_agent": "curl/8",
                            "timestamp": "2026-05-28T01:02:03+00:00",
                        }
                    ]
                },
            )
        )
        client = OobClient("http://oob.example")
        events = await client.poll()
        assert len(events) == 1
        assert events[0].token == "abc123"
        assert events[0].method == "GET"

    async def test_since_parameter_sent(self, respx_mock: respx.MockRouter) -> None:
        captured: list[str] = []

        def _responder(request: httpx.Request) -> httpx.Response:
            captured.append(str(request.url))
            return httpx.Response(200, json={"events": []})

        respx_mock.get("http://oob.example/__oob/callbacks").mock(side_effect=_responder)
        client = OobClient("http://oob.example")
        await client.poll(since=datetime(2026, 5, 28, tzinfo=UTC))
        assert any("since=" in url for url in captured)

    async def test_invalid_json_returns_empty(self, respx_mock: respx.MockRouter) -> None:
        respx_mock.get("http://oob.example/__oob/callbacks").mock(
            return_value=httpx.Response(200, text="not json")
        )
        client = OobClient("http://oob.example")
        events = await client.poll()
        assert events == []

    async def test_5xx_returns_empty(self, respx_mock: respx.MockRouter) -> None:
        respx_mock.get("http://oob.example/__oob/callbacks").mock(
            return_value=httpx.Response(500, text="boom")
        )
        client = OobClient("http://oob.example")
        events = await client.poll()
        assert events == []

    async def test_transport_error_returns_empty(self, respx_mock: respx.MockRouter) -> None:
        respx_mock.get("http://oob.example/__oob/callbacks").mock(
            side_effect=httpx.ConnectError("server down")
        )
        client = OobClient("http://oob.example")
        events = await client.poll()
        assert events == []
