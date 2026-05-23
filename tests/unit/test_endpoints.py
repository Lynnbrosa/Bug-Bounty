"""Tests for endpoint enumeration."""

from __future__ import annotations

import httpx
import respx

from bounty_agent.core import ScopePolicy
from bounty_agent.recon.endpoints import enumerate_endpoints


async def test_returns_endpoints_with_success_status(
    respx_mock: respx.MockRouter,
) -> None:
    scope = ScopePolicy.from_iterables(["allowed.example"])

    def responder(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path in {"/", "/api"}:
            return httpx.Response(200, text="ok")
        if path == "/login":
            return httpx.Response(302, headers={"Location": "/dashboard"})
        return httpx.Response(404)

    respx_mock.get(host="allowed.example").mock(side_effect=responder)

    async with httpx.AsyncClient() as client:
        results = await enumerate_endpoints(
            client,
            "https://allowed.example/",
            scope=scope,
            paths=("/", "/api", "/login", "/missing"),
        )
    assert "https://allowed.example/" in results
    assert "https://allowed.example/api" in results
    assert "https://allowed.example/login" in results
    assert "https://allowed.example/missing" not in results


async def test_filters_out_of_scope_paths(
    respx_mock: respx.MockRouter,
) -> None:
    scope = ScopePolicy.from_iterables(
        ["allowed.example"], path_denylist=["/admin"]
    )
    respx_mock.get(host="allowed.example").mock(return_value=httpx.Response(200))

    async with httpx.AsyncClient() as client:
        results = await enumerate_endpoints(
            client,
            "https://allowed.example/",
            scope=scope,
            paths=("/admin", "/safe"),
        )
    assert all("/admin" not in url for url in results)
    assert "https://allowed.example/safe" in results
