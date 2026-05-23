"""Tests for the WAF detector."""

from __future__ import annotations

import httpx
import pytest
import respx

from bounty_agent.core import ScopePolicy
from bounty_agent.recon.waf import (
    WafSignature,
    detect_async,
    detect_from_response,
)


def _make_response(
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    text: str = "",
    cookies: dict[str, str] | None = None,
) -> httpx.Response:
    """Build a real ``httpx.Response`` so we exercise the same code path."""
    request = httpx.Request("GET", "https://example.com/")
    response = httpx.Response(
        status_code=status_code,
        headers=headers or {},
        text=text,
        request=request,
    )
    if cookies:
        for name, value in cookies.items():
            response.cookies.set(name, value)
    return response


class TestDetectFromResponse:
    def test_detects_cloudflare_via_header(self) -> None:
        response = _make_response(headers={"cf-ray": "abc123-ORD"})
        detection = detect_from_response(response)
        assert "Cloudflare" in detection.detected_vendors
        assert detection.likely_protected
        assert detection.status_code == 200

    def test_detects_cloudflare_via_cookie(self) -> None:
        response = _make_response(cookies={"__cf_bm": "value"})
        detection = detect_from_response(response)
        assert "Cloudflare" in detection.detected_vendors

    def test_detects_aws_waf(self) -> None:
        response = _make_response(headers={"x-amzn-waf-action": "block"})
        detection = detect_from_response(response)
        assert "AWS WAF" in detection.detected_vendors

    def test_detects_akamai_via_server_header(self) -> None:
        response = _make_response(headers={"server": "AkamaiGHost"})
        detection = detect_from_response(response)
        assert "Akamai" in detection.detected_vendors

    def test_detects_modsecurity_via_body(self) -> None:
        response = _make_response(status_code=403, text="ModSecurity Action: blocked")
        detection = detect_from_response(response)
        assert "ModSecurity" in detection.detected_vendors
        assert detection.likely_protected

    def test_no_match_returns_empty_vendors(self) -> None:
        response = _make_response(headers={"server": "nginx"}, text="hello world")
        detection = detect_from_response(response)
        assert detection.detected_vendors == []
        assert not detection.likely_protected

    def test_likely_protected_from_blocking_status(self) -> None:
        response = _make_response(status_code=429)
        detection = detect_from_response(response)
        assert detection.detected_vendors == []
        assert detection.likely_protected

    def test_likely_protected_from_body_marker(self) -> None:
        response = _make_response(status_code=200, text="<h1>Access Denied</h1>")
        detection = detect_from_response(response)
        assert detection.likely_protected

    def test_header_value_pattern_is_case_insensitive(self) -> None:
        response = _make_response(headers={"Server": "CloudFlare"})
        detection = detect_from_response(response)
        assert "Cloudflare" in detection.detected_vendors

    def test_custom_signature_is_honoured(self) -> None:
        custom = (WafSignature(vendor="Custom", header_names=("x-custom-shield",)),)
        response = _make_response(headers={"x-custom-shield": "yes"})
        detection = detect_from_response(response, signatures=custom)
        assert detection.detected_vendors == ["Custom"]


class TestDetectAsync:
    async def test_happy_path(self, respx_mock: respx.MockRouter) -> None:
        respx_mock.get("https://allowed.example/").mock(
            return_value=httpx.Response(200, headers={"cf-ray": "abc"})
        )
        scope = ScopePolicy.from_iterables(["allowed.example"])
        async with httpx.AsyncClient() as client:
            detection = await detect_async(client, "https://allowed.example/", scope=scope)
        assert detection.detected_vendors == ["Cloudflare"]
        assert detection.error is None

    async def test_scope_violation_propagates(self) -> None:
        from bounty_agent.core import ScopeViolation

        scope = ScopePolicy.from_iterables(["allowed.example"])
        async with httpx.AsyncClient() as client:
            with pytest.raises(ScopeViolation):
                await detect_async(client, "https://denied.example/", scope=scope)

    async def test_network_error_is_captured(
        self,
        respx_mock: respx.MockRouter,
    ) -> None:
        respx_mock.get("https://allowed.example/").mock(side_effect=httpx.ConnectError("boom"))
        scope = ScopePolicy.from_iterables(["allowed.example"])
        async with httpx.AsyncClient() as client:
            detection = await detect_async(client, "https://allowed.example/", scope=scope)
        assert detection.detected_vendors == []
        assert detection.error == "boom"

    async def test_without_scope_allows_any_host(
        self,
        respx_mock: respx.MockRouter,
    ) -> None:
        respx_mock.get("https://anywhere.example/").mock(
            return_value=httpx.Response(403, text="Request Blocked")
        )
        async with httpx.AsyncClient() as client:
            detection = await detect_async(client, "https://anywhere.example/", scope=None)
        assert detection.likely_protected
