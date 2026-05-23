"""Tests for the application fingerprinter."""

from __future__ import annotations

import httpx

from bounty_agent.recon.app_fingerprint import detect_stack_from_response


def _response(text: str = "", headers: dict[str, str] | None = None) -> httpx.Response:
    request = httpx.Request("GET", "https://example.com/")
    return httpx.Response(
        status_code=200,
        headers=headers or {},
        text=text,
        request=request,
    )


def test_detects_django_body_marker() -> None:
    response = _response(text='<input name="csrfmiddlewaretoken" value="x">')
    assert "Django" in detect_stack_from_response(response)


def test_detects_laravel_body_marker() -> None:
    response = _response(text="set-cookie: laravel_session=abc")
    assert "Laravel" in detect_stack_from_response(response)


def test_detects_aspnet_via_header() -> None:
    response = _response(headers={"x-powered-by": "ASP.NET 4.0"})
    assert "ASP.NET" in detect_stack_from_response(response)


def test_no_match_returns_empty() -> None:
    response = _response(text="plain content", headers={"server": "nginx"})
    assert detect_stack_from_response(response) == []
