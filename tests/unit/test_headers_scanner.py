"""Tests for the cookie + CSP passive auditors."""

from __future__ import annotations

import httpx

from bounty_agent.core import Severity
from bounty_agent.scanners.headers import CookieSecurityAuditor, CspAuditor


def _response(headers: dict[str, str | list[str]]) -> httpx.Response:
    """Build a real httpx.Response with multiple Set-Cookie headers."""
    request = httpx.Request("GET", "https://example.com/")
    # httpx accepts a list-of-tuples for repeated headers.
    pairs: list[tuple[str, str]] = []
    for name, value in headers.items():
        if isinstance(value, list):
            for v in value:
                pairs.append((name, v))
        else:
            pairs.append((name, value))
    return httpx.Response(200, request=request, headers=pairs)


class TestCookieAuditor:
    def test_session_cookie_missing_secure_and_httponly(self) -> None:
        auditor = CookieSecurityAuditor()
        response = _response({"Set-Cookie": "session=abc123; Path=/"})
        findings = auditor.audit("https://example.com/", response)
        assert len(findings) == 1
        missing = findings[0].evidence["missing_attributes"]
        assert "Secure" in missing
        assert "HttpOnly" in missing
        assert "SameSite" in missing

    def test_fully_protected_cookie_no_finding(self) -> None:
        auditor = CookieSecurityAuditor()
        response = _response({"Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Strict"})
        assert auditor.audit("https://example.com/", response) == []

    def test_tracking_cookies_ignored(self) -> None:
        # `_ga` is not session-shaped; should be ignored.
        auditor = CookieSecurityAuditor()
        response = _response({"Set-Cookie": "_ga=GA1.2.123; Path=/"})
        assert auditor.audit("https://example.com/", response) == []

    def test_no_set_cookie_no_finding(self) -> None:
        auditor = CookieSecurityAuditor()
        response = _response({"Content-Type": "text/html"})
        assert auditor.audit("https://example.com/", response) == []

    def test_secure_only_flagged_on_https_url(self) -> None:
        # If the URL is HTTP, missing Secure shouldn't be flagged
        # (the cookie can't be sent securely anyway).
        auditor = CookieSecurityAuditor()
        response = _response({"Set-Cookie": "session=x"})
        findings = auditor.audit("http://example.com/", response)
        assert findings  # still flags HttpOnly + SameSite missing
        missing = findings[0].evidence["missing_attributes"]
        assert "Secure" not in missing
        assert "HttpOnly" in missing


class TestCspAuditor:
    def test_no_csp_header_returns_low_finding(self) -> None:
        auditor = CspAuditor()
        response = _response({})
        findings = auditor.audit("https://example.com/", response)
        assert len(findings) == 1
        assert "Content-Security-Policy header missing" in findings[0].title
        assert findings[0].severity == Severity.LOW

    def test_unsafe_inline_flagged(self) -> None:
        auditor = CspAuditor()
        response = _response({"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"})
        findings = auditor.audit("https://example.com/", response)
        titles = [f.title for f in findings]
        assert any("unsafe-inline" in t for t in titles)

    def test_wildcard_default_src_flagged(self) -> None:
        auditor = CspAuditor()
        response = _response({"Content-Security-Policy": "default-src *"})
        findings = auditor.audit("https://example.com/", response)
        titles = [f.title for f in findings]
        assert any("default-src" in t and "wildcard" in t for t in titles)

    def test_missing_frame_ancestors_flagged(self) -> None:
        auditor = CspAuditor()
        response = _response({"Content-Security-Policy": "default-src 'self'; script-src 'self'"})
        findings = auditor.audit("https://example.com/", response)
        titles = [f.title for f in findings]
        assert any("frame-ancestors" in t for t in titles)

    def test_well_configured_csp_no_findings(self) -> None:
        auditor = CspAuditor()
        response = _response(
            {
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'self'; object-src 'none'; "
                    "frame-ancestors 'none'; base-uri 'self'"
                )
            }
        )
        assert auditor.audit("https://example.com/", response) == []
