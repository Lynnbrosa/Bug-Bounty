"""Tests for HttpsEnforcementChecker + Soft404Detector + SecurityHeadersAuditor."""

from __future__ import annotations

import httpx
import respx

from bounty_agent.core import Severity
from bounty_agent.scanners.headers import SecurityHeadersAuditor
from bounty_agent.scanners.transport import HttpsEnforcementChecker, Soft404Detector


def _response_with(headers: dict[str, str]) -> httpx.Response:
    request = httpx.Request("GET", "https://example.com/")
    return httpx.Response(200, request=request, headers=headers)


class TestSecurityHeadersAuditor:
    def test_all_headers_missing_emits_5_findings(self) -> None:
        auditor = SecurityHeadersAuditor()
        response = _response_with({})
        findings = auditor.audit("https://example.com/", response)
        assert len(findings) == 5  # HSTS + XFO + nosniff + referrer + permissions
        titles = {f.title for f in findings}
        assert any("HSTS" in t for t in titles)
        assert any("X-Frame-Options" in t for t in titles)
        assert any("X-Content-Type-Options" in t for t in titles)
        assert any("Referrer-Policy" in t for t in titles)
        assert any("Permissions-Policy" in t for t in titles)

    def test_all_headers_present_no_findings(self) -> None:
        auditor = SecurityHeadersAuditor()
        response = _response_with(
            {
                "strict-transport-security": "max-age=31536000",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "camera=()",
            }
        )
        findings = auditor.audit("https://example.com/", response)
        assert findings == []

    def test_hsts_not_required_on_http(self) -> None:
        auditor = SecurityHeadersAuditor()
        response = _response_with({})
        findings = auditor.audit("http://example.com/", response)
        # HSTS only meaningful on HTTPS; the other 4 should still fire.
        assert len(findings) == 4
        assert all("HSTS" not in f.title for f in findings)

    def test_finding_severity_low(self) -> None:
        auditor = SecurityHeadersAuditor()
        response = _response_with({})
        findings = auditor.audit("https://example.com/", response)
        assert all(f.severity == Severity.LOW for f in findings)


class TestHttpsEnforcement:
    async def test_http_200_flagged_as_medium(self, respx_mock: respx.MockRouter) -> None:
        respx_mock.get("http://example.com/").mock(
            return_value=httpx.Response(200, text="welcome over http")
        )
        checker = HttpsEnforcementChecker(request_timeout_seconds=2.0)
        async with httpx.AsyncClient() as client:
            finding = await checker.check(client, "https://example.com/")
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert "not redirected to HTTPS" in finding.title

    async def test_http_redirects_to_https_no_finding(self, respx_mock: respx.MockRouter) -> None:
        respx_mock.get("http://example.com/").mock(
            return_value=httpx.Response(301, headers={"Location": "https://example.com/"})
        )
        checker = HttpsEnforcementChecker(request_timeout_seconds=2.0)
        async with httpx.AsyncClient() as client:
            finding = await checker.check(client, "https://example.com/")
        assert finding is None

    async def test_http_redirects_elsewhere_flagged(self, respx_mock: respx.MockRouter) -> None:
        respx_mock.get("http://example.com/").mock(
            return_value=httpx.Response(302, headers={"Location": "http://elsewhere.example/"})
        )
        checker = HttpsEnforcementChecker(request_timeout_seconds=2.0)
        async with httpx.AsyncClient() as client:
            finding = await checker.check(client, "https://example.com/")
        assert finding is not None
        assert "somewhere other than HTTPS" in finding.title


class TestSoft404Detector:
    async def test_universal_200_with_same_body_is_soft_404(
        self, respx_mock: respx.MockRouter
    ) -> None:
        # Mock catches any GET on this host with the homepage body.
        respx_mock.get(url__startswith="https://example.com/__bountyagent_random_").mock(
            return_value=httpx.Response(200, text="<html>welcome to example, our content</html>")
        )
        detector = Soft404Detector(request_timeout_seconds=2.0)
        async with httpx.AsyncClient() as client:
            finding = await detector.check(client, "https://example.com/")
        assert finding is not None
        assert "Soft 404" in finding.title
        assert finding.evidence["body_similarity"] >= 0.85

    async def test_real_404_no_finding(self, respx_mock: respx.MockRouter) -> None:
        respx_mock.get(url__startswith="https://example.com/__bountyagent_random_").mock(
            return_value=httpx.Response(404, text="not found")
        )
        detector = Soft404Detector(request_timeout_seconds=2.0)
        async with httpx.AsyncClient() as client:
            finding = await detector.check(client, "https://example.com/")
        assert finding is None
