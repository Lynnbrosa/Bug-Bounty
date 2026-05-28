"""Active CORS misconfiguration probe.

For each candidate URL, sends four small variants with a forged
``Origin`` header and inspects the response's
``Access-Control-Allow-Origin`` / ``Access-Control-Allow-Credentials``
pair. We flag the four classic dangerous combinations:

1. **Origin reflected verbatim + Allow-Credentials: true** -
   any attacker site can read the response with the victim's cookies.
2. **null origin accepted + Allow-Credentials: true** -
   sandboxed iframes (no-referrer redirects) can hit the API.
3. **Wildcard subdomain accepted** (e.g. ``evil.target.example``) -
   a takeover or a wildcard-cert subdomain attacker can pivot.
4. **Trailing-suffix bypass** (e.g. ``target.example.evil.com``) -
   poorly-written regex allowlists let attacker domains through.

Each call is a single GET. Findings come back tagged with the test
that found them so the operator can replay the probe by hand.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from bounty_agent.core import Finding, FindingSource, ScopePolicy, Severity
from bounty_agent.logging_setup import audit, get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class _CorsProbe:
    """One forged Origin to try."""

    name: str
    origin: str
    severity: Severity
    description: str


def _probes_for(target_host: str) -> tuple[_CorsProbe, ...]:
    """Build the canonical 4 probes for one target host."""
    return (
        _CorsProbe(
            name="reflected_origin_with_credentials",
            origin="https://attacker.example",
            severity=Severity.HIGH,
            description=(
                "Server reflects an arbitrary Origin AND sets "
                "Access-Control-Allow-Credentials: true. Any attacker-"
                "controlled origin can read this response with the "
                "victim's session cookie."
            ),
        ),
        _CorsProbe(
            name="null_origin_with_credentials",
            origin="null",
            severity=Severity.HIGH,
            description=(
                "Server accepts Origin: null with Allow-Credentials: "
                "true. Sandboxed iframes / data: URLs / redirected "
                "requests fall into this bucket and can read "
                "authenticated responses."
            ),
        ),
        _CorsProbe(
            name="wildcard_subdomain_takeover",
            origin=f"https://evil.{target_host}",
            severity=Severity.MEDIUM,
            description=(
                f"Server accepts arbitrary subdomain of {target_host}. "
                "If any subdomain is takeover-vulnerable or a wildcard "
                "cert leaks, an attacker can host content under the "
                "victim's main brand."
            ),
        ),
        _CorsProbe(
            name="suffix_bypass",
            origin=f"https://{target_host}.evil.example",
            severity=Severity.MEDIUM,
            description=(
                f"Server accepts a domain that merely starts with "
                f"{target_host}. Regex allowlists that miss the trailing "
                "dot anchor are vulnerable; the attacker registers "
                f"{target_host}.evil.example."
            ),
        ),
    )


class CorsProbeScanner:
    """Send the canonical CORS probes against each URL."""

    def __init__(
        self,
        scope: ScopePolicy | None = None,
        request_timeout_seconds: float = 10.0,
    ) -> None:
        self.scope = scope
        self.request_timeout_seconds = request_timeout_seconds

    async def scan(self, client: httpx.AsyncClient, urls: list[str]) -> list[Finding]:
        if not urls:
            return []
        audit("cors.scan_started", urls=len(urls))
        coros = [self._probe_url(client, url) for url in urls]
        results = await asyncio.gather(*coros, return_exceptions=True)
        findings: list[Finding] = []
        for outcome in results:
            if isinstance(outcome, BaseException):
                logger.info("cors.probe_failed", error=str(outcome))
                continue
            findings.extend(outcome)
        audit("cors.scan_finished", urls=len(urls), findings=len(findings))
        return findings

    async def _probe_url(self, client: httpx.AsyncClient, url: str) -> list[Finding]:
        if self.scope is not None:
            self.scope.check(url)
        parsed = urlparse(url)
        host = parsed.hostname or url
        findings: list[Finding] = []
        for probe in _probes_for(host):
            try:
                response = await client.get(
                    url,
                    headers={"Origin": probe.origin},
                    timeout=self.request_timeout_seconds,
                )
            except httpx.HTTPError as exc:
                logger.info("cors.probe_request_failed", url=url, error=str(exc))
                continue
            allow_origin = response.headers.get("access-control-allow-origin", "")
            allow_credentials = (
                response.headers.get("access-control-allow-credentials", "").lower() == "true"
            )
            if not _origin_is_accepted(probe.origin, allow_origin):
                continue
            # Credentials + reflection is the worst combo. Reflection
            # without credentials is still worth flagging but lower.
            severity = probe.severity
            if not allow_credentials and probe.name in {
                "reflected_origin_with_credentials",
                "null_origin_with_credentials",
            }:
                severity = Severity.MEDIUM
            findings.append(
                Finding(
                    url=url,  # type: ignore[arg-type]
                    source=FindingSource.MANUAL,
                    severity=severity,
                    title=f"CORS: {probe.name}",
                    description=probe.description,
                    evidence={
                        "sent_origin": probe.origin,
                        "allow_origin": allow_origin,
                        "allow_credentials": allow_credentials,
                        "status_code": response.status_code,
                        "tool": "cors-probe",
                    },
                )
            )
        return findings


def _origin_is_accepted(sent: str, returned: str) -> bool:
    """True when the server's ACAO reflects the attacker-controlled origin."""
    if not returned:
        return False
    if returned == sent:
        return True
    # Some servers echo with a trailing slash or normalise case.
    if returned.lower() == sent.lower():
        return True
    return False


__all__ = ["CorsProbeScanner"]
