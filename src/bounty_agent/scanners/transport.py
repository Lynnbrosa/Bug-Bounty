"""Transport-layer + 404-shape detectors.

Two cheap checks that have to leave the agent's normal HTTPS-only
request flow, so they live outside :class:`SensitivePathScanner` /
:class:`CookieSecurityAuditor`:

* :class:`HttpsEnforcementChecker` — hits the target on plain
  ``http://`` and confirms the server returns a 3xx pointing to
  ``https://``. Apps that answer 200 OK on HTTP let SSL-stripping
  MITM attacks succeed; that's a Medium finding even with HSTS
  configured (HSTS only works after the first HTTPS visit).
* :class:`Soft404Detector` — sends a randomly-named path that
  cannot legitimately exist (``/__bountyagent_random_<token>__``)
  and checks whether the server returned anything other than a real
  4xx. Sites that respond ``200 OK`` with the homepage body to
  unknown paths defeat most signature-based scanners; the operator
  needs to know.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlparse, urlunparse

import httpx

from bounty_agent.core import Finding, FindingSource, ScopePolicy, Severity
from bounty_agent.logging_setup import audit, get_logger

logger = get_logger(__name__)


_HTTP_REDIRECT_MIN = 300
_HTTP_REDIRECT_MAX = 400
_SOFT_404_BODY_SIMILARITY_THRESHOLD = 0.85  # 85% identical -> looks soft 404


class HttpsEnforcementChecker:
    """Confirm the host redirects plain HTTP to HTTPS."""

    def __init__(
        self,
        scope: ScopePolicy | None = None,
        request_timeout_seconds: float = 5.0,
    ) -> None:
        self.scope = scope
        self.request_timeout_seconds = request_timeout_seconds

    async def check(  # noqa: PLR0911 - branchy by intent, each return is a distinct outcome
        self, client: httpx.AsyncClient, https_url: str
    ) -> Finding | None:
        """Return a Finding when HTTP is served instead of redirected."""
        http_url = _force_http(https_url)
        if http_url is None:
            return None
        if self.scope is not None:
            try:
                self.scope.check(http_url)
            except Exception:
                return None
        try:
            response = await client.get(
                http_url,
                timeout=self.request_timeout_seconds,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            logger.info("transport.http_probe_failed", url=http_url, error=str(exc))
            return None
        if _HTTP_REDIRECT_MIN <= response.status_code < _HTTP_REDIRECT_MAX:
            location = response.headers.get("location", "")
            if location.lower().startswith("https://"):
                # Healthy: HTTP -> HTTPS redirect.
                return None
            # 3xx but NOT to https. Worth flagging — could be an open
            # redirect or a misconfigured rewrite.
            audit(
                "transport.http_redirect_not_https",
                url=http_url,
                location=location[:200],
            )
            return Finding(
                url=http_url,  # type: ignore[arg-type]
                source=FindingSource.MANUAL,
                severity=Severity.MEDIUM,
                title="HTTP redirects somewhere other than HTTPS",
                description=(
                    "The server returned a 3xx response on plain HTTP, but "
                    "the Location does not point at HTTPS. Either the "
                    "redirect is broken (no HTTPS upgrade) or it leaks to "
                    "an external host. Both are reportable."
                ),
                evidence={
                    "status_code": response.status_code,
                    "location": location[:200],
                    "tool": "https-enforcement",
                },
            )
        if response.status_code < _HTTP_REDIRECT_MAX:
            # 2xx on HTTP: the site is happy to serve content over an
            # insecure channel. SSL-stripping MITM works trivially.
            audit("transport.http_served_200", url=http_url, status=response.status_code)
            return Finding(
                url=http_url,  # type: ignore[arg-type]
                source=FindingSource.MANUAL,
                severity=Severity.MEDIUM,
                title="HTTP not redirected to HTTPS",
                description=(
                    "The server answers the same content on plain HTTP as "
                    "on HTTPS, without redirecting. A network attacker can "
                    "downgrade the first connection to HTTP via SSL "
                    "stripping; HSTS does not help on the very first "
                    "visit. Configure the server to issue a 301/308 to the "
                    "HTTPS equivalent."
                ),
                evidence={
                    "http_status": response.status_code,
                    "https_url": https_url,
                    "tool": "https-enforcement",
                },
            )
        # 4xx/5xx on HTTP -> the server refuses plain HTTP. Healthy.
        return None


def _force_http(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None
    return urlunparse(parsed._replace(scheme="http"))


class Soft404Detector:
    """Detect targets that return identical content for any unknown path.

    Three probe URLs (random tokens) are sent. If all three return the
    same status (typically 200) and the body is highly similar across
    the three, the site has soft-404 semantics: every signature-based
    scanner gets nullified because there is no shape difference between
    "exists" and "does not exist".
    """

    def __init__(
        self,
        scope: ScopePolicy | None = None,
        request_timeout_seconds: float = 5.0,
        similarity_threshold: float = _SOFT_404_BODY_SIMILARITY_THRESHOLD,
    ) -> None:
        self.scope = scope
        self.request_timeout_seconds = request_timeout_seconds
        self.similarity_threshold = similarity_threshold

    async def check(  # noqa: PLR0911 - branchy by intent, each return is a distinct outcome
        self, client: httpx.AsyncClient, base_url: str
    ) -> Finding | None:
        parsed = urlparse(base_url)
        if not parsed.scheme:
            return None
        if self.scope is not None:
            try:
                self.scope.check(base_url)
            except Exception:
                return None
        probes = [
            urlunparse(
                parsed._replace(
                    path=f"/__bountyagent_random_{secrets.token_urlsafe(8)}__",
                    query="",
                    fragment="",
                )
            )
            for _ in range(3)
        ]
        bodies: list[str] = []
        statuses: list[int] = []
        for probe in probes:
            try:
                response = await client.get(
                    probe,
                    timeout=self.request_timeout_seconds,
                    follow_redirects=True,
                )
            except httpx.HTTPError as exc:
                logger.info("transport.soft404_probe_failed", url=probe, error=str(exc))
                continue
            bodies.append(response.text or "")
            statuses.append(response.status_code)
        if len(bodies) < 3:  # noqa: PLR2004 - need all 3 probes
            return None
        # Healthy: every probe should be 404. If the server returns 2xx
        # on a random nonexistent path, that is soft-404.
        if all(400 <= s < 500 for s in statuses):  # noqa: PLR2004 - 4xx range
            return None
        if not all(s < 500 for s in statuses):  # noqa: PLR2004 - 5xx -> unrelated
            return None
        # Compare body similarity pairwise; we need all three to agree.
        sims = (
            _similarity(bodies[0], bodies[1]),
            _similarity(bodies[0], bodies[2]),
            _similarity(bodies[1], bodies[2]),
        )
        if min(sims) < self.similarity_threshold:
            return None
        audit(
            "transport.soft_404_detected",
            base=base_url,
            statuses=statuses,
            similarity=round(min(sims), 3),
        )
        return Finding(
            url=base_url,  # type: ignore[arg-type]
            source=FindingSource.MANUAL,
            severity=Severity.LOW,
            title="Soft 404: unknown paths return the homepage with 200",
            description=(
                "Three randomly-named paths that cannot exist all returned "
                "non-4xx responses with near-identical bodies. The server "
                "is misconfigured to serve the same page (typically the "
                "homepage) for every unknown URL. This breaks signature "
                "scanners, hides admin endpoints that exist but return "
                "non-default content, and is generally bad SEO. Fix the "
                "router to return real 404s for unknown paths."
            ),
            evidence={
                "probe_statuses": statuses,
                "body_similarity": round(min(sims), 3),
                "threshold": self.similarity_threshold,
                "tool": "soft-404",
            },
        )


def _similarity(a: str, b: str) -> float:
    """Length-normalised Jaccard-ish similarity over body byte trigrams.

    Cheap, no third-party deps. Two identical bodies -> 1.0; two
    completely different bodies -> ~0.0. Trigrams over bytes
    capture both layout and content overlap.
    """
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    n = 3
    set_a = {a[i : i + n] for i in range(len(a) - n + 1)}
    set_b = {b[i : i + n] for i in range(len(b) - n + 1)}
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union else 0.0


__all__ = ["HttpsEnforcementChecker", "Soft404Detector"]
