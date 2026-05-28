"""Header-based passive audit: cookie security + CSP weaknesses.

Two checks that run with a single GET per endpoint (no payload):

* :class:`CookieSecurityAuditor` parses every ``Set-Cookie`` and
  flags cookies that look session-shaped (``session``, ``auth``,
  ``token``, ``jwt`` or 32+ chars of opaque value) but lack
  ``Secure``, ``HttpOnly`` or ``SameSite``.
* :class:`CspAuditor` parses ``Content-Security-Policy`` and flags
  the unsafe sinks that get accepted in triage: ``unsafe-inline``
  on ``script-src``, wildcards on ``default-src`` / ``connect-src``,
  missing ``frame-ancestors``, missing ``object-src``.

Both audits are passive: only a GET, no state change, no fuzzing.
Findings come back as :class:`Finding` instances ready to be merged
into :class:`ScanResult`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx

from bounty_agent.core import Finding, FindingSource, ScopePolicy, Severity
from bounty_agent.logging_setup import audit, get_logger

logger = get_logger(__name__)


_SESSION_NAME_RE = re.compile(
    r"^(session|sessid|jsessionid|phpsessid|auth|access[_-]?token|"
    r"refresh[_-]?token|jwt|id[_-]?token|bearer|csrf[_-]?token)$",
    re.IGNORECASE,
)
_OPAQUE_VALUE_RE = re.compile(r"^[A-Za-z0-9+/=._-]{32,}$")


def _looks_like_session_cookie(name: str, value: str) -> bool:
    return bool(_SESSION_NAME_RE.match(name)) or bool(_OPAQUE_VALUE_RE.match(value))


@dataclass(frozen=True)
class _CookieAttributes:
    """Parsed flags + value for one Set-Cookie line."""

    name: str
    value: str
    has_secure: bool
    has_http_only: bool
    same_site: str  # "", "lax", "strict", "none"


def _parse_set_cookie(raw: str) -> _CookieAttributes | None:
    """Parse a single ``Set-Cookie`` header value."""
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts:
        return None
    if "=" not in parts[0]:
        return None
    name, _, value = parts[0].partition("=")
    name = name.strip()
    value = value.strip().strip('"')
    if not name:
        return None
    attrs_lower = [p.lower() for p in parts[1:]]
    has_secure = "secure" in attrs_lower
    has_http_only = "httponly" in attrs_lower
    same_site = ""
    for attr in attrs_lower:
        if attr.startswith("samesite="):
            same_site = attr.split("=", 1)[1]
            break
    return _CookieAttributes(
        name=name,
        value=value,
        has_secure=has_secure,
        has_http_only=has_http_only,
        same_site=same_site,
    )


class CookieSecurityAuditor:
    """Inspect every Set-Cookie on a response and flag misconfigurations."""

    def __init__(self, scope: ScopePolicy | None = None) -> None:
        self.scope = scope

    def audit(self, url: str, response: httpx.Response) -> list[Finding]:
        # httpx exposes all Set-Cookie values via .get_list (case-
        # insensitive). Falls back to ``headers.get_list`` for old
        # versions.
        raws: list[str] = []
        if hasattr(response.headers, "get_list"):
            raws = response.headers.get_list("set-cookie")
        else:  # pragma: no cover - fallback
            single = response.headers.get("set-cookie")
            if single:
                raws = [single]
        if not raws:
            return []
        findings: list[Finding] = []
        for raw in raws:
            attrs = _parse_set_cookie(raw)
            if attrs is None:
                continue
            if not _looks_like_session_cookie(attrs.name, attrs.value):
                # Tracking-only cookies (utm, _ga, etc.) are noisy;
                # skip so the report stays focused.
                continue
            missing: list[str] = []
            if not attrs.has_secure and url.startswith("https://"):
                missing.append("Secure")
            if not attrs.has_http_only:
                missing.append("HttpOnly")
            if attrs.same_site == "":
                missing.append("SameSite")
            if not missing:
                continue
            findings.append(
                Finding(
                    url=url,  # type: ignore[arg-type]
                    source=FindingSource.MANUAL,
                    severity=Severity.MEDIUM if "HttpOnly" in missing else Severity.LOW,
                    title=(f"Session cookie '{attrs.name}' missing " + ", ".join(missing)),
                    description=(
                        "The Set-Cookie response header for a session-shaped "
                        "cookie omits one or more security attributes. Without "
                        "HttpOnly the cookie is reachable from JavaScript "
                        "(XSS amplification). Without Secure it can leak over "
                        "plain HTTP. Without SameSite it is sent on cross-site "
                        "requests (CSRF amplification)."
                    ),
                    evidence={
                        "cookie_name": attrs.name,
                        "missing_attributes": missing,
                        "raw_header_excerpt": raw[:200],
                        "tool": "cookie-audit",
                    },
                )
            )
        if findings:
            audit("headers.cookie_findings", url=url, count=len(findings))
        return findings


_CSP_UNSAFE_TOKENS = ("'unsafe-inline'", "'unsafe-eval'")


# Five security headers that almost every bug bounty program expects
# on every HTTPS response. Missing ones land as LOW findings.
_REQUIRED_HEADERS: tuple[tuple[str, str, str], ...] = (
    (
        "strict-transport-security",
        "HSTS header missing (Strict-Transport-Security)",
        "The response lacks Strict-Transport-Security. A network attacker can "
        "downgrade subsequent connections to HTTP and intercept traffic via "
        "SSL stripping. Add `Strict-Transport-Security: max-age=31536000; "
        "includeSubDomains` once the operator confirms every subdomain is "
        "HTTPS-only.",
    ),
    (
        "x-frame-options",
        "X-Frame-Options header missing",
        "Without X-Frame-Options (or a CSP frame-ancestors directive) the "
        "page can be embedded in a hostile iframe (clickjacking).",
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options header missing",
        "Without `X-Content-Type-Options: nosniff` browsers may MIME-sniff "
        "responses and execute attacker-controlled bytes in unexpected "
        "contexts (e.g. user-uploaded images interpreted as scripts).",
    ),
    (
        "referrer-policy",
        "Referrer-Policy header missing",
        "Without a Referrer-Policy the browser sends the full URL (including "
        "query string) to third-party origins. Common leak surface for "
        "tokens, session ids and UTM-encoded PII.",
    ),
    (
        "permissions-policy",
        "Permissions-Policy header missing",
        "Without Permissions-Policy (or the legacy Feature-Policy) the page "
        "inherits the browser default for sensitive APIs (camera, "
        "microphone, geolocation, payment, USB). Restrict explicitly.",
    ),
)


class SecurityHeadersAuditor:
    """Flag responses missing the canonical security headers.

    Runs alongside :class:`CspAuditor` (which already covers CSP). The
    orchestrator dedupes per (host, finding-title) so a site with no
    HSTS reports the gap once for the whole host, not once per URL.
    """

    def audit(self, url: str, response: httpx.Response) -> list[Finding]:
        # Only HTTPS responses are expected to carry HSTS; the other
        # four apply regardless of scheme.
        is_https = url.startswith("https://")
        findings: list[Finding] = []
        for header_name, title, description in _REQUIRED_HEADERS:
            if header_name == "strict-transport-security" and not is_https:
                continue
            if response.headers.get(header_name):
                continue
            findings.append(
                Finding(
                    url=url,  # type: ignore[arg-type]
                    source=FindingSource.MANUAL,
                    severity=Severity.LOW,
                    title=title,
                    description=description,
                    evidence={
                        "header": header_name,
                        "tool": "security-headers",
                    },
                )
            )
        if findings:
            audit(
                "headers.security_headers_findings",
                url=url,
                count=len(findings),
            )
        return findings


class CspAuditor:
    """Parse Content-Security-Policy and flag the usual unsafe sinks."""

    def audit(self, url: str, response: httpx.Response) -> list[Finding]:
        csp = response.headers.get("content-security-policy", "").strip()
        if not csp:
            return [
                Finding(
                    url=url,  # type: ignore[arg-type]
                    source=FindingSource.MANUAL,
                    severity=Severity.LOW,
                    title="Content-Security-Policy header missing",
                    description=(
                        "The response did not include a Content-Security-Policy "
                        "header. Without CSP, any reflected or stored XSS "
                        "executes with no defense-in-depth restriction."
                    ),
                    evidence={"tool": "csp-audit"},
                )
            ]
        directives = _parse_csp(csp)
        findings: list[Finding] = []
        # script-src must not allow 'unsafe-inline' / 'unsafe-eval'.
        script_src = directives.get("script-src") or directives.get("default-src") or []
        unsafe = [t for t in _CSP_UNSAFE_TOKENS if t in script_src]
        if unsafe:
            findings.append(
                Finding(
                    url=url,  # type: ignore[arg-type]
                    source=FindingSource.MANUAL,
                    severity=Severity.MEDIUM,
                    title=f"CSP allows {' + '.join(unsafe)} on script-src",
                    description=(
                        "script-src includes a token that disables CSP's main "
                        "XSS protection. Migrate to a nonce-based or hash-based "
                        "script-src so the browser only executes scripts the "
                        "server vouches for."
                    ),
                    evidence={
                        "policy_excerpt": csp[:300],
                        "unsafe_tokens": unsafe,
                        "tool": "csp-audit",
                    },
                )
            )
        # Wildcards on default-src or connect-src.
        for directive in ("default-src", "connect-src"):
            values = directives.get(directive, [])
            if "*" in values or "http:" in values or "https:" in values:
                findings.append(
                    Finding(
                        url=url,  # type: ignore[arg-type]
                        source=FindingSource.MANUAL,
                        severity=Severity.LOW,
                        title=f"CSP {directive} uses a wildcard source",
                        description=(
                            f"{directive} allows requests to any host. "
                            "Restrict to the specific origins the page "
                            "actually contacts."
                        ),
                        evidence={
                            "policy_excerpt": csp[:300],
                            "directive": directive,
                            "tool": "csp-audit",
                        },
                    )
                )
        # frame-ancestors missing -> clickjacking still possible.
        if "frame-ancestors" not in directives:
            findings.append(
                Finding(
                    url=url,  # type: ignore[arg-type]
                    source=FindingSource.MANUAL,
                    severity=Severity.MEDIUM,
                    title="CSP missing frame-ancestors directive",
                    description=(
                        "Without frame-ancestors, the page can be embedded "
                        "in a third-party iframe (clickjacking). Add "
                        "`frame-ancestors 'none'` or restrict to your own "
                        "origins."
                    ),
                    evidence={"policy_excerpt": csp[:300], "tool": "csp-audit"},
                )
            )
        # object-src missing -> legacy plugins / SVG XSS surface.
        if "object-src" not in directives and "default-src" not in directives:
            findings.append(
                Finding(
                    url=url,  # type: ignore[arg-type]
                    source=FindingSource.MANUAL,
                    severity=Severity.LOW,
                    title="CSP missing object-src directive",
                    description=(
                        "object-src not set; browser will fall back to "
                        "default-src or allow all. Add `object-src 'none'` "
                        "to block legacy <object>/<embed>-based XSS."
                    ),
                    evidence={"policy_excerpt": csp[:300], "tool": "csp-audit"},
                )
            )
        if findings:
            audit("headers.csp_findings", url=url, count=len(findings))
        return findings


def _parse_csp(value: str) -> dict[str, list[str]]:
    """Return {directive: [source, ...]} from a single CSP header value."""
    parsed: dict[str, list[str]] = {}
    for raw in value.split(";"):
        chunk = raw.strip()
        if not chunk:
            continue
        head, _, rest = chunk.partition(" ")
        directive = head.strip().lower()
        sources = [s.strip() for s in rest.split() if s.strip()]
        parsed[directive] = sources
    return parsed


__all__ = ["CookieSecurityAuditor", "CspAuditor", "SecurityHeadersAuditor"]
