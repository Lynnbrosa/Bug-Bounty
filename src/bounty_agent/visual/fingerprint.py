"""Per-endpoint content fingerprinting.

The fingerprint is a tuple of:

* ``status_code`` — outer behaviour
* ``content_type``
* ``content_length`` (post-normalisation)
* ``structural_hash`` — sha256 over a normalised body where session
  IDs, CSRF tokens, timestamps and other obvious dynamic noise are
  redacted. Two scans of the same page should produce the same
  ``structural_hash`` if no real change happened.
* ``title`` and ``meta_generator`` extracted from the HTML head when
  the content-type permits.

A future iteration plugs in playwright to also produce a real PNG
screenshot per endpoint; today's implementation is what a visual
diff would compare under the hood. The JSON shape is stable so the
screenshot extension can be additive.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import asdict, dataclass, field

import httpx

from bounty_agent.logging_setup import audit, get_logger

logger = get_logger(__name__)


# Patterns that get blanked out before hashing so the fingerprint is
# stable across reloads of the same page.
_NOISE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # CSRF/anti-forgery tokens
    re.compile(r'(name="(csrf|_token|authenticity_token)"\s+value=")[^"]+"'),
    # Random nonces inside style/script attrs
    re.compile(r'(nonce=")[^"]+"'),
    # Timestamps in ISO format
    re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})"),
    # Session-like hex/base64 chunks
    re.compile(r"[0-9a-f]{32,}", re.IGNORECASE),
    re.compile(r"[A-Za-z0-9+/=]{40,}"),
)


@dataclass(frozen=True)
class EndpointFingerprint:
    """One endpoint's normalised view."""

    url: str
    status_code: int
    content_type: str
    content_length: int
    structural_hash: str
    title: str = ""
    meta_generator: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class FingerprintSet:
    """All endpoint fingerprints from one scan, indexed by URL."""

    target: str
    fingerprints: dict[str, EndpointFingerprint] = field(default_factory=dict)

    def diff(self, previous: FingerprintSet | None) -> dict[str, list[str]]:
        """Return added/removed/changed URLs vs a previous fingerprint set."""
        if previous is None:
            return {
                "added": list(self.fingerprints.keys()),
                "removed": [],
                "changed": [],
            }
        prev_urls = set(previous.fingerprints.keys())
        curr_urls = set(self.fingerprints.keys())
        added = sorted(curr_urls - prev_urls)
        removed = sorted(prev_urls - curr_urls)
        changed: list[str] = []
        for url in sorted(prev_urls & curr_urls):
            if previous.fingerprints[url].structural_hash != self.fingerprints[url].structural_hash:
                changed.append(url)
        return {"added": added, "removed": removed, "changed": changed}


def fingerprint_response(url: str, response: httpx.Response) -> EndpointFingerprint:
    """Build a fingerprint from a single httpx response."""
    body = response.text or ""
    normalised = _normalise_body(body)
    structural_hash = hashlib.sha256(normalised.encode("utf-8")).hexdigest()[:32]
    return EndpointFingerprint(
        url=url,
        status_code=response.status_code,
        content_type=(response.headers.get("content-type") or "").split(";")[0].strip(),
        content_length=len(normalised),
        structural_hash=structural_hash,
        title=_extract_title(body),
        meta_generator=_extract_meta_generator(body),
    )


async def fingerprint_endpoints(
    target: str,
    urls: list[str],
    request_timeout_seconds: float = 10.0,
) -> FingerprintSet:
    """GET each URL once, return a FingerprintSet."""
    fingerprints: dict[str, EndpointFingerprint] = {}
    audit("visual.fingerprint_started", target=target, urls=len(urls))
    async with httpx.AsyncClient(timeout=request_timeout_seconds, follow_redirects=True) as client:
        coros = [_fingerprint_one(client, url) for url in urls]
        results = await asyncio.gather(*coros, return_exceptions=True)
    for url, outcome in zip(urls, results, strict=True):
        if isinstance(outcome, BaseException):
            logger.info("visual.fingerprint_failed", url=url, error=str(outcome))
            continue
        fingerprints[url] = outcome
    audit(
        "visual.fingerprint_done",
        target=target,
        urls=len(urls),
        captured=len(fingerprints),
    )
    return FingerprintSet(target=target, fingerprints=fingerprints)


async def _fingerprint_one(client: httpx.AsyncClient, url: str) -> EndpointFingerprint:
    response = await client.get(url)
    return fingerprint_response(url, response)


def _normalise_body(body: str) -> str:
    """Strip dynamic noise so the hash is stable across reloads."""
    for pattern in _NOISE_PATTERNS:
        body = pattern.sub("REDACTED", body)
    # Collapse whitespace so spurious indentation changes don't shift
    # the hash.
    return re.sub(r"\s+", " ", body)


_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,200})</title>", re.IGNORECASE)
_META_GEN_RE = re.compile(
    r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']{1,200})["\']',
    re.IGNORECASE,
)


def _extract_title(body: str) -> str:
    match = _TITLE_RE.search(body)
    return match.group(1).strip() if match else ""


def _extract_meta_generator(body: str) -> str:
    match = _META_GEN_RE.search(body)
    return match.group(1).strip() if match else ""


__all__ = [
    "EndpointFingerprint",
    "FingerprintSet",
    "fingerprint_endpoints",
    "fingerprint_response",
]
