"""Application stack fingerprinting.

Inspired by the snippet in EXEMPLOS_AVANCADOS.md, but implemented as a
synchronous response inspector plus an async fetch helper so it can be
tested without the network.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from bounty_agent.core import ScopePolicy
from bounty_agent.logging_setup import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class StackSignature:
    name: str
    body_markers: tuple[str, ...] = ()
    header_names: tuple[str, ...] = ()


DEFAULT_STACKS: tuple[StackSignature, ...] = (
    StackSignature(
        name="Django",
        body_markers=("csrfmiddlewaretoken", "django-admin"),
        header_names=("x-frame-options",),
    ),
    StackSignature(
        name="Laravel",
        body_markers=("xsrf-token", "laravel_session"),
    ),
    StackSignature(
        name="Flask",
        body_markers=("werkzeug",),
        header_names=("server",),
    ),
    StackSignature(
        name="Spring",
        body_markers=("jsessionid",),
        header_names=("x-application-context",),
    ),
    StackSignature(
        name="ASP.NET",
        body_markers=("__viewstate", "asp.net"),
        header_names=("x-aspnet-version", "x-powered-by"),
    ),
    StackSignature(
        name="Node.js/Express",
        body_markers=(),
        header_names=("x-powered-by",),
    ),
    StackSignature(
        name="WordPress",
        body_markers=("wp-content", "wp-includes"),
    ),
)


def detect_stack_from_response(
    response: httpx.Response,
    signatures: tuple[StackSignature, ...] = DEFAULT_STACKS,
) -> list[str]:
    body = _safe_text(response).lower()
    headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
    matches: list[str] = []
    for sig in signatures:
        if any(marker.lower() in body for marker in sig.body_markers):
            matches.append(sig.name)
            continue
        for header in sig.header_names:
            value = headers_lower.get(header.lower())
            if value and sig.name.lower() in value:
                matches.append(sig.name)
                break
    return matches


async def detect_stack_async(
    client: httpx.AsyncClient,
    url: str,
    scope: ScopePolicy | None = None,
) -> list[str]:
    if scope is not None:
        scope.check(url)
    try:
        response = await client.get(url, follow_redirects=True)
    except httpx.RequestError as exc:
        logger.warning("fingerprint.fetch_failed", url=url, error=str(exc))
        return []
    return detect_stack_from_response(response)


def _safe_text(response: httpx.Response) -> str:
    try:
        return response.text
    except UnicodeDecodeError:
        return ""


__all__ = [
    "DEFAULT_STACKS",
    "StackSignature",
    "detect_stack_async",
    "detect_stack_from_response",
]
