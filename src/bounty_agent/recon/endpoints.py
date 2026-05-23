"""Endpoint enumeration.

Probes a configurable list of common paths under a base URL. Every
candidate goes through :class:`ScopePolicy` before any request is
issued.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urljoin

import httpx

from bounty_agent.core import ScopePolicy
from bounty_agent.logging_setup import get_logger

logger = get_logger(__name__)

_HTTP_ERROR_MIN = 400

DEFAULT_PATHS: tuple[str, ...] = (
    "/",
    "/admin",
    "/api",
    "/api/v1",
    "/login",
    "/register",
    "/search",
    "/user",
    "/profile",
    "/settings",
    "/upload",
    "/.git/config",
    "/.env",
    "/robots.txt",
    "/sitemap.xml",
)


async def enumerate_endpoints(
    client: httpx.AsyncClient,
    base_url: str,
    scope: ScopePolicy,
    paths: tuple[str, ...] = DEFAULT_PATHS,
    max_concurrent: int = 4,
) -> list[str]:
    """Return URLs whose probe returned a 2xx or 3xx status."""
    semaphore = asyncio.Semaphore(max_concurrent)

    async def probe(path: str) -> str | None:
        url = urljoin(base_url, path)
        try:
            scope.check(url)
        except Exception:  # ScopeViolation is the expected case
            return None
        async with semaphore:
            try:
                response = await client.get(url, follow_redirects=False)
            except httpx.RequestError as exc:
                logger.debug("endpoints.probe_failed", url=url, error=str(exc))
                return None
        if response.status_code < _HTTP_ERROR_MIN:
            return url
        return None

    results = await asyncio.gather(*(probe(p) for p in paths))
    return [url for url in results if url is not None]


__all__ = ["DEFAULT_PATHS", "enumerate_endpoints"]
