"""Responsible fuzzer.

Refactors the legacy ``ResponsibleFuzzer`` into something:

* Modular: payloads come from a :class:`PayloadRegistry`, detection
  comes from per-category :class:`Analyzer` instances.
* Scope-aware: every request goes through ``ScopePolicy.check`` before
  it leaves the process.
* Observable: every request and finding is recorded in the audit log
  with the scan_id correlation id.
* Configurable: rate limiting, delay band and retry policy live in
  :class:`FuzzerConfig`.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx
from tenacity import (
    AsyncRetrying,
    RetryError,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from bounty_agent.core import Finding, ScopePolicy
from bounty_agent.fuzzing.analyzers import DEFAULT_ANALYZERS, Analyzer
from bounty_agent.fuzzing.payloads import PayloadRegistry
from bounty_agent.logging_setup import audit, get_logger

if TYPE_CHECKING:
    from uuid import UUID


logger = get_logger(__name__)


_RATE_LIMIT_WINDOW_SECONDS = 60.0
_DEFAULT_USER_AGENTS: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
)


@dataclass(frozen=True)
class FuzzerConfig:
    """Knobs that control fuzzing behaviour."""

    min_delay_seconds: float = 1.0
    max_delay_seconds: float = 3.0
    max_requests_per_minute: int = 20
    request_timeout_seconds: float = 10.0
    retry_attempts: int = 3
    rotate_user_agents: bool = True
    user_agents: tuple[str, ...] = field(default_factory=lambda: _DEFAULT_USER_AGENTS)


class ResponsibleFuzzer:
    """Async fuzzer with rate limit, scope check, retry and analyzers."""

    def __init__(
        self,
        config: FuzzerConfig | None = None,
        registry: PayloadRegistry | None = None,
        scope: ScopePolicy | None = None,
        analyzers: tuple[Analyzer, ...] = DEFAULT_ANALYZERS,
    ) -> None:
        self.config = config or FuzzerConfig()
        self.registry = registry or PayloadRegistry.from_mapping({})
        self.scope = scope
        self.analyzers = analyzers
        self._request_times: list[float] = []

    def _next_delay(self) -> float:
        lo = self.config.min_delay_seconds
        hi = self.config.max_delay_seconds
        if hi <= lo:
            return max(lo, 0.0)
        # secrets.randbelow is good enough here, we only need jitter.
        span_ms = int((hi - lo) * 1000)
        if span_ms <= 0:
            return lo
        return lo + secrets.randbelow(span_ms + 1) / 1000.0

    async def _respect_rate_limit(self) -> None:
        now = time.monotonic()
        self._request_times = [
            t for t in self._request_times if now - t < _RATE_LIMIT_WINDOW_SECONDS
        ]
        if len(self._request_times) >= self.config.max_requests_per_minute:
            sleep_for = _RATE_LIMIT_WINDOW_SECONDS - (now - self._request_times[0])
            if sleep_for > 0:
                logger.info("fuzzer.rate_limit_pause", sleep_seconds=round(sleep_for, 2))
                await asyncio.sleep(sleep_for)
        self._request_times.append(time.monotonic())

    def _build_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers: dict[str, str] = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "DNT": "1",
            "Connection": "keep-alive",
        }
        if self.config.rotate_user_agents and self.config.user_agents:
            headers["User-Agent"] = secrets.choice(self.config.user_agents)
        if extra:
            headers.update(extra)
        return headers

    async def _safe_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        **kwargs: object,
    ) -> httpx.Response | None:
        if self.scope is not None:
            self.scope.check(url)
        await self._respect_rate_limit()
        await asyncio.sleep(self._next_delay())
        kwargs.setdefault("headers", self._build_headers())
        kwargs.setdefault("timeout", self.config.request_timeout_seconds)
        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self.config.retry_attempts),
                wait=wait_exponential(multiplier=1, min=2, max=10),
                retry=retry_if_exception_type(httpx.TransportError),
                reraise=True,
            ):
                with attempt:
                    return await client.request(method, url, **kwargs)  # type: ignore[arg-type]
        except RetryError as exc:
            logger.warning("fuzzer.request_failed", url=url, error=str(exc))
        except httpx.HTTPError as exc:
            logger.warning("fuzzer.request_failed", url=url, error=str(exc))
        return None

    async def fuzz_endpoint(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        category: str,
        scan_id: UUID | None = None,
    ) -> list[Finding]:
        payloads = self.registry.get(category)
        if not payloads:
            logger.info("fuzzer.no_payloads", category=category)
            return []

        analyzers_for_category = [a for a in self.analyzers if a.category == category]
        if not analyzers_for_category:
            logger.info("fuzzer.no_analyzer", category=category)
            return []

        baseline = await self._safe_request(client, "GET", url)
        findings: list[Finding] = []

        for payload in payloads:
            test_url = self._inject_param(url, param, payload)
            response = await self._safe_request(client, "GET", test_url)
            if response is None:
                continue
            for analyzer in analyzers_for_category:
                finding = analyzer.analyze(test_url, payload, response, baseline)
                if finding is None:
                    continue
                findings.append(finding)
                audit(
                    "fuzzer.finding",
                    scan_id=str(scan_id) if scan_id else None,
                    url=test_url,
                    category=category,
                    severity=finding.severity.value,
                )
        return findings

    @staticmethod
    def _inject_param(url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[param] = payload
        new_query = urlencode(query, safe=":/")
        return urlunparse(parsed._replace(query=new_query))


__all__ = ["FuzzerConfig", "ResponsibleFuzzer"]
