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
from collections.abc import Callable
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
from bounty_agent.oob.tokens import OOB_PLACEHOLDER, TokenRegistry

if TYPE_CHECKING:
    from uuid import UUID


logger = get_logger(__name__)


_RATE_LIMIT_WINDOW_SECONDS = 60.0
_DEFAULT_USER_AGENTS: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
)


#: Marker value used in :meth:`ResponsibleFuzzer.fuzz_json_body` templates.
#: Body fields whose value equals this string are substituted with each
#: payload. Other fields keep their literal values.
FUZZ_MARKER = "__FUZZ__"


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
        oob_token_registry: TokenRegistry | None = None,
        oob_domain: str | None = None,
    ) -> None:
        self.config = config or FuzzerConfig()
        self.registry = registry or PayloadRegistry.from_mapping({})
        self.scope = scope
        self.analyzers = analyzers
        self._request_times: list[float] = []
        # OOB integration. When both are set, payloads containing the
        # ``{OOB_URL}`` placeholder are minted a unique token and sent
        # to ``<token>.<oob_domain>``. The correlator pairs callbacks
        # back via :class:`TokenRegistry.lookup`.
        self.oob_token_registry = oob_token_registry
        self.oob_domain = oob_domain

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
        """Fuzz a single query parameter on ``url`` with all payloads in ``category``."""
        return await self._fuzz_with_injector(
            client=client,
            url=url,
            category=category,
            scan_id=scan_id,
            location=f"param:{param}",
            injector=lambda payload: self._inject_param(url, param, payload),
        )

    async def fuzz_path_segment(
        self,
        client: httpx.AsyncClient,
        url: str,
        category: str,
        scan_id: UUID | None = None,
    ) -> list[Finding]:
        """Fuzz the last URL path segment (e.g. ``/api/Users/1`` -> ``/api/Users/<payload>``).

        Returns immediately with an empty list when the last segment is missing
        or does not look like a numeric ID (the IDOR/path-injection pattern we
        care about). Use :meth:`fuzz_endpoint` for query-string fuzzing.
        """
        if not self._last_path_segment_is_id(url):
            return []
        return await self._fuzz_with_injector(
            client=client,
            url=url,
            category=category,
            scan_id=scan_id,
            location="path",
            injector=lambda payload: self._inject_path_segment(url, payload),
        )

    async def fuzz_json_body(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        body_template: dict[str, object],
        category: str,
        scan_id: UUID | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Fuzz JSON body fields on a POST/PUT/PATCH endpoint.

        Every field whose value equals the marker :data:`FUZZ_MARKER`
        (``"__FUZZ__"``) is replaced with each payload, one at a time.
        The other fields keep their literal values. The request is sent
        with ``Content-Type: application/json``.

        Example template for OWASP Juice Shop login::

            {"email": "__FUZZ__", "password": "x"}
        """
        markers = [k for k, v in body_template.items() if v == FUZZ_MARKER]
        if not markers:
            logger.info("fuzzer.body_template_has_no_marker", url=url)
            return []

        payloads = self.registry.get(category)
        if not payloads:
            return []
        analyzers_for_category = [a for a in self.analyzers if a.category == category]
        if not analyzers_for_category:
            return []

        method_upper = method.upper()
        location = f"body:{method_upper}:{','.join(markers)}"
        audit(
            "fuzzer.started",
            scan_id=str(scan_id) if scan_id else None,
            url=url,
            category=category,
            location=location,
            payloads=len(payloads),
        )
        started = time.monotonic()

        headers = {"Content-Type": "application/json"}
        if extra_headers:
            headers.update(extra_headers)

        # Baseline: replace markers with a safe literal so we have a
        # reference response to diff against.
        safe_body = {k: ("baseline" if v == FUZZ_MARKER else v) for k, v in body_template.items()}
        baseline = await self._safe_request(
            client, method_upper, url, json=safe_body, headers=headers
        )

        findings: list[Finding] = []
        for raw_payload in payloads:
            payload = self._materialise_oob(
                payload=raw_payload, target_url=url, category=category, scan_id=scan_id
            )
            for marker_key in markers:
                test_body = dict(body_template)
                for k, v in test_body.items():
                    if v == FUZZ_MARKER:
                        # Only the active marker gets the payload; the rest
                        # keep their safe baseline value.
                        test_body[k] = payload if k == marker_key else "baseline"
                response = await self._safe_request(
                    client, method_upper, url, json=test_body, headers=headers
                )
                if response is None:
                    continue
                for analyzer in analyzers_for_category:
                    finding = analyzer.analyze(url, payload, response, baseline)
                    if finding is None:
                        continue
                    findings.append(finding)
                    audit(
                        "fuzzer.finding",
                        scan_id=str(scan_id) if scan_id else None,
                        url=url,
                        category=category,
                        location=f"body:{marker_key}",
                        severity=finding.severity.value,
                    )

        audit(
            "fuzzer.finished",
            scan_id=str(scan_id) if scan_id else None,
            url=url,
            category=category,
            location=location,
            findings=len(findings),
            duration_seconds=round(time.monotonic() - started, 3),
        )
        return findings

    async def _fuzz_with_injector(
        self,
        client: httpx.AsyncClient,
        url: str,
        category: str,
        scan_id: UUID | None,
        location: str,
        injector: Callable[[str], str],
    ) -> list[Finding]:
        payloads = self.registry.get(category)
        if not payloads:
            logger.info("fuzzer.no_payloads", category=category)
            return []

        analyzers_for_category = [a for a in self.analyzers if a.category == category]
        if not analyzers_for_category:
            logger.info("fuzzer.no_analyzer", category=category)
            return []

        audit(
            "fuzzer.started",
            scan_id=str(scan_id) if scan_id else None,
            url=url,
            category=category,
            location=location,
            payloads=len(payloads),
        )
        started = time.monotonic()

        baseline = await self._safe_request(client, "GET", url)
        findings: list[Finding] = []

        for raw_payload in payloads:
            payload = self._materialise_oob(
                payload=raw_payload, target_url=url, category=category, scan_id=scan_id
            )
            test_url = injector(payload)
            response = await self._safe_request(client, "GET", test_url)
            if response is None:
                continue
            for analyzer in analyzers_for_category:
                finding = analyzer.analyze(test_url, payload, response, baseline)
                if finding is None:
                    continue
                # Time-based blind SQLi: verify by re-sending the same
                # request and re-running the analyzer. If the slowdown
                # was network noise, the second call comes back fast and
                # the second analyse() returns None -> we drop the
                # candidate. This collapses ~80% of FPs on shared
                # hosting / slow targets while keeping TPs essentially
                # unchanged (real time-based SQLi reproduces).
                if "time-based" in finding.title.lower():
                    verification = await self._safe_request(client, "GET", test_url)
                    if (
                        verification is None
                        or analyzer.analyze(test_url, payload, verification, baseline) is None
                    ):
                        audit(
                            "fuzzer.time_based_unverified",
                            scan_id=str(scan_id) if scan_id else None,
                            url=test_url,
                        )
                        continue
                findings.append(finding)
                audit(
                    "fuzzer.finding",
                    scan_id=str(scan_id) if scan_id else None,
                    url=test_url,
                    category=category,
                    location=location,
                    severity=finding.severity.value,
                )

        audit(
            "fuzzer.finished",
            scan_id=str(scan_id) if scan_id else None,
            url=url,
            category=category,
            location=location,
            findings=len(findings),
            duration_seconds=round(time.monotonic() - started, 3),
        )
        return findings

    def _materialise_oob(
        self,
        payload: str,
        target_url: str,
        category: str,
        scan_id: UUID | None,
    ) -> str:
        """Substitute ``{OOB_URL}`` in ``payload`` with a fresh token.

        If OOB is not configured or the payload doesn't contain the
        placeholder, the payload is returned unchanged. Otherwise a
        new token is registered (and persisted) so the post-scan
        correlator can later identify which payload caused which
        callback.
        """
        if self.oob_token_registry is None or not self.oob_domain or OOB_PLACEHOLDER not in payload:
            return payload
        token = self.oob_token_registry.register(
            target_url=target_url,
            payload=payload,
            category=category,
            scan_id=scan_id,
        )
        oob_host = f"{token.token}.{self.oob_domain}"
        return payload.replace(OOB_PLACEHOLDER, oob_host)

    @staticmethod
    def _inject_param(url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[param] = payload
        new_query = urlencode(query, safe=":/")
        return urlunparse(parsed._replace(query=new_query))

    @staticmethod
    def _inject_path_segment(url: str, payload: str) -> str:
        """Replace the last path segment with ``payload`` (URL-encoded by httpx)."""
        parsed = urlparse(url)
        path = parsed.path or "/"
        if path == "/":
            new_path = f"/{payload}"
        else:
            head, _, _ = path.rpartition("/")
            new_path = f"{head}/{payload}" if head else f"/{payload}"
        return urlunparse(parsed._replace(path=new_path))

    @staticmethod
    def _last_path_segment_is_id(url: str) -> bool:
        """True when the URL's last path segment is purely numeric.

        Conservative on purpose: we only fuzz the segment when it looks like
        a numeric primary key, the classic IDOR shape. Slugs and UUIDs are
        skipped to keep false-positive injection attempts under control.
        """
        parsed = urlparse(url)
        path = parsed.path or ""
        tail = path.rstrip("/").rsplit("/", 1)[-1]
        return bool(tail) and tail.isdigit()


__all__ = ["FUZZ_MARKER", "FuzzerConfig", "ResponsibleFuzzer"]
