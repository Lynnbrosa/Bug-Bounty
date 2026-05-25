"""High level orchestrator.

Ties together scope, WAF detection, fuzzing and Nuclei into a single
:class:`ScanResult`. The :class:`BountyAgent` class is intentionally
thin: every subsystem can be swapped or stubbed for tests.

A scan looks like:

* Authorisation snapshot recorded into the result (and audit log).
* Scope checked against the target URL.
* WAF detection (best effort, never aborts the scan).
* Nuclei run if a binary is on PATH and the config allows it.
* Per-category fuzzing of the requested endpoints.

This is the unit that the CLI ``scan`` command calls.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlparse
from uuid import uuid4

import httpx

from bounty_agent.config import Config
from bounty_agent.core import (
    Finding,
    ScanResult,
    ScopePolicy,
    ScopeViolation,
    TargetContext,
)
from bounty_agent.fuzzing import (
    DEFAULT_ANALYZERS,
    PayloadRegistry,
    ResponsibleFuzzer,
)
from bounty_agent.logging_setup import audit, bind_scan_context, get_logger
from bounty_agent.persistence.tool_cache import NoopToolCache, ToolCache
from bounty_agent.recon.pipeline import ReconResult, run_recon_pipeline
from bounty_agent.recon.waf import detect_async as detect_waf_async
from bounty_agent.scanners import (
    JwtAttackScanner,
    NucleiNotInstalledError,
    NucleiScanner,
    NucleiTimeoutError,
    SensitivePathScanner,
)
from bounty_agent.tools import ToolRegistry

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path
    from uuid import UUID


logger = get_logger(__name__)


class BountyAgent:
    """Modular orchestrator that drives a single scan."""

    def __init__(
        self,
        config: Config,
        payload_registry: PayloadRegistry,
        *,
        fuzzer: ResponsibleFuzzer | None = None,
        nuclei: NucleiScanner | None = None,
        sensitive: SensitivePathScanner | None = None,
        jwt_scanner: JwtAttackScanner | None = None,
        scope: ScopePolicy | None = None,
        tool_registry: ToolRegistry | None = None,
        tool_cache: ToolCache | None = None,
    ) -> None:
        self.config = config
        self.scope = scope or config.scope.as_policy()
        self.fuzzer = fuzzer or ResponsibleFuzzer(
            config=config.agent.as_fuzzer_config(),
            registry=payload_registry,
            scope=self.scope,
            analyzers=DEFAULT_ANALYZERS,
        )
        self.nuclei = nuclei or NucleiScanner(
            config=config.nuclei.as_nuclei_config(), scope=self.scope
        )
        self.sensitive = sensitive or SensitivePathScanner(
            scope=self.scope,
            request_timeout_seconds=config.agent.request_timeout_seconds,
        )
        self.jwt_scanner = jwt_scanner or JwtAttackScanner(
            scope=self.scope,
            request_timeout_seconds=config.agent.request_timeout_seconds,
        )
        self.tool_registry = tool_registry or ToolRegistry()
        self.tool_cache = tool_cache or NoopToolCache()

    async def scan(
        self,
        target: str,
        target_context: TargetContext | None = None,
        preset_targets: list[str] | None = None,
        post_targets: list[dict[str, object]] | None = None,
    ) -> ScanResult:
        """Run a full scan.

        ``preset_targets`` skips the recon pipeline and feeds the
        supplied URLs straight to fuzzing and nuclei. Every URL is
        still validated against the scope policy first.

        ``post_targets`` is an optional list of POST/PUT/PATCH endpoints
        with JSON body templates. Each item is a dict with keys
        ``url``, ``method``, ``body`` (a JSON-shaped dict where fields
        whose value equals :data:`FUZZ_MARKER` are substituted with
        payloads). Optional ``categories`` selects fuzzing categories.
        """
        scan_id = uuid4()
        bind_scan_context(scan_id, target)

        ctx = target_context or TargetContext()
        audit(
            "scan.started",
            scan_id=str(scan_id),
            target=target,
            program=ctx.program,
        )

        # Refuse early if the URL is not in scope.
        self.scope.check(target)

        result = ScanResult(
            scan_id=scan_id,
            target=target,  # type: ignore[arg-type]
            target_context=ctx,
        )

        if preset_targets:
            # Bypass recon entirely. Validate each URL against scope.
            validated: list[str] = []
            errors: list[str] = []
            for url in preset_targets:
                try:
                    self.scope.check(url)
                except ScopeViolation as exc:
                    errors.append(f"out of scope: {exc.url}")
                    continue
                validated.append(url)
            scan_targets = validated or [target]
            result = result.model_copy(
                update={
                    "endpoints": scan_targets,
                    "errors": list(result.errors) + errors,
                }
            )
            audit(
                "scan.preset_targets",
                scan_id=str(scan_id),
                accepted=len(validated),
                rejected=len(errors),
            )
        else:
            # External recon pipeline first, so WAF/fuzz/nuclei work
            # against the URLs actually discovered.
            recon = await self._run_recon(target, scan_id)
            result = result.model_copy(
                update={
                    "endpoints": recon.urls or [target],
                    "findings": list(result.findings) + recon.findings,
                    "errors": list(result.errors) + recon.errors,
                }
            )
            scan_targets = recon.urls or [target]

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.agent.request_timeout_seconds),
            follow_redirects=True,
        ) as client:
            if self.config.waf.detect:
                detection = await detect_waf_async(client, target, scope=self.scope)
                result = result.model_copy(update={"waf_detection": detection})
            else:
                detection = result.waf_detection

            if self.config.fuzzing.enabled:
                fuzz_findings = await self._run_fuzzing_many(client, scan_targets, scan_id)
                result = self._with_findings(result, fuzz_findings)

                if post_targets:
                    post_findings = await self._run_post_fuzzing(client, post_targets, scan_id)
                    result = self._with_findings(result, post_findings)

            # Sensitive-content scan: signature-based, no payloads. Cheap to
            # run on every endpoint, catches the high-confidence stuff the
            # fuzzer/nuclei don't see (backup files, /metrics, /ftp/*, env
            # leaks). Bounded by the same max_endpoints budget as fuzzing.
            sensitive_targets = scan_targets[: self.config.fuzzing.max_endpoints]
            sensitive_findings = await self.sensitive.scan(
                client, sensitive_targets, scan_id=scan_id
            )
            result = self._with_findings(result, sensitive_findings)

            # JWT manipulation: if anything we found exposes a JWT (auth
            # bypass, response leak), try alg:none and signature stripping
            # against the scan target list. The scanner self-skips URLs
            # that aren't actually auth-protected (200 in unauth baseline).
            captured_jwts = _collect_jwts(result.findings)
            for token in captured_jwts:
                jwt_findings = await self.jwt_scanner.scan(
                    client,
                    token=token,
                    protected_urls=sensitive_targets,
                    scan_id=scan_id,
                )
                if jwt_findings:
                    result = self._with_findings(result, jwt_findings)

        if self.config.nuclei.enabled:
            nuclei_findings, nuclei_errors = await self._run_nuclei_many(scan_targets, scan_id)
            result = self._with_findings(result, nuclei_findings)
            if nuclei_errors:
                result = result.model_copy(update={"errors": list(result.errors) + nuclei_errors})

        finished_at = _utcnow()
        result = result.model_copy(update={"finished_at": finished_at})
        audit(
            "scan.finished",
            scan_id=str(scan_id),
            target=target,
            findings=len(result.findings),
            errors=len(result.errors),
        )
        return result

    async def _run_recon(
        self,
        target: str,
        scan_id: UUID,
    ) -> ReconResult:
        try:
            return await run_recon_pipeline(
                target=target,
                config=self.config,
                scope=self.scope,
                registry=self.tool_registry,
                scan_id=scan_id,
                intrusive_ok=True,
                cache=self.tool_cache,
            )
        except ScopeViolation:
            raise
        except Exception as exc:
            logger.warning("recon.pipeline_failed", error=str(exc))
            return ReconResult(errors=[f"recon pipeline failed: {exc}"])

    async def _run_fuzzing_many(
        self,
        client: httpx.AsyncClient,
        targets: list[str],
        scan_id: object,
    ) -> list[Finding]:
        findings: list[Finding] = []
        # Bound the fuzzing surface so a large recon output does not
        # explode the run time.
        bounded = targets[: self.config.fuzzing.max_endpoints]
        for url in bounded:
            findings.extend(await self._run_fuzzing(client, url, scan_id))
        return findings

    async def _run_post_fuzzing(
        self,
        client: httpx.AsyncClient,
        post_targets: list[dict[str, object]],
        scan_id: object,
    ) -> list[Finding]:
        """Drive :meth:`ResponsibleFuzzer.fuzz_json_body` for each post target.

        Each entry shape::

            {
                "url": "http://localhost:3000/rest/user/login",
                "method": "POST",
                "body": {"email": "__FUZZ__", "password": "x"},
                "categories": ["sql_injection"],   # optional
                "headers": {...},                  # optional
            }
        """
        findings: list[Finding] = []
        for entry in post_targets:
            url = str(entry.get("url", ""))
            method = str(entry.get("method", "POST"))
            body_obj = entry.get("body")
            if not url or not isinstance(body_obj, dict):
                logger.warning(
                    "fuzzer.post_target_skipped",
                    reason="missing url or non-dict body",
                    url=url,
                )
                continue
            try:
                self.scope.check(url)
            except ScopeViolation as exc:
                logger.warning("fuzzer.post_target_out_of_scope", url=str(exc.url))
                continue
            categories_raw = entry.get("categories")
            if isinstance(categories_raw, list):
                categories: list[str] = [str(c) for c in categories_raw]
            else:
                categories = list(self.config.fuzzing.categories)
            extra_headers_raw = entry.get("headers")
            extra_headers: dict[str, str] | None = None
            if isinstance(extra_headers_raw, dict):
                extra_headers = {str(k): str(v) for k, v in extra_headers_raw.items()}
            for category in categories:
                try:
                    cat_findings = await self.fuzzer.fuzz_json_body(
                        client=client,
                        url=url,
                        method=method,
                        body_template=body_obj,
                        category=category,
                        scan_id=scan_id,  # type: ignore[arg-type]
                        extra_headers=extra_headers,
                    )
                except ScopeViolation:
                    raise
                except Exception as exc:
                    logger.warning(
                        "fuzzer.post_category_failed",
                        category=category,
                        url=url,
                        error=str(exc),
                    )
                    continue
                findings.extend(cat_findings)
        return findings

    async def _run_fuzzing(
        self,
        client: httpx.AsyncClient,
        target: str,
        scan_id: object,
    ) -> list[Finding]:
        """Run all fuzzing categories against ``target``.

        Strategy (Phase 24):

        1. Parse the URL's query string. Fuzz every existing param.
        2. If there are no query params, fuzz a small set of common
           parameter names (``q``, ``id``, ``search``, ...) so an
           endpoint like ``/rest/products/search`` still gets touched.
        3. Always attempt path-segment fuzzing. The fuzzer no-ops when
           the last segment isn't a numeric ID, so this is safe to call
           unconditionally and catches IDOR-shaped URLs like
           ``/api/Users/1``.
        """
        findings: list[Finding] = []
        params = self._fuzzable_params(target)
        for category in self.config.fuzzing.categories:
            for param in params:
                try:
                    category_findings = await self.fuzzer.fuzz_endpoint(
                        client,
                        target,
                        param=param,
                        category=category,
                        scan_id=scan_id,  # type: ignore[arg-type]
                    )
                except ScopeViolation:
                    raise
                except Exception as exc:
                    logger.warning(
                        "fuzzer.category_failed",
                        category=category,
                        param=param,
                        error=str(exc),
                    )
                    continue
                findings.extend(category_findings)

            try:
                path_findings = await self.fuzzer.fuzz_path_segment(
                    client,
                    target,
                    category=category,
                    scan_id=scan_id,  # type: ignore[arg-type]
                )
            except ScopeViolation:
                raise
            except Exception as exc:
                logger.warning(
                    "fuzzer.path_segment_failed",
                    category=category,
                    error=str(exc),
                )
            else:
                findings.extend(path_findings)
        return findings

    # Common parameter names tried when the URL has no query string. These
    # cover the bulk of real-world reflective sinks: search forms, ID
    # lookups, file-include params, redirect params.
    _FALLBACK_PARAMS: tuple[str, ...] = (
        "q",
        "id",
        "search",
        "name",
        "query",
        "file",
        "path",
        "redirect",
        "url",
    )

    def _fuzzable_params(self, url: str) -> tuple[str, ...]:
        """Return the parameter names we'll inject payloads into.

        Existing query params take priority: if the URL already has
        ``?q=apple``, fuzzing only ``q`` is what a tester would do. When
        there are none, fall back to a curated list of common sinks.
        """
        parsed = urlparse(url)
        existing = tuple(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
        return existing or self._FALLBACK_PARAMS

    async def _run_nuclei_many(
        self,
        targets: list[str],
        scan_id: object,
    ) -> tuple[list[Finding], list[str]]:
        all_findings: list[Finding] = []
        all_errors: list[str] = []
        # Same bound as fuzzing: keep run time predictable.
        bounded = targets[: self.config.fuzzing.max_endpoints]
        for url in bounded:
            findings, errors = await self._run_nuclei(url, scan_id)
            all_findings.extend(findings)
            all_errors.extend(errors)
        return all_findings, all_errors

    async def _run_nuclei(
        self,
        target: str,
        scan_id: object,
    ) -> tuple[list[Finding], list[str]]:
        try:
            result = await self.nuclei.scan(target, scan_id=scan_id)  # type: ignore[arg-type]
        except NucleiNotInstalledError as exc:
            logger.info("nuclei.not_installed", error=str(exc))
            return [], [f"nuclei not installed: {exc}"]
        except NucleiTimeoutError as exc:
            logger.warning("nuclei.timeout", error=str(exc))
            return [], [str(exc)]
        return result.findings, []

    @staticmethod
    def _with_findings(result: ScanResult, new: list[Finding]) -> ScanResult:
        return result.model_copy(update={"findings": list(result.findings) + new})


def _utcnow() -> datetime:
    from datetime import UTC, datetime

    return datetime.now(UTC)


def _collect_jwts(findings: list[Finding]) -> list[str]:
    """Return the unique full JWTs stashed in finding evidence.

    The :class:`AuthBypassAnalyzer` parks the matched token in
    ``evidence['jwt']``. Other producers may follow the same key in the
    future; this helper de-duplicates and orders by first-seen so the
    JWT scanner gets a stable input.
    """
    seen: set[str] = set()
    ordered: list[str] = []
    for finding in findings:
        token = finding.evidence.get("jwt") if finding.evidence else None
        if isinstance(token, str) and token and token not in seen:
            seen.add(token)
            ordered.append(token)
    return ordered


def default_payload_registry(config: Config, project_root: Path | None = None) -> PayloadRegistry:
    """Load the payloads YAML scoped to the configured categories.

    Honours ``config.fuzzing.payloads_file`` if set (opt-in aggressive
    payloads); otherwise falls back to ``config/payloads.yaml``.
    """
    from pathlib import Path

    root = project_root or Path.cwd()
    if config.fuzzing.payloads_file:
        yaml_path = Path(config.fuzzing.payloads_file)
        if not yaml_path.is_absolute():
            yaml_path = root / yaml_path
    else:
        yaml_path = root / "config" / "payloads.yaml"

    if not yaml_path.exists():
        return PayloadRegistry.from_mapping({})

    registry = PayloadRegistry.from_yaml(yaml_path)
    if config.fuzzing.categories:
        wanted = set(c.lower() for c in config.fuzzing.categories)
        return PayloadRegistry.from_mapping(
            {c: registry.get(c) for c in registry.categories() if c in wanted}
        )
    return registry


__all__ = ["BountyAgent", "default_payload_registry"]
