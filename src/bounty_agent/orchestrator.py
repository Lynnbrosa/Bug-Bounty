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
from uuid import uuid4

import httpx

from bounty_agent.config import Config
from bounty_agent.core import (
    AuthorizationRecord,
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
from bounty_agent.recon.pipeline import ReconResult, run_recon_pipeline
from bounty_agent.recon.waf import detect_async as detect_waf_async
from bounty_agent.scanners import (
    NucleiNotInstalledError,
    NucleiScanner,
    NucleiTimeoutError,
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
        scope: ScopePolicy | None = None,
        tool_registry: ToolRegistry | None = None,
        intrusive_ok: bool = False,
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
        self.tool_registry = tool_registry or ToolRegistry()
        self.intrusive_ok = intrusive_ok

    async def scan(
        self,
        target: str,
        target_context: TargetContext | None = None,
        preset_targets: list[str] | None = None,
    ) -> ScanResult:
        """Run a full scan.

        ``preset_targets`` skips the recon pipeline and feeds the
        supplied URLs straight to fuzzing and nuclei. Every URL is
        still validated against the scope policy first.
        """
        scan_id = uuid4()
        bind_scan_context(scan_id, target)

        authorization = AuthorizationRecord(
            acknowledged=self.config.authorization.acknowledged,
            program=self.config.authorization.program,
            contact=self.config.authorization.contact,
            notes=self.config.authorization.notes,
        )
        audit(
            "scan.started",
            scan_id=str(scan_id),
            target=target,
            program=authorization.program,
        )

        # Refuse early if the URL is not in scope.
        self.scope.check(target)

        result = ScanResult(
            scan_id=scan_id,
            target=target,  # type: ignore[arg-type]
            authorization=authorization,
            target_context=target_context or TargetContext(),
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
                intrusive_ok=self.intrusive_ok,
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

    async def _run_fuzzing(
        self,
        client: httpx.AsyncClient,
        target: str,
        scan_id: object,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for category in self.config.fuzzing.categories:
            try:
                category_findings = await self.fuzzer.fuzz_endpoint(
                    client,
                    target,
                    param="q",
                    category=category,
                    scan_id=scan_id,  # type: ignore[arg-type]
                )
            except ScopeViolation:
                raise
            except Exception as exc:
                logger.warning("fuzzer.category_failed", category=category, error=str(exc))
                continue
            findings.extend(category_findings)
        return findings

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


def default_payload_registry(config: Config, project_root: Path | None = None) -> PayloadRegistry:
    """Load the packaged payloads.yaml, scoped to the configured categories."""
    from pathlib import Path

    root = project_root or Path.cwd()
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
