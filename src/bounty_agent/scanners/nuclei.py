"""Async wrapper around the Nuclei CLI.

The original implementation blocked the event loop with
``subprocess.run`` and parsed JSONL output inline with the network
call. This module separates those concerns:

* :class:`NucleiConfig` is the immutable config snapshot used by a run.
* :func:`parse_nuclei_jsonl` is a pure function that turns raw stdout
  into :class:`Finding` objects. Trivially testable.
* :class:`NucleiScanner` is an async wrapper around
  ``asyncio.create_subprocess_exec`` with timeout, structured logging
  and explicit error types.

The scanner refuses to scan a URL that is denied by a configured
:class:`ScopePolicy`. Audit events are emitted at start, success and
on every error path.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from bounty_agent.core import (
    Finding,
    FindingSource,
    ScopePolicy,
    ScopeViolation,
    Severity,
)
from bounty_agent.logging_setup import audit, get_logger

if TYPE_CHECKING:
    from uuid import UUID


logger = get_logger(__name__)


class NucleiError(Exception):
    """Base error for the Nuclei wrapper."""


class NucleiNotInstalledError(NucleiError):
    """Raised when the nuclei binary is not on PATH."""


class NucleiTimeoutError(NucleiError):
    """Raised when nuclei exceeds the configured timeout."""


@dataclass(frozen=True)
class NucleiConfig:
    """Immutable snapshot of the nuclei run configuration."""

    binary: str = "nuclei"
    templates_path: str = "~/nuclei-templates"
    severity: tuple[str, ...] = ("critical", "high", "medium")
    concurrency: int = 1
    rate_limit: int = 10
    timeout_seconds: int = 120
    extra_args: tuple[str, ...] = field(default_factory=tuple)


def _normalize_severity(raw: str | None) -> Severity:
    if not raw:
        return Severity.INFO
    try:
        return Severity(raw.lower())
    except ValueError:
        logger.debug("nuclei.unknown_severity", value=raw)
        return Severity.INFO


def parse_nuclei_jsonl(stdout: str, fallback_url: str | None = None) -> list[Finding]:
    """Parse nuclei's ``-json`` stdout into :class:`Finding` objects.

    Lines that are not valid JSON or that are missing the ``info``
    block are skipped. The number of skipped lines is logged.
    """
    findings: list[Finding] = []
    skipped = 0

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue

        info = data.get("info") or {}
        url = data.get("matched-at") or data.get("host") or fallback_url
        if not url:
            skipped += 1
            continue
        try:
            findings.append(
                Finding(
                    url=url,  # type: ignore[arg-type]
                    source=FindingSource.NUCLEI,
                    severity=_normalize_severity(info.get("severity")),
                    title=info.get("name") or data.get("template-id") or "Unknown",
                    description=info.get("description") or "",
                    evidence={
                        "template_id": data.get("template-id"),
                        "template_path": data.get("template-path"),
                        "matcher_name": data.get("matcher-name"),
                        "type": data.get("type"),
                    },
                )
            )
        except ValueError:
            skipped += 1
            continue

    if skipped:
        logger.info("nuclei.parser.skipped_lines", skipped=skipped)
    return findings


@dataclass
class NucleiResult:
    """Outcome of a single nuclei invocation."""

    findings: list[Finding]
    stderr: str
    return_code: int


class NucleiScanner:
    """Async wrapper around the nuclei CLI."""

    def __init__(self, config: NucleiConfig, scope: ScopePolicy | None = None) -> None:
        self.config = config
        self.scope = scope

    def _build_command(self, url: str) -> list[str]:
        templates = str(Path(self.config.templates_path).expanduser())
        cmd = [
            self.config.binary,
            "-u",
            url,
            "-t",
            templates,
            "-severity",
            ",".join(self.config.severity),
            "-c",
            str(self.config.concurrency),
            "-rl",
            str(self.config.rate_limit),
            "-timeout",
            str(self.config.timeout_seconds),
            "-jsonl",
            "-silent",
        ]
        cmd.extend(self.config.extra_args)
        return cmd

    async def scan(self, url: str, scan_id: UUID | None = None) -> NucleiResult:
        """Run nuclei against ``url`` and return parsed findings.

        Raises:
            ScopeViolation: if the URL is not in scope.
            NucleiNotInstalledError: if the binary cannot be located.
            NucleiTimeoutError: if the run exceeds ``timeout_seconds``.
        """
        if self.scope is not None:
            self.scope.check(url)

        if shutil.which(self.config.binary) is None:
            audit(
                "nuclei.skipped",
                scan_id=str(scan_id) if scan_id else None,
                url=url,
                reason="binary not installed",
            )
            raise NucleiNotInstalledError(f"nuclei binary '{self.config.binary}' not found on PATH")

        cmd = self._build_command(url)
        logger.info("nuclei.starting", url=url, command=cmd)
        audit(
            "nuclei.started",
            scan_id=str(scan_id) if scan_id else None,
            url=url,
            templates=self.config.templates_path,
        )

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=float(self.config.timeout_seconds + 10),
            )
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            audit(
                "nuclei.timeout",
                scan_id=str(scan_id) if scan_id else None,
                url=url,
                timeout_seconds=self.config.timeout_seconds,
            )
            raise NucleiTimeoutError(
                f"nuclei exceeded {self.config.timeout_seconds}s scanning {url}"
            ) from exc

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        findings = parse_nuclei_jsonl(stdout, fallback_url=url)

        logger.info(
            "nuclei.finished",
            url=url,
            return_code=process.returncode,
            findings=len(findings),
        )
        audit(
            "nuclei.finished",
            scan_id=str(scan_id) if scan_id else None,
            url=url,
            return_code=process.returncode,
            findings=len(findings),
        )

        return NucleiResult(
            findings=findings,
            stderr=stderr,
            return_code=process.returncode if process.returncode is not None else -1,
        )


__all__ = [
    "NucleiConfig",
    "NucleiError",
    "NucleiNotInstalledError",
    "NucleiResult",
    "NucleiScanner",
    "NucleiTimeoutError",
    "ScopeViolation",
    "parse_nuclei_jsonl",
]
