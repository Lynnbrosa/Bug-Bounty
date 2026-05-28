"""External tool recon pipeline.

Runs the configured external tools in a coherent order to widen the
attack surface before the in-process scanners (WAF, fuzzer, nuclei)
take over.

Order:

1. ``subfinder``: passive subdomain enumeration. The result is
   filtered against the scope policy so we never leak outside the
   authorised host set.
2. ``waybackurls``: passive URL history for the same domain.
3. ``dnsx``: optional, resolves the subfinder output so dead names
   are dropped before they hit the network.
4. ``katana``: optional intrusive crawler, runs once per live URL
   surface discovered above.
5. ``httpx``: probes which URLs respond today; this is the list the
   rest of the agent fuzzes.
6. ``naabu``: optional intrusive port scan, emits ``info`` findings
   for each open port (not used to drive further scanning).

Each step is best-effort: a missing binary becomes a single audit
event and the pipeline keeps going. Intrusive tools (katana, naabu)
are gated by both ``config.tools.*`` and the registry's intrusive_ok
flag, which the caller must pass explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from bounty_agent.core import Finding, FindingSource, ScopePolicy, Severity
from bounty_agent.logging_setup import audit, get_logger
from bounty_agent.tools import IntrusiveToolBlocked, ToolRegistry, ToolResult

if TYPE_CHECKING:
    from uuid import UUID

    from bounty_agent.config import Config
    from bounty_agent.persistence import ToolCache


logger = get_logger(__name__)


@dataclass(frozen=True)
class ReconResult:
    """Outcome of one recon pipeline run."""

    subdomains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


async def run_recon_pipeline(  # noqa: PLR0912 - linear pipeline of optional steps
    target: str,
    config: Config,
    scope: ScopePolicy,
    registry: ToolRegistry | None = None,
    scan_id: UUID | None = None,
    max_urls: int = 50,
    intrusive_ok: bool = False,
    cache: ToolCache | None = None,
) -> ReconResult:
    """Execute the configured recon pipeline.

    ``intrusive_ok`` must be ``True`` for ``katana`` and ``naabu`` to
    run; otherwise they are silently skipped with an audit entry.

    ``cache`` short-circuits the passive tools (subfinder, waybackurls)
    when a fresh entry exists for the same target.
    """
    registry = registry or ToolRegistry()
    flags = config.tools
    cache_ttl = config.tools_cache.ttl_seconds if config.tools_cache.enabled else 0
    subdomains: list[str] = []
    urls: list[str] = []
    findings: list[Finding] = []
    errors: list[str] = []

    if flags.subfinder:
        items = await _cached_safe_run(
            registry,
            "subfinder",
            target,
            scope,
            errors,
            cache=cache,
            cache_ttl=cache_ttl,
        )
        subdomains = items

    if flags.dnsx and subdomains:
        # Resolve only the discovered subdomains, not the original target.
        # We replace subdomains with the subset that actually resolves.
        resolved: list[str] = []
        for host in subdomains:
            res = await _safe_run(registry, "dnsx", host, scope, errors, intrusive_ok=False)
            if res and res.items:
                resolved.extend(res.items)
        subdomains = sorted(set(resolved)) if resolved else subdomains

    if flags.waybackurls:
        items = await _cached_safe_run(
            registry,
            "waybackurls",
            target,
            scope,
            errors,
            cache=cache,
            cache_ttl=cache_ttl,
        )
        urls.extend(items)

    if flags.katana:
        result = await _safe_run(
            registry, "katana", target, scope, errors, intrusive_ok=intrusive_ok
        )
        if result:
            urls.extend(result.items)

    # Probe what is alive today. Feed every URL we have plus the original
    # target and an https://<host> per discovered subdomain.
    probe_candidates = _candidates_for_probe(target, subdomains, urls)
    if flags.httpx and probe_candidates:
        # httpx accepts one URL per invocation in our wrapper, so we call
        # it per candidate. Limit to ``max_urls`` to keep the run bounded.
        alive: list[str] = []
        for candidate in probe_candidates[:max_urls]:
            result = await _safe_run(
                registry, "httpx", candidate, scope, errors, intrusive_ok=False
            )
            if result and result.items:
                alive.extend(result.items)
            elif result and not result.skipped and result.return_code == 0:
                # httpx returns no output for unreachable hosts.
                continue
        urls = sorted(set(alive))
    else:
        # No probe configured; just dedup the URLs we already have.
        urls = sorted(set(urls))

    if flags.naabu:
        result = await _safe_run(
            registry, "naabu", target, scope, errors, intrusive_ok=intrusive_ok
        )
        if result:
            findings.extend(_ports_to_findings(target, result))

    if flags.nmap:
        # nmap emits its own structured findings (service+version, NSE
        # script outputs) inside the ToolResult.findings, so we just
        # forward them.
        result = await _safe_run(registry, "nmap", target, scope, errors, intrusive_ok=intrusive_ok)
        if result:
            findings.extend(result.findings)

    audit(
        "recon.finished",
        scan_id=str(scan_id) if scan_id else None,
        target=target,
        subdomains=len(subdomains),
        urls=len(urls),
        findings=len(findings),
        errors=len(errors),
    )

    return ReconResult(
        subdomains=subdomains,
        urls=urls,
        findings=findings,
        errors=errors,
    )


async def _cached_safe_run(
    registry: ToolRegistry,
    name: str,
    target: str,
    scope: ScopePolicy,
    errors: list[str],
    cache: ToolCache | None,
    cache_ttl: int,
) -> list[str]:
    """Cache-aware ``_safe_run`` for passive tools."""
    if cache is not None and cache_ttl > 0:
        cached = cache.get(name, target)
        if cached is not None:
            audit("recon.cache_hit", tool=name, target=target, items=len(cached))
            return cached

    result = await _safe_run(registry, name, target, scope, errors, intrusive_ok=False)
    items = result.items if result else []
    if cache is not None and cache_ttl > 0 and result is not None and not result.skipped:
        cache.set(name, target, items, cache_ttl)
    return items


async def _safe_run(
    registry: ToolRegistry,
    name: str,
    target: str,
    scope: ScopePolicy,
    errors: list[str],
    intrusive_ok: bool,
) -> ToolResult | None:
    try:
        result = await registry.run(name, target, scope=scope, intrusive_ok=intrusive_ok)
    except IntrusiveToolBlocked as exc:
        logger.info("recon.intrusive_blocked", tool=name, error=str(exc))
        audit("recon.intrusive_blocked", tool=name, target=target)
        return None
    except Exception as exc:
        logger.warning("recon.tool_failed", tool=name, error=str(exc))
        errors.append(f"{name}: {exc}")
        return None

    if result.skipped:
        logger.info("recon.tool_skipped", tool=name, reason=result.skipped_reason)
        errors.append(f"{name} skipped: {result.skipped_reason}")
        return None

    return result


def _candidates_for_probe(
    target: str,
    subdomains: list[str],
    urls: list[str],
) -> list[str]:
    """Build the URL set we'll hand to httpx."""
    candidates: list[str] = []
    seen: set[str] = set()

    def _push(value: str) -> None:
        if value not in seen:
            seen.add(value)
            candidates.append(value)

    _push(target)
    for host in subdomains:
        _push(f"https://{host}")
    for url in urls:
        _push(url)
    return candidates


def _ports_to_findings(target: str, result: ToolResult) -> list[Finding]:
    """Translate ``host:port`` strings into info findings."""
    findings: list[Finding] = []
    host = _extract_domain(target)
    base = target if target.startswith(("http://", "https://")) else f"https://{host}"
    for item in result.items:
        findings.append(
            Finding(
                url=base,  # type: ignore[arg-type]
                source=FindingSource.MANUAL,
                severity=Severity.INFO,
                title=f"Open port: {item}",
                description=(
                    "naabu reported an open TCP port. Treat as informational; "
                    "follow up with service identification before reporting."
                ),
                evidence={"observation": item, "tool": result.tool},
            )
        )
    return findings


def _extract_domain(value: str) -> str:
    parsed = urlparse(value)
    return parsed.hostname or value


__all__ = ["ReconResult", "run_recon_pipeline"]
