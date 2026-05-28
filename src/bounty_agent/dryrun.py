"""Dry-run mode: enumerate every request the scanner would send.

Plans the work of a full scan without sending a single byte. Useful
to prove scope compliance to a bug bounty program *before* engaging:
the operator can show "these and only these URLs are about to be
touched, with these and only these methods, payloads and headers".

Produces a structured :class:`DryRunPlan` and renders it as a Rich
table for the CLI. The plan covers:

- the scope evaluation: which input URLs pass / fail the policy
- the recon phase: which external tools would run and on what target
- the fuzzer phase: per endpoint, the params and categories to be
  exercised, and how many payload requests that totals
- the sensitive scanner: which URLs get a GET probe
- the JWT scanner: which URLs would receive Bearer attempts (when a
  captured JWT is available — we honour configured login flows)
- the nuclei phase: which URLs would be scanned and with what
  template severity

Strictly read-only on the network and the filesystem. The only side
effect is the Rich-rendered plan to stdout.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from bounty_agent.config import Config
from bounty_agent.fuzzing import PayloadRegistry


@dataclass(frozen=True)
class PhasePlan:
    """One stage of the planned scan."""

    name: str
    enabled: bool
    target_count: int
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DryRunPlan:
    """What the agent would do, end to end."""

    target: str
    scope_in: list[str]
    scope_out: list[str]
    phases: list[PhasePlan]
    estimated_requests: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scope_in": self.scope_in,
            "scope_out": self.scope_out,
            "phases": [asdict(p) for p in self.phases],
            "estimated_requests": self.estimated_requests,
        }


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


def plan_scan(  # noqa: PLR0912, PLR0915 - planner enumerates each phase linearly
    config: Config,
    target: str,
    preset_targets: list[str] | None = None,
    post_targets: list[dict[str, object]] | None = None,
) -> DryRunPlan:
    """Build a :class:`DryRunPlan` from the same inputs as ``scan``."""
    scope = config.scope.as_policy()
    candidate_urls = preset_targets or [target]

    scope_in: list[str] = []
    scope_out: list[str] = []
    for url in candidate_urls:
        try:
            scope.check(url)
            scope_in.append(url)
        except Exception:
            scope_out.append(url)

    phases: list[PhasePlan] = []

    # Recon
    if not preset_targets:
        recon_notes = []
        for tool_name in (
            "subfinder",
            "waybackurls",
            "dnsx",
            "katana",
            "httpx",
            "naabu",
            "nmap",
            "arjun",
            "subjack",
            "trufflehog",
        ):
            if getattr(config.tools, tool_name, False):
                recon_notes.append(f"would invoke {tool_name}")
        phases.append(
            PhasePlan(
                name="recon",
                enabled=True,
                target_count=1,
                notes=recon_notes,
            )
        )

    # WAF detection
    phases.append(
        PhasePlan(
            name="waf detection",
            enabled=config.waf.detect,
            target_count=1 if config.waf.detect else 0,
            notes=["single GET to the root URL"] if config.waf.detect else [],
        )
    )

    # Fuzzing
    fuzz_targets = scope_in[: config.fuzzing.max_endpoints]
    fuzz_requests = 0
    fuzz_notes: list[str] = []
    if config.fuzzing.enabled:
        try:
            registry = _try_load_payloads(config)
            per_category_counts = {cat: len(registry.get(cat)) for cat in config.fuzzing.categories}
            for url in fuzz_targets:
                params = _params_for(url)
                # Each (param, category) emits 1 baseline + N payload requests.
                for category in config.fuzzing.categories:
                    payload_count = per_category_counts.get(category, 0)
                    if payload_count == 0:
                        continue
                    fuzz_requests += 1 + payload_count * len(params)
            fuzz_notes.append(
                f"params per url: existing query OR {len(_FALLBACK_PARAMS)} fallbacks"
            )
            fuzz_notes.append(
                "categories: " + ", ".join(f"{cat}({n})" for cat, n in per_category_counts.items())
            )
        except Exception as exc:
            fuzz_notes.append(f"payload load failed: {exc}; counts skipped")
    if post_targets:
        # Each post target counts as 1 baseline + N payloads per marker.
        post_reqs = 0
        for entry in post_targets:
            body = entry.get("body") if isinstance(entry, dict) else None
            if isinstance(body, dict):
                markers = sum(1 for v in body.values() if v == "__FUZZ__")
                # Approximation: same payloads_per_param across categories.
                avg_payloads = max(1, config.fuzzing.payloads_per_param)
                post_reqs += 1 + markers * avg_payloads * len(config.fuzzing.categories)
        fuzz_notes.append(
            f"post-targets: {len(post_targets)} endpoints, ~{post_reqs} extra requests"
        )
        fuzz_requests += post_reqs
    phases.append(
        PhasePlan(
            name="fuzzing",
            enabled=config.fuzzing.enabled,
            target_count=len(fuzz_targets),
            notes=fuzz_notes,
        )
    )

    # Sensitive scanner: 1 GET per target.
    sensitive_targets = scope_in[: config.fuzzing.max_endpoints]
    phases.append(
        PhasePlan(
            name="sensitive scanner",
            enabled=True,
            target_count=len(sensitive_targets),
            notes=["one GET per URL; +1 retry on 401/403 with %2500.md suffix"],
        )
    )
    sensitive_requests = len(sensitive_targets)

    # JWT scanner: skipped unless login is configured + auth bypass observed.
    phases.append(
        PhasePlan(
            name="jwt attack",
            enabled=False,
            target_count=0,
            notes=[
                "runs only after a JWT is captured (auth bypass or login flow); "
                "would send 2 attack variants per protected URL (alg:none, "
                "signature strip)"
            ],
        )
    )

    # Nuclei: 1 invocation per target.
    nuclei_targets = scope_in[: config.fuzzing.max_endpoints]
    phases.append(
        PhasePlan(
            name="nuclei",
            enabled=config.nuclei.enabled,
            target_count=len(nuclei_targets),
            notes=[
                f"severity={list(config.nuclei.severity)}; "
                f"timeout={config.nuclei.timeout_seconds}s per url"
            ],
        )
    )

    # OOB correlator: no outbound from the agent; just polls + waits.
    phases.append(
        PhasePlan(
            name="oob correlator",
            enabled=config.oob.enabled,
            target_count=0,
            notes=(
                [
                    f"polls {config.oob.poll_url}" if config.oob.poll_url else "reads local log",
                    f"wait_after_scan={config.oob.poll_after_scan_seconds}s",
                ]
                if config.oob.enabled
                else []
            ),
        )
    )

    estimated_requests = fuzz_requests + sensitive_requests + (1 if config.waf.detect else 0)
    return DryRunPlan(
        target=target,
        scope_in=scope_in,
        scope_out=scope_out,
        phases=phases,
        estimated_requests=estimated_requests,
    )


def render_plan(plan: DryRunPlan, console: Console) -> None:
    """Render a :class:`DryRunPlan` as Rich panels."""
    console.rule(f"[bold cyan]dry-run plan[/bold cyan] - {plan.target}")
    scope_table = Table(title="scope evaluation", title_style="bold")
    scope_table.add_column("bucket")
    scope_table.add_column("count")
    scope_table.add_column("first")
    scope_table.add_row(
        "[green]in scope[/green]",
        str(len(plan.scope_in)),
        plan.scope_in[0] if plan.scope_in else "-",
    )
    scope_table.add_row(
        "[red]rejected[/red]",
        str(len(plan.scope_out)),
        plan.scope_out[0] if plan.scope_out else "-",
    )
    console.print(Panel(scope_table, border_style="cyan"))

    phases_table = Table(title="phases", title_style="bold")
    phases_table.add_column("phase")
    phases_table.add_column("enabled")
    phases_table.add_column("targets")
    phases_table.add_column("notes")
    for phase in plan.phases:
        phases_table.add_row(
            phase.name,
            "[green]yes[/green]" if phase.enabled else "[dim]no[/dim]",
            str(phase.target_count),
            "; ".join(phase.notes) if phase.notes else "-",
        )
    console.print(Panel(phases_table, border_style="cyan"))

    summary = (
        f"[bold]Estimated total HTTP requests:[/bold] ~{plan.estimated_requests}\n"
        f"[bold]No requests have been sent.[/bold] "
        "Re-run without --dry-run to execute."
    )
    console.print(Panel(summary, border_style="green"))


def _try_load_payloads(config: Config) -> PayloadRegistry:
    """Mirror orchestrator.default_payload_registry, lazy + safe."""
    from pathlib import Path

    if config.fuzzing.payloads_file:
        path = Path(config.fuzzing.payloads_file)
    else:
        path = Path("config/payloads.yaml")
    if not path.exists():
        return PayloadRegistry.from_mapping({})
    return PayloadRegistry.from_yaml(path)


def _params_for(url: str) -> tuple[str, ...]:
    parsed = urlparse(url)
    existing = tuple(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
    return existing or _FALLBACK_PARAMS


__all__ = ["DryRunPlan", "PhasePlan", "plan_scan", "render_plan"]
