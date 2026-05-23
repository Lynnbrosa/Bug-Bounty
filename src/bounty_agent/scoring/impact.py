"""Contextual impact scoring.

Implements the multiplier model from EXEMPLOS_AVANCADOS.md (Snippet 2)
on top of the :class:`Severity` base score, capped at 10.0.
"""

from __future__ import annotations

from dataclasses import dataclass

from bounty_agent.core import Finding, Severity, TargetContext


@dataclass(frozen=True)
class ImpactMultipliers:
    is_production: float = 1.5
    requires_auth: float = 0.7
    affects_pii: float = 1.3
    affects_payment: float = 1.5


DEFAULT_MULTIPLIERS = ImpactMultipliers()


def score(
    finding: Finding,
    context: TargetContext,
    multipliers: ImpactMultipliers = DEFAULT_MULTIPLIERS,
) -> float:
    """Return the contextual score (0.0-10.0) for ``finding``."""
    base: float = Severity(finding.severity).base_score
    if context.is_production:
        base *= multipliers.is_production
    if context.requires_auth:
        base *= multipliers.requires_auth
    if context.affects_pii:
        base *= multipliers.affects_pii
    if context.affects_payment:
        base *= multipliers.affects_payment
    return min(round(base, 2), 10.0)


def apply_scoring(
    findings: list[Finding],
    context: TargetContext,
    multipliers: ImpactMultipliers = DEFAULT_MULTIPLIERS,
) -> list[Finding]:
    """Return ``findings`` with ``contextual_score`` filled in."""
    return [
        finding.model_copy(update={"contextual_score": score(finding, context, multipliers)})
        for finding in findings
    ]


__all__ = ["DEFAULT_MULTIPLIERS", "ImpactMultipliers", "apply_scoring", "score"]
