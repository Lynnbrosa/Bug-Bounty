"""Severity scoring with contextual multipliers."""

from bounty_agent.scoring.impact import (
    DEFAULT_MULTIPLIERS,
    ImpactMultipliers,
    apply_scoring,
    score,
)

__all__ = ["DEFAULT_MULTIPLIERS", "ImpactMultipliers", "apply_scoring", "score"]
