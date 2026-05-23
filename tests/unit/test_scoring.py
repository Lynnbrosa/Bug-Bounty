"""Tests for the contextual impact scoring."""

from __future__ import annotations

from bounty_agent.core import Finding, FindingSource, Severity, TargetContext
from bounty_agent.scoring import apply_scoring, score


def _finding(severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        url="https://example.com/",
        source=FindingSource.NUCLEI,
        severity=severity,
        title="t",
    )


def test_no_context_returns_base_score() -> None:
    assert score(_finding(Severity.HIGH), TargetContext()) == 7.0


def test_production_boosts_score_and_caps_at_ten() -> None:
    # base 7.0 * 1.5 = 10.5, capped to 10.0
    assert score(_finding(Severity.HIGH), TargetContext(is_production=True)) == 10.0


def test_production_boosts_low_under_cap() -> None:
    # base 3.0 * 1.5 = 4.5, under the cap
    assert score(_finding(Severity.LOW), TargetContext(is_production=True)) == 4.5


def test_requires_auth_reduces_score() -> None:
    boosted = score(_finding(Severity.HIGH), TargetContext(requires_auth=True))
    assert boosted < 7.0


def test_score_is_capped_at_ten() -> None:
    context = TargetContext(is_production=True, affects_pii=True, affects_payment=True)
    assert score(_finding(Severity.CRITICAL), context) == 10.0


def test_apply_scoring_fills_contextual_score() -> None:
    findings = [_finding(Severity.HIGH), _finding(Severity.LOW)]
    enriched = apply_scoring(findings, TargetContext(is_production=True))
    assert enriched[0].contextual_score == 10.0
    assert enriched[1].contextual_score == 4.5
