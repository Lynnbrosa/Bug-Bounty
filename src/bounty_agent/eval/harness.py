"""Harness that runs the analyzers against the golden dataset and
computes precision / recall / F1 per category.

The analyzers are pure functions of ``(url, payload, response,
baseline)``, so the harness can build synthetic ``httpx.Response``
objects from the golden cases without touching the network.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from bounty_agent.eval.dataset import Category, GoldenCase
from bounty_agent.fuzzing import (
    Analyzer,
    PathTraversalAnalyzer,
    ReflectedXssAnalyzer,
    SqlInjectionAnalyzer,
)

ANALYZERS_BY_CATEGORY: dict[Category, list[Analyzer]] = {
    "sql_injection": [SqlInjectionAnalyzer()],
    "xss": [ReflectedXssAnalyzer()],
    "path_traversal": [PathTraversalAnalyzer()],
    "none": [],
}


@dataclass(frozen=True)
class CategoryMetrics:
    """Confusion-matrix derived metrics for one category."""

    category: Category
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    true_negative: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positive + self.false_positive
        return self.true_positive / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positive + self.false_negative
        return self.true_positive / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass(frozen=True)
class EvalReport:
    """Aggregate eval output."""

    per_category: dict[Category, CategoryMetrics]
    failures: list[str] = field(default_factory=list)

    @property
    def overall(self) -> CategoryMetrics:
        tp = sum(m.true_positive for m in self.per_category.values())
        fp = sum(m.false_positive for m in self.per_category.values())
        fn = sum(m.false_negative for m in self.per_category.values())
        tn = sum(m.true_negative for m in self.per_category.values())
        return CategoryMetrics(
            category="none",
            true_positive=tp,
            false_positive=fp,
            false_negative=fn,
            true_negative=tn,
        )


def _make_response(case: GoldenCase) -> httpx.Response:
    request = httpx.Request("GET", case.url)
    return httpx.Response(
        status_code=case.response.status_code,
        headers=case.response.headers,
        text=case.response.body,
        request=request,
    )


def evaluate(cases: list[GoldenCase]) -> EvalReport:
    """Run the analyzers against ``cases`` and return aggregate metrics."""
    counters: dict[Category, dict[str, int]] = {}
    failures: list[str] = []

    for case in cases:
        analyzers = ANALYZERS_BY_CATEGORY.get(case.category, [])
        response = _make_response(case)
        triggered = any(
            a.analyze(case.url, case.payload, response, baseline=None) is not None
            for a in analyzers
        )
        bucket = counters.setdefault(
            case.category,
            {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
        )

        if case.expected == "tp" and triggered:
            bucket["tp"] += 1
        elif case.expected == "tp" and not triggered:
            bucket["fn"] += 1
            failures.append(f"missed: {case.id}")
        elif case.expected == "fp" and triggered:
            bucket["fp"] += 1
            failures.append(f"over-triggered: {case.id}")
        else:
            bucket["tn"] += 1

    per_category = {
        category: CategoryMetrics(
            category=category,
            true_positive=values["tp"],
            false_positive=values["fp"],
            false_negative=values["fn"],
            true_negative=values["tn"],
        )
        for category, values in counters.items()
    }
    return EvalReport(per_category=per_category, failures=failures)


__all__ = ["ANALYZERS_BY_CATEGORY", "CategoryMetrics", "EvalReport", "evaluate"]
