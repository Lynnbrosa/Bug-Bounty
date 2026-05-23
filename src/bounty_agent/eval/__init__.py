"""Golden dataset and evaluation harness."""

from bounty_agent.eval.dataset import GoldenCase, GoldenResponse, load_cases
from bounty_agent.eval.harness import (
    ANALYZERS_BY_CATEGORY,
    CategoryMetrics,
    EvalReport,
    evaluate,
)

__all__ = [
    "ANALYZERS_BY_CATEGORY",
    "CategoryMetrics",
    "EvalReport",
    "GoldenCase",
    "GoldenResponse",
    "evaluate",
    "load_cases",
]
