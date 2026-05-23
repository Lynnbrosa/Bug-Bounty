"""Golden dataset loader.

Each case is one JSON file matching :class:`GoldenCase`. Loading is
strict: bad files raise instead of being silently skipped, so the
eval harness never reports inflated numbers due to a missed case.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Expected = Literal["tp", "fp"]
Category = Literal["sql_injection", "xss", "path_traversal", "none"]


class GoldenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""


class GoldenCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    description: str
    category: Category
    url: str
    payload: str
    response: GoldenResponse
    expected: Expected


def load_cases(directory: Path) -> list[GoldenCase]:
    cases: list[GoldenCase] = []
    for path in sorted(directory.glob("*.json")):
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        cases.append(GoldenCase.model_validate(data))
    return cases


def iter_cases_by_category(
    cases: list[GoldenCase],
) -> Iterator[tuple[Category, list[GoldenCase]]]:
    grouped: dict[Category, list[GoldenCase]] = {}
    for case in cases:
        grouped.setdefault(case.category, []).append(case)
    yield from grouped.items()


__all__ = [
    "Category",
    "Expected",
    "GoldenCase",
    "GoldenResponse",
    "iter_cases_by_category",
    "load_cases",
]
