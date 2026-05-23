"""Payload registry.

Replaces the legacy ``PAYLOADS_FUZZING`` module-global mutable dict
(B10) with a frozen registry that can be loaded from an external YAML
file. Mutation is explicit and returns a new registry.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Self

import yaml


@dataclass(frozen=True)
class PayloadRegistry:
    """Immutable view of category -> payload list."""

    _payloads: MappingProxyType[str, tuple[str, ...]]

    @classmethod
    def from_mapping(cls, mapping: dict[str, list[str] | tuple[str, ...]]) -> Self:
        cleaned: dict[str, tuple[str, ...]] = {}
        for category, payloads in mapping.items():
            key = category.strip().lower()
            cleaned[key] = tuple(p for p in payloads if p)
        return cls(MappingProxyType(cleaned))

    @classmethod
    def from_yaml(cls, path: Path | str) -> Self:
        raw = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(raw) or {}
        if not isinstance(data, dict):
            raise ValueError(f"payloads YAML at {path} must be a mapping")
        return cls.from_mapping(data)

    def categories(self) -> tuple[str, ...]:
        return tuple(self._payloads.keys())

    def get(self, category: str) -> tuple[str, ...]:
        return self._payloads.get(category.lower(), ())

    def with_overrides(
        self,
        overrides: dict[str, list[str] | tuple[str, ...]],
    ) -> Self:
        """Return a new registry with the given categories replaced."""
        merged: dict[str, tuple[str, ...]] = dict(self._payloads)
        for category, payloads in overrides.items():
            merged[category.lower()] = tuple(payloads)
        return type(self)(MappingProxyType(merged))


__all__ = ["PayloadRegistry"]
