"""LLM-driven adaptive payload generation.

Most fuzzers ship a static catalogue: every target gets the same
payloads from the same YAML file. That's mediocre against modern
stacks where the right payload depends on whether the backend is
Mongo or Postgres, Node or Rails, Express or Spring.

This module asks Claude to generate ~10 bespoke payloads per category
based on the target's actual tech stack (gathered by ``recon`` and
``waf`` detection). The result merges with the static catalogue so
the operator can audit the diff between "generic" and "adaptive".

Cheap by default: uses Haiku 4.5 and a single call per scan (not per
endpoint). The adaptive payloads are produced once and reused across
the scan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from bounty_agent.fuzzing.payloads import PayloadRegistry
from bounty_agent.logging_setup import audit, get_logger

logger = get_logger(__name__)


_SYSTEM_PROMPT = (
    "You are a senior bug bounty researcher generating bespoke fuzzing "
    "payloads for one authorised target. You are given the target's "
    "detected tech stack (backend language, database, framework, WAF) "
    "and a set of categories. Your job is to write payloads that are "
    "most likely to trigger errors or behavioural changes against "
    "THAT SPECIFIC STACK. Avoid generic payloads from public lists; "
    "the operator already has those. Be precise: short payloads that "
    "exercise a known quirk of the stack are more valuable than "
    "long shotgun payloads. Never include destructive operations."
)


_RULES_PROMPT = (
    "## Output rules\n"
    "\n"
    "- Generate 8-12 payloads per requested category.\n"
    "- Each payload is a single string, no comments inside the "
    "payload itself.\n"
    "- Reference the stack in a short `rationale` per category "
    "explaining why these payloads suit it.\n"
    "- If a category doesn't fit the stack (e.g. nosql_injection on "
    "Postgres-only), return an empty list and explain in rationale.\n"
)


@dataclass(frozen=True)
class AdaptivePayloadsConfig:
    enabled: bool = False
    model: str = "claude-haiku-4-5"
    max_tokens: int = 2048
    api_key: str | None = None
    categories: tuple[str, ...] = (
        "sql_injection",
        "nosql_injection",
        "xss",
        "path_traversal",
        "command_injection",
        "ssti",
    )


class CategoryPayloads(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str = Field(min_length=1, max_length=50)
    rationale: str = Field(max_length=400)
    payloads: list[str] = Field(default_factory=list)


class AdaptivePayloadSet(BaseModel):
    """LLM output: one set of payloads per category."""

    model_config = ConfigDict(extra="forbid")

    stack_fingerprint: str = Field(max_length=300)
    categories: list[CategoryPayloads] = Field(default_factory=list)


@dataclass
class AdaptivePayloadGenerator:
    """Build a PayloadRegistry from LLM-tailored payloads."""

    config: AdaptivePayloadsConfig
    client: Any = None

    def _ensure_client(self) -> Any:  # noqa: ANN401 - SDK type
        if self.client is not None:
            return self.client
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                'anthropic package required. Install: pip install -e ".[llm]"'
            ) from exc
        if self.config.api_key:
            return anthropic.Anthropic(api_key=self.config.api_key)
        return anthropic.Anthropic()

    def generate(self, target_fingerprint: dict[str, Any]) -> AdaptivePayloadSet | None:
        """Run the adaptive call. Returns ``None`` on LLM failure."""
        if not self.config.enabled:
            return None
        client = self._ensure_client()
        user_content = (
            "Target fingerprint:\n"
            f"```json\n{json.dumps(target_fingerprint, indent=2)}\n```\n\n"
            f"Categories requested: {list(self.config.categories)}\n"
        )
        try:
            response = client.messages.parse(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                system=[
                    {
                        "type": "text",
                        "text": _SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"},
                    },
                    {
                        "type": "text",
                        "text": _RULES_PROMPT,
                        "cache_control": {"type": "ephemeral"},
                    },
                ],
                messages=[{"role": "user", "content": user_content}],
                output_format=AdaptivePayloadSet,
            )
        except Exception as exc:
            logger.warning("adaptive.generate_failed", error=str(exc))
            audit("adaptive.generate_failed", error=str(exc))
            return None

        payloads: AdaptivePayloadSet = response.parsed_output
        audit(
            "adaptive.generated",
            stack=payloads.stack_fingerprint,
            categories=[c.category for c in payloads.categories],
            total_payloads=sum(len(c.payloads) for c in payloads.categories),
        )
        return payloads


def merge_into_registry(
    static_registry: PayloadRegistry,
    adaptive: AdaptivePayloadSet,
) -> PayloadRegistry:
    """Return a NEW PayloadRegistry where each category is the union
    of the static catalogue and the LLM's bespoke additions."""
    merged: dict[str, list[str]] = {}
    # Seed with the static set.
    for category in static_registry.categories():
        merged[category] = list(static_registry.get(category))
    # Layer adaptive payloads on top. We dedup conservatively: same
    # payload string already present -> skip.
    for cat in adaptive.categories:
        bucket = merged.setdefault(cat.category, [])
        existing = set(bucket)
        for payload in cat.payloads:
            if payload not in existing:
                bucket.append(payload)
                existing.add(payload)
    # PayloadRegistry.from_mapping accepts list or tuple values; pass
    # explicitly typed dict to satisfy the invariant generic.
    typed: dict[str, list[str] | tuple[str, ...]] = dict(merged)
    return PayloadRegistry.from_mapping(typed)


__all__ = [
    "AdaptivePayloadGenerator",
    "AdaptivePayloadSet",
    "AdaptivePayloadsConfig",
    "CategoryPayloads",
    "merge_into_registry",
]
