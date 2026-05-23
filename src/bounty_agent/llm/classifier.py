"""LLM post-processor for findings.

Uses the Anthropic Python SDK to ask Claude Haiku 4.5 whether a finding
looks like a real positive, suggest a refined title, and propose a
contextual severity. Designed for batch use after a scan finishes:
synchronous, one request per finding.

Prompt caching is applied to the system prompt and classification rules
(both stable across requests) so the bulk of every invocation hits the
cache after the first call. Verify with
``response.usage.cache_read_input_tokens > 0``.

This module is opt-in: callers must construct an :class:`LLMConfig` with
``enabled=True`` and provide either an API key argument or set
``ANTHROPIC_API_KEY``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from bounty_agent.core import Finding, Severity
from bounty_agent.logging_setup import audit, get_logger

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = get_logger(__name__)


_SYSTEM_PROMPT = (
    "You are a senior application security analyst reviewing fuzzing and "
    "scanner output from an authorised bug bounty engagement. Your job is "
    "to decide whether each candidate finding is a real positive worth "
    "reporting, refine the wording so it would pass a triage team's "
    "review, and propose a contextual severity. Be conservative: when in "
    "doubt, mark the finding as a false positive and explain what would "
    "be needed to confirm it. Never invent evidence that is not in the "
    "response excerpt you were given."
)


_CLASSIFICATION_RULES = (
    "## Classification rules\n"
    "\n"
    "- `true_positive` is `true` only when the response excerpt clearly "
    "demonstrates the claimed weakness. Suspicion alone is not enough.\n"
    "- `refined_title` should be a one-line headline a triage analyst "
    "would accept. Lead with the impact, not the payload.\n"
    "- `suggested_severity` follows the canonical ladder: critical, high, "
    "medium, low, info. Only suggest a lower severity than the source if "
    "the evidence shows the impact is limited (e.g. reflected XSS in a "
    "static help page).\n"
    "- `reasoning` is at most three sentences. Reference the excerpt; do "
    "not invent details.\n"
    "- `confidence` is your own calibration of the verdict, from 0 to 1.\n"
    "\n"
    "## Schema\n"
    "\n"
    "Respond using the structured output schema below."
)


class LLMVerdict(BaseModel):
    """Structured verdict returned by the classifier."""

    model_config = ConfigDict(extra="forbid")

    true_positive: bool
    refined_title: str = Field(min_length=1, max_length=200)
    suggested_severity: Literal["critical", "high", "medium", "low", "info"]
    reasoning: str = Field(max_length=600)
    confidence: float = Field(ge=0.0, le=1.0)


@dataclass(frozen=True)
class LLMConfig:
    """Configuration for the LLM classifier."""

    enabled: bool = False
    model: str = "claude-haiku-4-5"
    max_tokens: int = 1024
    api_key: str | None = None
    response_excerpt_chars: int = 2000


@dataclass
class LLMUsage:
    """Token usage accounting for one classifier call."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0


@dataclass
class LLMResult:
    """Pairing of a verdict with the usage that produced it."""

    verdict: LLMVerdict
    usage: LLMUsage


class LLMClassifier:
    """Synchronous classifier against the Anthropic Messages API."""

    def __init__(
        self,
        config: LLMConfig,
        client: Any | None = None,  # noqa: ANN401 - third-party SDK client, not typed here
    ) -> None:
        self.config = config
        self._client = client

    def _ensure_client(self) -> Any:  # noqa: ANN401 - returns the anthropic.Anthropic client
        if self._client is not None:
            return self._client
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - exercised when extra not installed
            raise RuntimeError(
                "anthropic package is required for the LLM post-processor. "
                'Install with: pip install -e ".[llm]"'
            ) from exc
        api_key = self.config.api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set and no api_key was provided")
        self._client = anthropic.Anthropic(api_key=api_key)
        return self._client

    def classify(
        self,
        finding: Finding,
        response_excerpt: str = "",
    ) -> LLMResult | None:
        """Classify a single finding.

        Returns ``None`` when the classifier is disabled or the API
        call fails. On failure the error is logged and audited but
        never raised, so a degraded LLM does not abort a scan.
        """
        if not self.config.enabled:
            return None

        client = self._ensure_client()
        user_content = self._build_user_content(finding, response_excerpt)

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
                        "text": _CLASSIFICATION_RULES,
                        "cache_control": {"type": "ephemeral"},
                    },
                ],
                messages=[{"role": "user", "content": user_content}],
                output_format=LLMVerdict,
            )
        except Exception as exc:  # network/parse failures are best-effort
            logger.warning(
                "llm.classify_failed",
                finding_id=str(finding.id),
                error=str(exc),
            )
            audit("llm.classify_failed", finding_id=str(finding.id), error=str(exc))
            return None

        verdict = response.parsed_output
        usage = _read_usage(response)
        audit(
            "llm.classified",
            finding_id=str(finding.id),
            true_positive=verdict.true_positive,
            cache_read_tokens=usage.cache_read_input_tokens,
            cache_creation_tokens=usage.cache_creation_input_tokens,
        )
        return LLMResult(verdict=verdict, usage=usage)

    def classify_batch(
        self,
        items: Iterable[tuple[Finding, str]],
    ) -> list[tuple[Finding, LLMResult | None]]:
        """Classify many findings sequentially. Returns input pairs."""
        out: list[tuple[Finding, LLMResult | None]] = []
        for finding, excerpt in items:
            out.append((finding, self.classify(finding, excerpt)))
        return out

    def _build_user_content(self, finding: Finding, response_excerpt: str) -> str:
        excerpt = (response_excerpt or "").strip()
        if len(excerpt) > self.config.response_excerpt_chars:
            excerpt = excerpt[: self.config.response_excerpt_chars] + "\n... (truncated)"
        return (
            f"Finding to classify:\n"
            f"- title: {finding.title}\n"
            f"- severity (claimed): {finding.severity.value}\n"
            f"- source: {finding.source.value}\n"
            f"- url: {finding.url}\n"
            f"- payload: {finding.payload or '(none)'}\n"
            f"- description: {finding.description or '(none)'}\n"
            f"- evidence keys: {sorted(finding.evidence.keys())}\n"
            f"\nResponse excerpt:\n```\n{excerpt or '(no excerpt available)'}\n```\n"
        )


def apply_verdict(finding: Finding, verdict: LLMVerdict) -> Finding:
    """Return a copy of ``finding`` enriched with the verdict.

    The original ``Finding`` is immutable in spirit (Pydantic model_copy
    produces a new instance). The refined title and contextual score
    are overwritten; severity is updated to the LLM's suggestion.
    """
    return finding.model_copy(
        update={
            "title": verdict.refined_title,
            "severity": Severity(verdict.suggested_severity),
            "contextual_score": round(verdict.confidence * 10.0, 2),
        }
    )


def _read_usage(
    response: Any,  # noqa: ANN401 - third-party SDK response
) -> LLMUsage:
    """Extract the usage block in a way that survives missing fields."""
    usage = getattr(response, "usage", None)
    if usage is None:
        return LLMUsage()
    return LLMUsage(
        input_tokens=getattr(usage, "input_tokens", 0) or 0,
        output_tokens=getattr(usage, "output_tokens", 0) or 0,
        cache_creation_input_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
        cache_read_input_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
    )


__all__ = [
    "LLMClassifier",
    "LLMConfig",
    "LLMResult",
    "LLMUsage",
    "LLMVerdict",
    "apply_verdict",
]
