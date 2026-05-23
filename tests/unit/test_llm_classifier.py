"""Tests for the LLM post-processor."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from bounty_agent.core import Finding, FindingSource, Severity
from bounty_agent.llm import (
    LLMClassifier,
    LLMConfig,
    LLMVerdict,
    apply_verdict,
)


def _finding() -> Finding:
    return Finding(
        url="https://example.com/api/search?q=test",
        source=FindingSource.FUZZING,
        severity=Severity.HIGH,
        title="Possible SQL injection",
        description="DB error reflected in body.",
        payload="' OR '1'='1",
        evidence={"matched_marker": "MySQL"},
    )


@dataclass
class _FakeUsage:
    input_tokens: int = 200
    output_tokens: int = 80
    cache_creation_input_tokens: int = 600
    cache_read_input_tokens: int = 0


@dataclass
class _FakeResponse:
    parsed_output: LLMVerdict
    usage: _FakeUsage


class _FakeMessages:
    def __init__(self, verdict: LLMVerdict, usage: _FakeUsage | None = None) -> None:
        self.verdict = verdict
        self.usage = usage or _FakeUsage()
        self.last_request: dict[str, Any] | None = None

    def parse(self, **kwargs: Any) -> _FakeResponse:
        self.last_request = kwargs
        return _FakeResponse(parsed_output=self.verdict, usage=self.usage)


class _FakeAnthropic:
    def __init__(self, verdict: LLMVerdict, usage: _FakeUsage | None = None) -> None:
        self.messages = _FakeMessages(verdict, usage)


class TestDisabledClassifier:
    def test_returns_none_when_disabled(self) -> None:
        classifier = LLMClassifier(LLMConfig(enabled=False))
        assert classifier.classify(_finding(), "body") is None


class TestSuccessPath:
    def test_returns_verdict_and_usage(self) -> None:
        verdict = LLMVerdict(
            true_positive=True,
            refined_title="SQL injection confirmed via DB error reflection",
            suggested_severity="high",
            reasoning="Body contains a MariaDB syntax error in response to the payload.",
            confidence=0.85,
        )
        client = _FakeAnthropic(verdict)
        classifier = LLMClassifier(LLMConfig(enabled=True), client=client)
        result = classifier.classify(_finding(), "You have an error in your SQL syntax")
        assert result is not None
        assert result.verdict.true_positive is True
        assert result.verdict.refined_title.startswith("SQL injection")
        assert result.usage.cache_creation_input_tokens == 600

    def test_request_uses_cache_control_on_system_prompt(self) -> None:
        verdict = LLMVerdict(
            true_positive=False,
            refined_title="Not exploitable",
            suggested_severity="info",
            reasoning="No error markers in response.",
            confidence=0.7,
        )
        client = _FakeAnthropic(verdict)
        classifier = LLMClassifier(LLMConfig(enabled=True), client=client)
        classifier.classify(_finding(), "ok")

        req = client.messages.last_request
        assert req is not None
        system_blocks = req["system"]
        # both system blocks must carry cache_control so the prefix is cacheable
        for block in system_blocks:
            assert block["cache_control"] == {"type": "ephemeral"}
        assert req["model"] == "claude-haiku-4-5"
        # Pydantic schema is forwarded via output_format helper
        assert req["output_format"] is LLMVerdict


class TestErrorHandling:
    def test_returns_none_when_api_raises(self) -> None:
        class _BoomMessages:
            def parse(self, **_kwargs: Any) -> None:
                raise RuntimeError("network down")

        class _BoomClient:
            messages = _BoomMessages()

        classifier = LLMClassifier(LLMConfig(enabled=True), client=_BoomClient())
        assert classifier.classify(_finding(), "body") is None


class TestExcerptTruncation:
    def test_long_excerpt_is_truncated(self) -> None:
        verdict = LLMVerdict(
            true_positive=False,
            refined_title="No reflection",
            suggested_severity="info",
            reasoning="r",
            confidence=0.1,
        )
        client = _FakeAnthropic(verdict)
        classifier = LLMClassifier(
            LLMConfig(enabled=True, response_excerpt_chars=100),
            client=client,
        )
        long_body = "A" * 1000
        classifier.classify(_finding(), long_body)
        user_msg = client.messages.last_request["messages"][0]["content"]
        assert "truncated" in user_msg
        assert "A" * 1000 not in user_msg


class TestApplyVerdict:
    def test_apply_verdict_rewrites_finding(self) -> None:
        verdict = LLMVerdict(
            true_positive=True,
            refined_title="Stored XSS in profile bio",
            suggested_severity="critical",
            reasoning="Payload persisted in profile page HTML.",
            confidence=0.95,
        )
        before = _finding()
        after = apply_verdict(before, verdict)
        assert after.title == "Stored XSS in profile bio"
        assert after.severity is Severity.CRITICAL
        assert after.contextual_score == 9.5
        # original is untouched
        assert before.title == "Possible SQL injection"
        assert before.severity is Severity.HIGH


class TestMissingApiKey:
    def test_raises_when_no_key_and_no_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        classifier = LLMClassifier(LLMConfig(enabled=True))
        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
            classifier.classify(_finding(), "body")
