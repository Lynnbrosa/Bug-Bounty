"""Tests for the scope guard."""

from __future__ import annotations

import pytest

from bounty_agent.core import ScopePolicy, ScopeViolation


class TestEmptyAllowlist:
    def test_empty_allowlist_denies_everything(self) -> None:
        policy = ScopePolicy.from_iterables([])
        decision = policy.evaluate("https://example.com/")
        assert decision.denied
        assert "allowlist is empty" in decision.reason

    def test_check_raises_on_empty_allowlist(self) -> None:
        policy = ScopePolicy.from_iterables([])
        with pytest.raises(ScopeViolation):
            policy.check("https://example.com/")


class TestHostMatching:
    def test_exact_host_match(self) -> None:
        policy = ScopePolicy.from_iterables(["api.example.com"])
        assert policy.evaluate("https://api.example.com/path").allowed

    def test_host_matching_is_case_insensitive(self) -> None:
        policy = ScopePolicy.from_iterables(["API.Example.com"])
        assert policy.evaluate("https://api.example.com/").allowed
        assert policy.evaluate("https://API.EXAMPLE.COM/").allowed

    def test_wildcard_matches_subdomains_only(self) -> None:
        policy = ScopePolicy.from_iterables(["*.example.com"])
        assert policy.evaluate("https://api.example.com/").allowed
        assert policy.evaluate("https://deep.api.example.com/").allowed
        assert not policy.evaluate("https://example.com/").allowed

    def test_wildcard_does_not_match_unrelated_host(self) -> None:
        policy = ScopePolicy.from_iterables(["*.example.com"])
        assert not policy.evaluate("https://api.evil.com/").allowed
        assert not policy.evaluate("https://example.com.evil.com/").allowed

    def test_unknown_host_is_denied(self) -> None:
        policy = ScopePolicy.from_iterables(["api.example.com"])
        decision = policy.evaluate("https://other.example.com/")
        assert decision.denied
        assert "not in allowlist" in decision.reason


class TestPathDenylist:
    def test_path_prefix_denied(self) -> None:
        policy = ScopePolicy.from_iterables(
            ["example.com"], path_denylist=["/admin"]
        )
        assert policy.evaluate("https://example.com/admin").denied
        assert policy.evaluate("https://example.com/admin/users").denied
        assert policy.evaluate("https://example.com/public").allowed

    def test_path_denylist_does_not_match_substrings(self) -> None:
        policy = ScopePolicy.from_iterables(
            ["example.com"], path_denylist=["/admin"]
        )
        assert policy.evaluate("https://example.com/administrator").allowed


class TestSchemeAndShape:
    def test_non_http_scheme_denied(self) -> None:
        policy = ScopePolicy.from_iterables(["example.com"])
        assert policy.evaluate("ftp://example.com/").denied
        assert policy.evaluate("file:///etc/passwd").denied

    def test_missing_hostname_denied(self) -> None:
        policy = ScopePolicy.from_iterables(["example.com"])
        assert policy.evaluate("http:///path").denied


class TestImmutability:
    def test_policy_is_frozen(self) -> None:
        policy = ScopePolicy.from_iterables(["example.com"])
        with pytest.raises(Exception):  # noqa: B017 - frozen dataclass raises
            policy.allowlist = ("other.com",)  # type: ignore[misc]
