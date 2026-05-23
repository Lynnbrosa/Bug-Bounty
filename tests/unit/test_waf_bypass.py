"""Tests for the educational encoding variants helper."""

from __future__ import annotations

from bounty_agent.fuzzing.waf_bypass import encoding_variants


def test_original_payload_first() -> None:
    variants = encoding_variants("' OR '1'='1")
    assert variants[0] == "' OR '1'='1"


def test_variants_are_deduplicated() -> None:
    variants = encoding_variants("abc")
    assert len(variants) == len(set(variants))


def test_url_encoded_variant_present() -> None:
    variants = encoding_variants("<script>")
    assert "%3Cscript%3E" in variants


def test_html_entity_variant_present() -> None:
    variants = encoding_variants("ab")
    assert any("&#97" in v for v in variants)
