"""Tests for the payload registry."""

from __future__ import annotations

from pathlib import Path

import pytest

from bounty_agent.fuzzing import PayloadRegistry


def test_from_mapping_normalises_keys() -> None:
    registry = PayloadRegistry.from_mapping(
        {"SQL_Injection": ["a", "b"], "xss": ("c",)}
    )
    assert set(registry.categories()) == {"sql_injection", "xss"}
    assert registry.get("sql_injection") == ("a", "b")
    assert registry.get("XSS") == ("c",)


def test_from_mapping_drops_empty_payloads() -> None:
    registry = PayloadRegistry.from_mapping({"sql_injection": ["a", "", "b", None]})  # type: ignore[list-item]
    assert registry.get("sql_injection") == ("a", "b")


def test_unknown_category_returns_empty_tuple() -> None:
    registry = PayloadRegistry.from_mapping({"sql_injection": ["a"]})
    assert registry.get("not-a-category") == ()


def test_from_yaml_loads_defaults(tmp_path: Path) -> None:
    yaml_text = (
        "sql_injection:\n"
        "  - \"' OR '1'='1\"\n"
        "  - admin' --\n"
        "xss:\n"
        "  - <script>x</script>\n"
    )
    path = tmp_path / "payloads.yaml"
    path.write_text(yaml_text, encoding="utf-8")

    registry = PayloadRegistry.from_yaml(path)
    assert registry.get("sql_injection") == ("' OR '1'='1", "admin' --")
    assert registry.get("xss") == ("<script>x</script>",)


def test_from_yaml_rejects_non_mapping(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text("- one\n- two\n", encoding="utf-8")
    with pytest.raises(ValueError):
        PayloadRegistry.from_yaml(path)


def test_with_overrides_creates_new_registry() -> None:
    base = PayloadRegistry.from_mapping({"sql_injection": ["a"]})
    new = base.with_overrides({"sql_injection": ["b", "c"]})
    assert base.get("sql_injection") == ("a",)
    assert new.get("sql_injection") == ("b", "c")


def test_repository_default_yaml_is_loadable() -> None:
    """The packaged config/payloads.yaml must always parse cleanly."""
    project_root = Path(__file__).resolve().parents[2]
    registry = PayloadRegistry.from_yaml(project_root / "config" / "payloads.yaml")
    assert "sql_injection" in registry.categories()
    assert "xss" in registry.categories()
