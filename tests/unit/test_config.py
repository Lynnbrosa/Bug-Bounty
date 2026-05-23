"""Tests for the configuration loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from bounty_agent.config import Config, load_config


def _write_yaml(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(__import__("os").environ):
        if key.startswith("BOUNTY_AGENT_"):
            monkeypatch.delenv(key, raising=False)


def test_defaults_load_when_no_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = load_config()
    assert config.scope.allowlist == ()
    assert config.agent.max_requests_per_minute == 20


def test_yaml_overrides_defaults(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    _write_yaml(
        path,
        "agent:\n  max_requests_per_minute: 5\nscope:\n  allowlist: [a.example, b.example]\n",
    )
    config = load_config(path)
    assert config.agent.max_requests_per_minute == 5
    assert config.scope.allowlist == ("a.example", "b.example")


def test_env_overrides_yaml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.yaml"
    _write_yaml(path, "agent:\n  max_requests_per_minute: 5\n")
    monkeypatch.setenv("BOUNTY_AGENT_AGENT__MAX_REQUESTS_PER_MINUTE", "7")
    config = load_config(path)
    assert config.agent.max_requests_per_minute == 7


def test_scope_config_to_policy(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    _write_yaml(
        path,
        "scope:\n  allowlist: [example.com]\n  path_denylist: [/admin]\n",
    )
    config = load_config(path)
    policy = config.scope.as_policy()
    assert policy.evaluate("https://example.com/").allowed
    assert policy.evaluate("https://example.com/admin/users").denied


def test_agent_config_to_fuzzer_config() -> None:
    config = Config()
    fuzzer_config = config.agent.as_fuzzer_config()
    assert fuzzer_config.max_requests_per_minute == config.agent.max_requests_per_minute


def test_nuclei_settings_to_nuclei_config() -> None:
    config = Config()
    nuclei_config = config.nuclei.as_nuclei_config()
    assert nuclei_config.binary == config.nuclei.binary
    assert nuclei_config.severity == config.nuclei.severity


def test_repository_default_yaml_is_loadable() -> None:
    project_root = Path(__file__).resolve().parents[2]
    config = Config.from_yaml(project_root / "config" / "default.yaml")
    # default.yaml ships with an empty allowlist by design
    assert config.scope.allowlist == ()
    assert config.authorization.acknowledged is False


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    _write_yaml(path, "- one\n- two\n")
    with pytest.raises(ValueError):
        load_config(path)


def test_unknown_field_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "extra.yaml"
    _write_yaml(path, "unknown_section:\n  foo: bar\n")
    with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError
        load_config(path)


def test_env_config_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "alt.yaml"
    _write_yaml(path, "agent:\n  max_requests_per_minute: 99\n")
    monkeypatch.setenv("BOUNTY_AGENT_CONFIG", str(path))
    monkeypatch.chdir(tmp_path)
    config = load_config()
    assert config.agent.max_requests_per_minute == 99
