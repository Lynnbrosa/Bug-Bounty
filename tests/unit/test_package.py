"""Smoke tests for package wiring."""

from __future__ import annotations

import bounty_agent
from bounty_agent.cli import app


def test_version_string_is_present() -> None:
    assert isinstance(bounty_agent.__version__, str)
    assert bounty_agent.__version__


def test_cli_app_has_expected_commands() -> None:
    command_names = {cmd.name for cmd in app.registered_commands}
    assert "legacy-scan" in command_names
    assert "scan" in command_names
