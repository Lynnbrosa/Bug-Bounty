"""Tests for the CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bounty_agent.cli import app

runner = CliRunner()


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "bounty-agent" in result.stdout


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert result.exit_code != 0
    assert "scan" in result.stdout
    assert "legacy-scan" in result.stdout


def test_scan_without_authorized_refuses() -> None:
    result = runner.invoke(app, ["scan", "https://example.com/"])
    assert result.exit_code == 2
    assert "Refusing to scan" in (result.stdout + result.stderr)


def test_scan_with_empty_allowlist_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("scope:\n  allowlist: []\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        ["scan", "https://example.com/", "--config", str(config), "--authorized"],
    )
    assert result.exit_code == 3
    assert "allowlist is empty" in (result.stdout + result.stderr)


def test_schema_command_prints_versioned_schema() -> None:
    result = runner.invoke(app, ["schema"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "ScanResult" in payload["title"]
    assert payload["$id"].endswith(".json")


def test_init_config_writes_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    destination = tmp_path / "my-config.yaml"
    result = runner.invoke(app, ["init-config", "--destination", str(destination)])
    assert result.exit_code == 0, result.stdout + result.stderr
    assert destination.exists()
    content = destination.read_text(encoding="utf-8")
    assert "scope:" in content


def test_init_config_refuses_to_overwrite_without_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    destination = tmp_path / "my-config.yaml"
    destination.write_text("existing", encoding="utf-8")
    result = runner.invoke(app, ["init-config", "--destination", str(destination)])
    assert result.exit_code == 2
    assert destination.read_text(encoding="utf-8") == "existing"


def test_audit_missing_log_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "config.yaml"
    config.write_text('logging:\n  audit_log_path: "missing.log"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["audit", "--config", str(config)])
    assert result.exit_code == 2
    assert "not found" in (result.stdout + result.stderr)


def test_scan_targets_file_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("scope:\n  allowlist: [example.com]\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com/",
            "--config",
            str(config),
            "--authorized",
            "--targets-file",
            str(tmp_path / "missing.txt"),
        ],
    )
    assert result.exit_code == 2
    assert "Targets file not found" in (result.stdout + result.stderr)


def test_scan_targets_file_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("scope:\n  allowlist: [example.com]\n", encoding="utf-8")
    empty = tmp_path / "urls.txt"
    empty.write_text("# only comments\n\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com/",
            "--config",
            str(config),
            "--authorized",
            "--targets-file",
            str(empty),
        ],
    )
    assert result.exit_code == 2
    assert "empty" in (result.stdout + result.stderr).lower()


def test_recon_refuses_without_authorized() -> None:
    result = runner.invoke(app, ["recon", "https://example.com/"])
    assert result.exit_code == 2
    assert "Refusing to scan" in (result.stdout + result.stderr)


def test_recon_refuses_empty_allowlist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("scope:\n  allowlist: []\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        ["recon", "https://example.com/", "--config", str(config), "--authorized"],
    )
    assert result.exit_code == 3
    assert "allowlist is empty" in (result.stdout + result.stderr)


def test_recon_runs_and_writes_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # No external binaries installed in the test env, so the pipeline
    # collects skip errors but exits cleanly.
    config = tmp_path / "config.yaml"
    config.write_text(
        "scope:\n  allowlist: [example.com]\n"
        "tools:\n  subfinder: true\n  waybackurls: false\n"
        "  httpx: false\n  dnsx: false\n  katana: false\n  naabu: false\n",
        encoding="utf-8",
    )
    output = tmp_path / "recon.json"
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        [
            "recon",
            "https://example.com/",
            "--config",
            str(config),
            "--authorized",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert output.exists()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["target"] == "https://example.com/"
    assert "subdomains" in payload
    assert "urls" in payload


def test_tools_list_renders_all_known_tools() -> None:
    result = runner.invoke(app, ["tools", "list"])
    assert result.exit_code == 0
    for name in ("subfinder", "waybackurls", "httpx", "dnsx", "katana", "naabu"):
        assert name in result.stdout


def test_tools_run_refuses_without_authorized() -> None:
    result = runner.invoke(app, ["tools", "run", "subfinder", "example.com"])
    assert result.exit_code == 2
    assert "Refusing to scan" in (result.stdout + result.stderr)


def test_tools_run_refuses_unknown_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["tools", "run", "not-a-tool", "example.com", "--authorized"])
    assert result.exit_code == 2
    assert "unknown tool" in (result.stdout + result.stderr)


def test_audit_reads_log_lines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit_log = tmp_path / "logs" / "audit.log"
    audit_log.parent.mkdir(parents=True)
    audit_log.write_text(
        '{"event":"scan.started","target":"https://e.example/"}\n', encoding="utf-8"
    )
    config = tmp_path / "config.yaml"
    config.write_text(f'logging:\n  audit_log_path: "{audit_log.as_posix()}"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["audit", "--config", str(config), "--tail", "5"])
    assert result.exit_code == 0
    assert "scan.started" in result.stdout
