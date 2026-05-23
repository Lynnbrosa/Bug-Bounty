"""Eval harness tests against the bundled golden dataset."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from bounty_agent.cli import app
from bounty_agent.eval import evaluate, load_cases


def _dataset_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "golden"


def test_load_cases_all_valid() -> None:
    cases = load_cases(_dataset_dir())
    assert len(cases) >= 8  # the bundled set we ship in this commit
    ids = {c.id for c in cases}
    assert "sqli-mysql-error" in ids
    assert "xss-reflected-html" in ids


def test_evaluate_meets_thresholds() -> None:
    """The shipped analyzers must hit the bundled dataset cleanly.

    If a future patch regresses this, the test catches it immediately.
    """
    cases = load_cases(_dataset_dir())
    report = evaluate(cases)
    assert report.failures == []  # no missed TPs, no FP regressions
    assert report.overall.precision >= 1.0
    assert report.overall.recall >= 1.0
    assert report.overall.f1 >= 1.0


def test_cli_eval_prints_table() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["eval"])
    assert result.exit_code == 0, result.stdout + result.stderr
    assert "Golden eval" in result.stdout
    assert "OVERALL" in result.stdout
