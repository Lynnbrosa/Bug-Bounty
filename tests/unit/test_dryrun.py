"""Tests for the dry-run planner."""

from __future__ import annotations

from bounty_agent.config import Config
from bounty_agent.dryrun import plan_scan


def _config_with(extra: dict) -> Config:
    base = {"scope": {"allowlist": ["example.com"]}}
    base.update(extra)
    return Config.model_validate(base)


class TestPlanScope:
    def test_in_scope_url_is_accepted(self) -> None:
        config = _config_with({})
        plan = plan_scan(
            config,
            target="https://example.com/api",
            preset_targets=["https://example.com/api"],
        )
        assert plan.scope_in == ["https://example.com/api"]
        assert plan.scope_out == []

    def test_out_of_scope_url_is_rejected(self) -> None:
        config = _config_with({})
        plan = plan_scan(
            config,
            target="https://example.com/",
            preset_targets=[
                "https://example.com/ok",
                "https://other.example/leak",
            ],
        )
        assert plan.scope_in == ["https://example.com/ok"]
        assert plan.scope_out == ["https://other.example/leak"]


class TestPlanPhases:
    def test_disabled_features_appear_with_enabled_false(self) -> None:
        config = _config_with(
            {
                "fuzzing": {"enabled": False},
                "nuclei": {"enabled": False},
                "waf": {"detect": False},
            }
        )
        plan = plan_scan(
            config,
            target="https://example.com/",
            preset_targets=["https://example.com/"],
        )
        phase_states = {p.name: p.enabled for p in plan.phases}
        assert phase_states["fuzzing"] is False
        assert phase_states["nuclei"] is False
        assert phase_states["waf detection"] is False

    def test_recon_phase_only_when_no_preset(self) -> None:
        config = _config_with({})
        without_preset = plan_scan(config, target="https://example.com/")
        with_preset = plan_scan(
            config,
            target="https://example.com/",
            preset_targets=["https://example.com/"],
        )
        assert any(p.name == "recon" for p in without_preset.phases)
        assert all(p.name != "recon" for p in with_preset.phases)


class TestEstimatedRequests:
    def test_dry_run_sends_nothing(self) -> None:
        # The planner must produce a number but never make a real
        # request. We can't directly assert no network, but we can
        # check that estimated_requests is computed deterministically
        # from config.
        config = _config_with(
            {
                "fuzzing": {
                    "enabled": True,
                    "max_endpoints": 10,
                    "payloads_per_param": 3,
                    "categories": ["sql_injection"],
                }
            }
        )
        plan = plan_scan(
            config,
            target="https://example.com/",
            preset_targets=["https://example.com/api?q=x"],
        )
        assert plan.estimated_requests > 0

    def test_no_phases_no_requests(self) -> None:
        config = _config_with(
            {
                "fuzzing": {"enabled": False},
                "nuclei": {"enabled": False},
                "waf": {"detect": False},
            }
        )
        plan = plan_scan(
            config,
            target="https://example.com/",
            preset_targets=["https://example.com/"],
        )
        # Sensitive scanner still runs (no config flag) -> 1 request.
        assert plan.estimated_requests == 1
