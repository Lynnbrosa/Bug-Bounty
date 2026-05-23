"""Configuration loading.

Defines a typed configuration tree (Pydantic v2) that mirrors
``config/default.yaml`` and can be overridden via environment
variables prefixed with ``BOUNTY_AGENT_``. Nested fields use a double
underscore as separator (for example
``BOUNTY_AGENT_SCOPE__ALLOWLIST='[a.example,b.example]'``).

The CLI is the only caller that should reach for :func:`load_config`.
Subsystems receive plain dataclasses (FuzzerConfig, NucleiConfig,
ScopePolicy) built from the loaded Config so that they do not depend
on pydantic-settings.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from bounty_agent.core import ScopePolicy
from bounty_agent.fuzzing import FuzzerConfig
from bounty_agent.scanners import NucleiConfig

_DEFAULT_CONFIG_PATH = Path("config/default.yaml")


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AuthorizationConfig(_FrozenModel):
    acknowledged: bool = False
    program: str | None = None
    contact: str | None = None
    notes: str | None = None


class ScopeConfig(_FrozenModel):
    allowlist: tuple[str, ...] = ()
    path_denylist: tuple[str, ...] = (
        "/logout",
        "/admin/delete",
        "/api/v1/users/delete",
    )

    def as_policy(self) -> ScopePolicy:
        return ScopePolicy.from_iterables(list(self.allowlist), list(self.path_denylist))


class AgentConfig(_FrozenModel):
    min_delay_seconds: float = 1.0
    max_delay_seconds: float = 3.0
    max_requests_per_minute: int = 20
    request_timeout_seconds: float = 10.0
    user_agents_rotate: bool = True

    def as_fuzzer_config(self) -> FuzzerConfig:
        return FuzzerConfig(
            min_delay_seconds=self.min_delay_seconds,
            max_delay_seconds=self.max_delay_seconds,
            max_requests_per_minute=self.max_requests_per_minute,
            request_timeout_seconds=self.request_timeout_seconds,
            rotate_user_agents=self.user_agents_rotate,
        )


class NucleiSettings(_FrozenModel):
    enabled: bool = True
    binary: str = "nuclei"
    templates_path: str = "~/nuclei-templates"
    severity: tuple[str, ...] = ("critical", "high", "medium")
    concurrency: int = 1
    rate_limit: int = 10
    timeout_seconds: int = 600

    def as_nuclei_config(self) -> NucleiConfig:
        return NucleiConfig(
            binary=self.binary,
            templates_path=self.templates_path,
            severity=self.severity,
            concurrency=self.concurrency,
            rate_limit=self.rate_limit,
            timeout_seconds=self.timeout_seconds,
        )


class FuzzingSettings(_FrozenModel):
    enabled: bool = True
    max_endpoints: int = 25
    payloads_per_param: int = 5
    categories: tuple[str, ...] = ("sql_injection", "xss", "path_traversal")


class WafSettings(_FrozenModel):
    detect: bool = True


class ReportingSettings(_FrozenModel):
    output_dir: str = "reports"
    formats: tuple[str, ...] = ("text", "markdown", "json")


class PersistenceSettings(_FrozenModel):
    enabled: bool = True
    sqlite_path: str = "bounty.sqlite"


class LoggingSettings(_FrozenModel):
    level: str = "INFO"
    audit_log_path: str | None = "logs/audit.log"


class NotificationsSettings(_FrozenModel):
    enabled: bool = False
    webhook_url: str | None = None


class ToolsSettings(_FrozenModel):
    """Per-tool enable flags. Intrusive tools default off."""

    subfinder: bool = True
    waybackurls: bool = True
    httpx: bool = True
    dnsx: bool = False
    katana: bool = False
    naabu: bool = False


class ToolsCacheSettings(_FrozenModel):
    """Cache for passive tool output (subfinder, waybackurls)."""

    enabled: bool = True
    ttl_seconds: int = 21600  # 6 hours


class LLMSettings(_FrozenModel):
    """Optional Anthropic-API-backed post-processor for findings."""

    enabled: bool = False
    model: str = "claude-haiku-4-5"
    max_tokens: int = 1024
    response_excerpt_chars: int = 2000


class Config(BaseSettings):
    """Top-level configuration loaded from YAML and environment."""

    # NOTE on extra="ignore": with env_file=".env", pydantic-settings reads
    # every line of the dotenv file regardless of env_prefix. Under
    # extra="forbid", an unrelated key in .env (e.g. ANTHROPIC_API_KEY)
    # raises ValidationError, and the error payload echoes the value as
    # input_value — leaking the secret into logs and tracebacks. "ignore"
    # makes those keys pass silently. The tradeoff: typos in BOUNTY_AGENT_*
    # vars also pass silently. We rely on the YAML schema + tests for typo
    # detection instead.
    model_config = SettingsConfigDict(
        env_prefix="BOUNTY_AGENT_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    authorization: AuthorizationConfig = Field(default_factory=AuthorizationConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    nuclei: NucleiSettings = Field(default_factory=NucleiSettings)
    fuzzing: FuzzingSettings = Field(default_factory=FuzzingSettings)
    waf: WafSettings = Field(default_factory=WafSettings)
    reporting: ReportingSettings = Field(default_factory=ReportingSettings)
    persistence: PersistenceSettings = Field(default_factory=PersistenceSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    notifications: NotificationsSettings = Field(default_factory=NotificationsSettings)
    tools: ToolsSettings = Field(default_factory=ToolsSettings)
    tools_cache: ToolsCacheSettings = Field(default_factory=ToolsCacheSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Make env vars override values supplied via init kwargs (the YAML).

        Default precedence in pydantic-settings is init > env. We invert
        that so callers can keep a YAML on disk and still override single
        knobs from the shell, which matches the contract documented in
        the project guide.
        """
        _ = settings_cls
        return (env_settings, init_settings, dotenv_settings, file_secret_settings)

    @classmethod
    def from_yaml(cls, path: Path | str) -> Self:
        raw = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(raw) or {}
        if not isinstance(data, dict):
            raise ValueError(f"config YAML at {path} must be a mapping")
        return cls.model_validate(data)


def load_config(path: Path | str | None = None) -> Config:
    """Load configuration from YAML and overlay environment variables.

    Order of precedence (highest wins): env vars > YAML > defaults.
    """
    yaml_data: dict[str, object] = {}
    candidate = Path(path) if path else _resolve_default_path()
    if candidate is not None and candidate.exists():
        loaded = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"config YAML at {candidate} must be a mapping")
        yaml_data = loaded
    return Config(**yaml_data)  # type: ignore[arg-type]


def _resolve_default_path() -> Path | None:
    """Find a default config file using common locations."""
    env_path = os.environ.get("BOUNTY_AGENT_CONFIG")
    if env_path:
        return Path(env_path)
    cwd = Path.cwd()
    candidate = cwd / _DEFAULT_CONFIG_PATH
    if candidate.exists():
        return candidate
    return None


__all__ = [
    "AgentConfig",
    "AuthorizationConfig",
    "Config",
    "FuzzingSettings",
    "LLMSettings",
    "LoggingSettings",
    "NotificationsSettings",
    "NucleiSettings",
    "PersistenceSettings",
    "ReportingSettings",
    "ScopeConfig",
    "ToolsCacheSettings",
    "ToolsSettings",
    "WafSettings",
    "load_config",
]
