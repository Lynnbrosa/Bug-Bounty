"""Domain models for bounty-agent.

All public state of a scan is described here so that the JSON schema is
versioned and stable. Producers and consumers (scanners, fuzzers,
reports, the database, the CLI output) agree on this shape.

Changes to any field that already exists in a released schema version
require bumping ``SCHEMA_VERSION``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION: Literal["1"] = "1"


class Severity(StrEnum):
    """Standard severity ladder used across producers."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def base_score(self) -> float:
        """Numeric base score, mirrors the legacy mapping."""
        return {
            Severity.CRITICAL: 9.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 3.0,
            Severity.INFO: 1.0,
        }[self]


class FindingSource(StrEnum):
    """Where a finding came from."""

    NUCLEI = "nuclei"
    FUZZING = "fuzzing"
    WAF_DETECTION = "waf_detection"
    FINGERPRINT = "fingerprint"
    MANUAL = "manual"


def _utcnow() -> datetime:
    """Timezone-aware UTC now. Centralised so we can stub it in tests."""
    return datetime.now(UTC)


class StrictModel(BaseModel):
    """Base model with strict defaults: no extras, frozen by default."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=False,
        populate_by_name=True,
        ser_json_timedelta="iso8601",
    )


class Finding(StrictModel):
    """A single security observation produced by any subsystem."""

    id: UUID = Field(default_factory=uuid4)
    url: AnyHttpUrl
    source: FindingSource
    severity: Severity
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    payload: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=_utcnow)
    contextual_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="Optional contextual score from scoring/impact.py.",
    )

    @field_validator("title")
    @classmethod
    def _strip_title(cls, value: str) -> str:
        return value.strip()


class WafDetection(StrictModel):
    """Result of the WAF detection step."""

    detected_vendors: list[str] = Field(default_factory=list)
    likely_protected: bool = False
    status_code: int | None = None
    error: str | None = None


class TargetContext(StrictModel):
    """Operator-supplied context that influences scoring and reporting."""

    program: str | None = None
    contact: str | None = None
    is_production: bool = False
    requires_auth: bool = False
    affects_pii: bool = False
    affects_payment: bool = False
    notes: str | None = None


class ScanResult(StrictModel):
    """Top-level result envelope for a scan run."""

    schema_version: Literal["1"] = SCHEMA_VERSION
    scan_id: UUID = Field(default_factory=uuid4)
    target: AnyHttpUrl
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime | None = None
    target_context: TargetContext = Field(default_factory=TargetContext)
    waf_detection: WafDetection = Field(default_factory=WafDetection)
    endpoints: list[AnyHttpUrl] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    def counts_by_severity(self) -> dict[Severity, int]:
        counts = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def findings_by_source(self, source: FindingSource) -> list[Finding]:
        return [f for f in self.findings if f.source == source]


__all__ = [
    "SCHEMA_VERSION",
    "Finding",
    "FindingSource",
    "ScanResult",
    "Severity",
    "StrictModel",
    "TargetContext",
    "WafDetection",
]
