"""SQLAlchemy 2.0 ORM models for scan history."""

from datetime import datetime

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for the persistence layer."""


class ScanRow(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target: Mapped[str] = mapped_column(String(2048), index=True)
    schema_version: Mapped[str] = mapped_column(String(8))
    program: Mapped[str | None] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime] = mapped_column(index=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    raw_json: Mapped[str] = mapped_column(Text)

    findings: Mapped[list["FindingRow"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    source: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    contextual_score: Mapped[float | None] = mapped_column(nullable=True)
    discovered_at: Mapped[datetime]
    evidence_json: Mapped[str] = mapped_column(Text, default="{}")

    scan: Mapped[ScanRow] = relationship(back_populates="findings")


class ToolCacheRow(Base):
    """Per-(tool, target) cache of passive recon output."""

    __tablename__ = "tool_cache"

    tool: Mapped[str] = mapped_column(String(64), primary_key=True)
    target: Mapped[str] = mapped_column(String(512), primary_key=True)
    items_json: Mapped[str] = mapped_column(Text)
    cached_at: Mapped[datetime] = mapped_column(index=True)
    ttl_seconds: Mapped[int]


__all__ = ["Base", "FindingRow", "ScanRow", "ToolCacheRow"]
