"""ScanJob ORM model.

Tracks the lifecycle of a single scan execution — from submission
through queuing, running, completion, or failure.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_targets.id", ondelete="CASCADE"),
        nullable=False,
    )
    scan_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="quick",
        comment="quick | standard | thorough | custom",
    )
    profile: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="pending",
        comment="pending | queued | running | completed | failed | cancelled",
    )
    progress: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    config: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True, default=dict,
        comment="Scan configuration overrides",
    )
    total_ips: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    ips_scanned: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    ports_found: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    findings_critical: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=0,
    )
    findings_high: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    findings_medium: Mapped[int] = mapped_column(default=0, server_default="0")
    findings_low: Mapped[int] = mapped_column(default=0, server_default="0")
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    duration_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    celery_task_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True,
        comment="Celery task ID for tracking",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False,
    )

    # ── Relationships ────────────────────────────────────────────
    target: Mapped["ScanTarget"] = relationship(  # noqa: F821
        "ScanTarget", back_populates="scan_jobs",
    )
    port_results: Mapped[list["PortResult"]] = relationship(  # noqa: F821
        "PortResult", back_populates="scan_job", cascade="all, delete-orphan",
    )
    http_analyses: Mapped[list["HttpAnalysis"]] = relationship(  # noqa: F821
        "HttpAnalysis", back_populates="scan_job", cascade="all, delete-orphan",
    )
    events: Mapped[list["ScanEvent"]] = relationship(  # noqa: F821
        "ScanEvent", back_populates="scan_job", cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return (
            f"<ScanJob id={self.id} "
            f"type={self.scan_type!r} "
            f"status={self.status!r}>"
        )
