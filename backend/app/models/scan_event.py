"""ScanEvent ORM model.

Append-only event log for a scan job — tracks state transitions,
progress updates, warnings, and errors.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(
        String(64), nullable=False,
        comment="progress | status_change | warning | error | info",
    )
    message: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_: Mapped[dict | None] = mapped_column(
        "metadata", JSONB, nullable=True, default=dict,
        comment="Arbitrary event payload",
    )
    progress: Mapped[float | None] = mapped_column(
        Integer, nullable=True,
        comment="Progress percentage at the time of this event",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    # ── Relationships ────────────────────────────────────────────
    scan_job: Mapped["ScanJob"] = relationship(  # noqa: F821
        "ScanJob", back_populates="events",
    )

    def __repr__(self) -> str:
        return (
            f"<ScanEvent id={self.id} "
            f"job_id={self.scan_job_id} "
            f"type={self.event_type!r}>"
        )
