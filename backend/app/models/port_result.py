"""PortResult ORM model.

Stores the outcome of a single port scan against a single IP address.
"""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class PortResult(Base):
    __tablename__ = "port_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    ip_address_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ip_addresses.id", ondelete="CASCADE"),
        nullable=False,
    )
    port: Mapped[int] = mapped_column(
        Integer, nullable=False,
    )
    protocol: Mapped[str] = mapped_column(String(16), default="tcp", nullable=False)
    state: Mapped[str] = mapped_column(
        String(32), nullable=False,
        comment="open | closed | filtered | unfiltered",
    )
    service_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    service_product: Mapped[str | None] = mapped_column(String(256), nullable=True)
    service_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(
        String(16), nullable=True,
        comment="critical | high | medium | low | info",
    )
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cve_ids: Mapped[list[str] | None] = mapped_column(
        JSONB, nullable=True, default=list,
        comment="List of related CVE identifiers",
    )
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    # ── Table constraints ────────────────────────────────────────
    __table_args__ = (
        CheckConstraint("port >= 1 AND port <= 65535", name="ck_port_result_port_range"),
    )

    # ── Relationships ────────────────────────────────────────────
    scan_job: Mapped["ScanJob"] = relationship(  # noqa: F821
        "ScanJob", back_populates="port_results",
    )
    ip_address: Mapped["IPAddress"] = relationship(  # noqa: F821
        "IPAddress", back_populates="port_results",
    )

    def __repr__(self) -> str:
        return (
            f"<PortResult id={self.id} "
            f"port={self.port}/{self.protocol} "
            f"state={self.state!r}>"
        )
