"""ScanTarget ORM model.

Represents a logical target grouping for scanning — could be a CIDR
range, a list of individual IPs, or a cloud provider resource group.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class ScanTarget(Base):
    __tablename__ = "scan_targets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="cidr",
        comment="cidr | ip_list | cloud_provider | hostname",
    )
    target_value: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="CIDR notation, comma-separated IPs, cloud provider ID, or hostname",
    )
    ports: Mapped[list[int] | None] = mapped_column(
        JSONB, nullable=True, default=list,
        comment="List of ports to scan (None = common ports)",
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    tags: Mapped[dict | None] = mapped_column(JSONB, nullable=True, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False,
    )

    # ── Relationships ────────────────────────────────────────────
    scan_jobs: Mapped[list["ScanJob"]] = relationship(  # noqa: F821
        "ScanJob", back_populates="target", cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<ScanTarget id={self.id} name={self.name!r} type={self.target_type}>"
