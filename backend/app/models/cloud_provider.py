"""CloudProvider ORM model.

Represents a cloud provider account or project that has been registered
for IP discovery and scanning.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class CloudProvider(Base):
    __tablename__ = "cloud_providers"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    provider_type: Mapped[str] = mapped_column(
        String(32), nullable=False, comment="aws | azure | gcp | oci",
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    regions: Mapped[list[str] | None] = mapped_column(
        String(1024), nullable=True,
        comment="Comma-separated list of regions to scan",
    )
    metadata_: Mapped[dict | None] = mapped_column(
        "metadata", String(2048), nullable=True,
        comment="JSON-encoded provider metadata",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False,
    )

    # ── Relationships ────────────────────────────────────────────
    credentials: Mapped[list["CloudCredential"]] = relationship(  # noqa: F821
        "CloudCredential", back_populates="cloud_provider", cascade="all, delete-orphan",
    )
    ip_addresses: Mapped[list["IPAddress"]] = relationship(  # noqa: F821
        "IPAddress", back_populates="cloud_provider", cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<CloudProvider id={self.id} name={self.name!r} type={self.provider_type}>"
