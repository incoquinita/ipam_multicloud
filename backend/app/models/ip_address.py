"""IPAddress ORM model.

Discovered IP addresses — either from cloud provider API enumeration or
from user-provided targets.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class IPAddress(Base):
    __tablename__ = "ip_addresses"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    cloud_provider_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cloud_providers.id", ondelete="SET NULL"),
        nullable=True,
    )
    resource_id: Mapped[str | None] = mapped_column(
        String(256), nullable=True,
        comment="Cloud provider resource ID (e.g. EC2 instance ID)",
    )
    resource_type: Mapped[str | None] = mapped_column(
        String(64), nullable=True,
        comment="Type of resource (instance, load_balancer, etc.)",
    )
    ip_address: Mapped[str] = mapped_column(
        String(45), nullable=False, index=True,
        comment="IP address as string (IPv4/IPv6); migration to INET later",
    )
    private_ip: Mapped[str | None] = mapped_column(
        String(45), nullable=True, comment="Private IP if applicable",
    )
    region: Mapped[str | None] = mapped_column(
        String(64), nullable=True, comment="Cloud provider region",
    )
    tags: Mapped[dict | None] = mapped_column(JSONB, nullable=True, default=dict)
    is_alive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(256), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    # ── Relationships ────────────────────────────────────────────
    cloud_provider: Mapped["CloudProvider | None"] = relationship(  # noqa: F821
        "CloudProvider", back_populates="ip_addresses",
    )
    port_results: Mapped[list["PortResult"]] = relationship(  # noqa: F821
        "PortResult", back_populates="ip_address", cascade="all, delete-orphan",
    )
    http_analyses: Mapped[list["HttpAnalysis"]] = relationship(  # noqa: F821
        "HttpAnalysis", back_populates="ip_address", cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<IPAddress id={self.id} ip={self.ip_address!r}>"
