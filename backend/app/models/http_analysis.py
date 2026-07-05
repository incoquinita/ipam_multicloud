"""HttpAnalysis ORM model.

Captures the result of an HTTP/HTTPS analysis performed on an open port.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class HttpAnalysis(Base):
    __tablename__ = "http_analyses"

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
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_static: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    has_login: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    has_rate_limit: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    response_headers: Mapped[dict | None] = mapped_column(JSONB, nullable=True, default=dict)
    technologies: Mapped[list[str] | None] = mapped_column(
        JSONB, nullable=True, default=list,
    )
    certificates: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True, default=dict,
        comment="TLS certificate info in JSON",
    )
    security_headers: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True, default=dict,
        comment="Present security headers and their values",
    )
    security_headers_score: Mapped[int | None] = mapped_column(
        Integer, nullable=True,
        comment="Security header compliance score (0-10)",
    )
    tls_version: Mapped[str | None] = mapped_column(
        String(32), nullable=True,
        comment="Negotiated TLS protocol version",
    )
    title: Mapped[str | None] = mapped_column(
        String(512), nullable=True,
        comment="HTML title tag content",
    )
    static_evidence: Mapped[list[str] | None] = mapped_column(
        JSONB, nullable=True, default=list,
        comment="Probe response evidence for static classification",
    )
    login_evidence: Mapped[list[str] | None] = mapped_column(
        JSONB, nullable=True, default=list,
        comment="Signals that triggered login-page detection",
    )
    rate_limit_details: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True, default=dict,
        comment="Burst probe results including status codes and timings",
    )
    analyzed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    # ── Relationships ────────────────────────────────────────────
    scan_job: Mapped[ScanJob] = relationship(  # noqa: F821
        "ScanJob", back_populates="http_analyses",
    )
    ip_address: Mapped[IPAddress] = relationship(  # noqa: F821
        "IPAddress", back_populates="http_analyses",
    )

    def __repr__(self) -> str:
        return f"<HttpAnalysis id={self.id} url={self.url!r} status={self.status_code}>"
