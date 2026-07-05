"""CloudCredential ORM model.

Stores encrypted credentials for each cloud provider.  The actual secret
values should be encrypted at the application layer before insertion.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class CloudCredential(Base):
    __tablename__ = "cloud_credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    cloud_provider_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cloud_providers.id", ondelete="CASCADE"),
        nullable=False,
    )
    credential_type: Mapped[str] = mapped_column(
        String(64), nullable=False,
        comment="access_key | service_principal | service_account | api_key | oci_config",
    )
    credential_name: Mapped[str] = mapped_column(
        String(128), nullable=False, comment="Human-readable label for this credential",
    )
    encrypted_data: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Fernet-encrypted JSON blob of credential fields",
    )
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False,
    )

    # ── Relationships ────────────────────────────────────────────
    cloud_provider: Mapped["CloudProvider"] = relationship(  # noqa: F821
        "CloudProvider", back_populates="credentials",
    )

    def __repr__(self) -> str:
        return (
            f"<CloudCredential id={self.id} "
            f"name={self.credential_name!r} "
            f"type={self.credential_type}>"
        )
