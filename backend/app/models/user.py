"""User ORM model.

Stores credentials and role flags for authenticated access to the
API.  Passwords are stored as bcrypt hashes only — never plaintext.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    email: Mapped[str] = mapped_column(
        String, unique=True, index=True, nullable=False,
        comment="Unique login email address",
    )
    username: Mapped[str] = mapped_column(
        String(50), unique=True, index=True, nullable=False,
        comment="Unique display name and login identifier",
    )
    hashed_password: Mapped[str] = mapped_column(
        String, nullable=False,
        comment="bcrypt hash of the user password",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true"),
    )
    is_superuser: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False,
    )

    def __repr__(self) -> str:
        return (
            f"<User id={self.id} "
            f"username={self.username!r} "
            f"email={self.email!r}>"
        )
