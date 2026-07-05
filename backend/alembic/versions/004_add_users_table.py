"""add_users_table

Create the ``users`` table for authenticated API access:
- ``email`` / ``username`` (unique, indexed)
- ``hashed_password`` (bcrypt)
- ``is_active`` / ``is_superuser`` role flags

Revision ID: 004
Revises: 003
Create Date: 2026-06-18 07:15:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column(
            "id", UUID(as_uuid=True), primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "email", sa.String, nullable=False,
            comment="Unique login email address",
        ),
        sa.Column(
            "username", sa.String(50), nullable=False,
            comment="Unique display name and login identifier",
        ),
        sa.Column(
            "hashed_password", sa.String, nullable=False,
            comment="bcrypt hash of the user password",
        ),
        sa.Column(
            "is_active", sa.Boolean, nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "is_superuser", sa.Boolean, nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
    )

    # Unique indexes match the model's ``unique=True, index=True`` columns
    # and the ``ix_%(column_0_label)s`` naming convention in database.py.
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_username", "users", ["username"], unique=True)


def downgrade() -> None:
    op.drop_table("users")
