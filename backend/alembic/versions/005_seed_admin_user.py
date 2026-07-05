"""seed_admin_user

Seed the initial superuser row in ``users``. Credentials are read
from the ``ADMIN_EMAIL`` / ``ADMIN_PASSWORD`` environment variables;
when either is absent, deliberately weak defaults are used and a loud
warning is printed so operators never ship them to production unchanged.

Revision ID: 005
Revises: 004
Create Date: 2026-06-18 07:20:00.000000
"""
import os
from collections.abc import Sequence

import bcrypt
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Default credentials — deliberately weak so they are impossible to
# mistake for production-safe. Operators MUST override via env vars.
_DEFAULT_ADMIN_EMAIL = "admin@ipam.local"
_DEFAULT_ADMIN_PASSWORD = "ChangeMe123!"


def _resolve_admin_credentials() -> tuple[str, str, bool]:
    """Return ``(email, password, used_defaults)`` from the environment.

    Falls back to insecure defaults when either env var is missing and
    flags the caller so a warning can be emitted (Fail Loud).
    """
    email = os.environ.get("ADMIN_EMAIL")
    password = os.environ.get("ADMIN_PASSWORD")
    if email and password:
        return email, password, False
    return _DEFAULT_ADMIN_EMAIL, _DEFAULT_ADMIN_PASSWORD, True


def _hash_password(password: str) -> str:
    """Return a bcrypt hash of *password* using the bcrypt library directly.

    ``passlib`` is unmaintained and incompatible with bcrypt 5.x, so we
    call ``bcrypt.hashpw`` directly.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def upgrade() -> None:
    email, password, used_defaults = _resolve_admin_credentials()

    if used_defaults:
        print(
            "WARNING: ADMIN_EMAIL and/or ADMIN_PASSWORD not set — seeding "
            f"admin user with default credentials (email={_DEFAULT_ADMIN_EMAIL!r}). "
            "Change them immediately in production!",
        )

    hashed_password = _hash_password(password)

    # NOTE: op.execute(sa.text(...), params) is not callable with a positional
    # params dict in Alembic 1.18+ (the 2nd arg is keyword-only
    # ``execution_options``). The documented pattern for parameterized SQL is
    # to use the migration bind directly — see alembic.operations.base.Operations.execute.
    op.get_bind().execute(
        sa.text(
            """
            INSERT INTO users
                (email, username, hashed_password, is_active, is_superuser,
                 created_at, updated_at)
            VALUES
                (:email, :username, :hashed_password, :is_active,
                 :is_superuser, NOW(), NOW())
            """
        ),
        {
            "email": email,
            "username": "admin",
            "hashed_password": hashed_password,
            "is_active": True,
            "is_superuser": True,
        },
    )


def downgrade() -> None:
    email, _, _ = _resolve_admin_credentials()
    op.get_bind().execute(
        sa.text("DELETE FROM users WHERE email = :email"),
        {"email": email},
    )
