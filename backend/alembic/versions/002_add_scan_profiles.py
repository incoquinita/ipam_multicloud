"""add_scan_profiles

Add ``profile`` column and ``findings_medium`` / ``findings_low``
counters to the ``scan_jobs`` table.

Revision ID: 002
Revises: 001
Create Date: 2026-06-18 07:05:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ── Add profile column to scan_jobs ────────────────────────────
    op.add_column(
        "scan_jobs",
        sa.Column(
            "profile",
            sa.String(32),
            nullable=True,
            server_default=sa.text("'standard'"),
            comment="Named scan profile (quick | standard | thorough | custom)",
        ),
    )

    # ── Add findings_medium and findings_low columns ───────────────
    op.add_column(
        "scan_jobs",
        sa.Column(
            "findings_medium",
            sa.Integer,
            nullable=True,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "scan_jobs",
        sa.Column(
            "findings_low",
            sa.Integer,
            nullable=True,
            server_default=sa.text("0"),
        ),
    )


def downgrade() -> None:
    op.drop_column("scan_jobs", "findings_low")
    op.drop_column("scan_jobs", "findings_medium")
    op.drop_column("scan_jobs", "profile")
