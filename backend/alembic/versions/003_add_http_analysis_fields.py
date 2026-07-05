"""add_http_analysis_fields

Add new columns to the ``http_analyses`` table for enhanced
Phase 4 HTTP/HTTPS analysis engine:
- ``security_headers`` / ``security_headers_score``
- ``tls_version`` / ``title``
- ``static_evidence`` / ``login_evidence`` / ``rate_limit_details``

Revision ID: 003
Revises: 002
Create Date: 2026-06-18 07:10:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "003"
down_revision: str | None = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ── security_headers (JSONB) ───────────────────────────────────
    op.add_column(
        "http_analyses",
        sa.Column(
            "security_headers",
            JSONB,
            nullable=True,
            server_default=sa.text("'{}'::jsonb"),
            comment="Present security headers and their values",
        ),
    )

    # ── security_headers_score (Integer, 0-10) ─────────────────────
    op.add_column(
        "http_analyses",
        sa.Column(
            "security_headers_score",
            sa.Integer,
            nullable=True,
            comment="Security header compliance score (0-10)",
        ),
    )

    # ── tls_version (String 32) ────────────────────────────────────
    op.add_column(
        "http_analyses",
        sa.Column(
            "tls_version",
            sa.String(32),
            nullable=True,
            comment="Negotiated TLS protocol version",
        ),
    )

    # ── title (String 512) ─────────────────────────────────────────
    op.add_column(
        "http_analyses",
        sa.Column(
            "title",
            sa.String(512),
            nullable=True,
            comment="HTML title tag content",
        ),
    )

    # ── static_evidence (JSONB array) ──────────────────────────────
    op.add_column(
        "http_analyses",
        sa.Column(
            "static_evidence",
            JSONB,
            nullable=True,
            server_default=sa.text("'[]'::jsonb"),
            comment="Probe response evidence for static classification",
        ),
    )

    # ── login_evidence (JSONB array) ───────────────────────────────
    op.add_column(
        "http_analyses",
        sa.Column(
            "login_evidence",
            JSONB,
            nullable=True,
            server_default=sa.text("'[]'::jsonb"),
            comment="Signals that triggered login-page detection",
        ),
    )

    # ── rate_limit_details (JSONB) ─────────────────────────────────
    op.add_column(
        "http_analyses",
        sa.Column(
            "rate_limit_details",
            JSONB,
            nullable=True,
            server_default=sa.text("'{}'::jsonb"),
            comment="Burst probe results including status codes and timings",
        ),
    )


def downgrade() -> None:
    op.drop_column("http_analyses", "rate_limit_details")
    op.drop_column("http_analyses", "login_evidence")
    op.drop_column("http_analyses", "static_evidence")
    op.drop_column("http_analyses", "title")
    op.drop_column("http_analyses", "tls_version")
    op.drop_column("http_analyses", "security_headers_score")
    op.drop_column("http_analyses", "security_headers")
