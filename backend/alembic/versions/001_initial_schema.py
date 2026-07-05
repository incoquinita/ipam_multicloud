"""initial_schema

Create Date: 2026-06-18

Revision ID: 001
Revises:
Create Date: 2026-06-18 07:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── cloud_providers ───────────────────────────────────────────
    op.create_table(
        "cloud_providers",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("provider_type", sa.String(32), nullable=False, comment="aws | azure | gcp | oci"),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("regions", sa.String(1024), nullable=True, comment="Comma-separated list of regions to scan"),
        sa.Column("metadata", sa.String(2048), nullable=True, comment="JSON-encoded provider metadata"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cloud_providers")),
    )

    # ── cloud_credentials ─────────────────────────────────────────
    op.create_table(
        "cloud_credentials",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("cloud_provider_id", UUID(as_uuid=True),
                  sa.ForeignKey("cloud_providers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("credential_type", sa.String(64), nullable=False,
                  comment="access_key | service_principal | service_account | api_key | oci_config"),
        sa.Column("credential_name", sa.String(128), nullable=False,
                  comment="Human-readable label for this credential"),
        sa.Column("encrypted_data", sa.Text, nullable=False,
                  comment="Fernet-encrypted JSON blob of credential fields"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cloud_credentials")),
    )

    # ── scan_targets ──────────────────────────────────────────────
    op.create_table(
        "scan_targets",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("target_type", sa.String(32), nullable=False, server_default=sa.text("'cidr'"),
                  comment="cidr | ip_list | cloud_provider | hostname"),
        sa.Column("target_value", sa.Text, nullable=False,
                  comment="CIDR notation, comma-separated IPs, cloud provider ID, or hostname"),
        sa.Column("ports", JSONB, nullable=True, server_default=sa.text("'[]'::jsonb"),
                  comment="List of ports to scan (None = common ports)"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("tags", JSONB, nullable=True, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_targets")),
    )

    # ── ip_addresses ──────────────────────────────────────────────
    op.create_table(
        "ip_addresses",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("cloud_provider_id", UUID(as_uuid=True),
                  sa.ForeignKey("cloud_providers.id", ondelete="SET NULL"), nullable=True),
        sa.Column("resource_id", sa.String(256), nullable=True,
                  comment="Cloud provider resource ID (e.g. EC2 instance ID)"),
        sa.Column("resource_type", sa.String(64), nullable=True,
                  comment="Type of resource (instance, load_balancer, etc.)"),
        sa.Column("ip_address", sa.String(45), nullable=False, index=True,
                  comment="IP address as string (IPv4/IPv6); migration to INET later"),
        sa.Column("private_ip", sa.String(45), nullable=True, comment="Private IP if applicable"),
        sa.Column("region", sa.String(64), nullable=True, comment="Cloud provider region"),
        sa.Column("tags", JSONB, nullable=True, server_default=sa.text("'{}'::jsonb")),
        sa.Column("is_alive", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("hostname", sa.String(256), nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ip_addresses")),
    )

    # ── scan_jobs ─────────────────────────────────────────────────
    op.create_table(
        "scan_jobs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("target_id", UUID(as_uuid=True),
                  sa.ForeignKey("scan_targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_type", sa.String(32), nullable=False, server_default=sa.text("'port_scan'"),
                  comment="port_scan | service_detection | http_analysis | full_audit"),
        sa.Column("status", sa.String(32), nullable=False, server_default=sa.text("'pending'"),
                  comment="pending | queued | running | completed | failed | cancelled"),
        sa.Column("progress", sa.Float, nullable=False, server_default=sa.text("0.0")),
        sa.Column("config", JSONB, nullable=True, server_default=sa.text("'{}'::jsonb"),
                  comment="Scan configuration overrides"),
        sa.Column("total_ips", sa.Integer, nullable=True, server_default=sa.text("0")),
        sa.Column("ips_scanned", sa.Integer, nullable=True, server_default=sa.text("0")),
        sa.Column("ports_found", sa.Integer, nullable=True, server_default=sa.text("0")),
        sa.Column("findings_critical", sa.Integer, nullable=True, server_default=sa.text("0")),
        sa.Column("findings_high", sa.Integer, nullable=True, server_default=sa.text("0")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Integer, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("celery_task_id", sa.String(128), nullable=True, comment="Celery task ID for tracking"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_jobs")),
    )

    # ── port_results ──────────────────────────────────────────────
    op.create_table(
        "port_results",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_job_id", UUID(as_uuid=True),
                  sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip_address_id", UUID(as_uuid=True),
                  sa.ForeignKey("ip_addresses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("protocol", sa.String(16), nullable=False, server_default=sa.text("'tcp'")),
        sa.Column("state", sa.String(32), nullable=False,
                  comment="open | closed | filtered | unfiltered"),
        sa.Column("service_name", sa.String(128), nullable=True),
        sa.Column("service_product", sa.String(256), nullable=True),
        sa.Column("service_version", sa.String(128), nullable=True),
        sa.Column("banner", sa.Text, nullable=True),
        sa.Column("risk_level", sa.String(16), nullable=True,
                  comment="critical | high | medium | low | info"),
        sa.Column("risk_score", sa.Float, nullable=True),
        sa.Column("cve_ids", JSONB, nullable=True, server_default=sa.text("'[]'::jsonb"),
                  comment="List of related CVE identifiers"),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_port_results")),
        sa.CheckConstraint("port >= 1 AND port <= 65535", name=op.f("ck_port_result_port_range")),
    )

    # ── http_analyses ─────────────────────────────────────────────
    op.create_table(
        "http_analyses",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_job_id", UUID(as_uuid=True),
                  sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip_address_id", UUID(as_uuid=True),
                  sa.ForeignKey("ip_addresses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("status_code", sa.Integer, nullable=True),
        sa.Column("is_static", sa.Boolean, nullable=True),
        sa.Column("has_login", sa.Boolean, nullable=True),
        sa.Column("has_rate_limit", sa.Boolean, nullable=True),
        sa.Column("response_headers", JSONB, nullable=True, server_default=sa.text("'{}'::jsonb")),
        sa.Column("technologies", JSONB, nullable=True, server_default=sa.text("'[]'::jsonb")),
        sa.Column("certificates", JSONB, nullable=True, server_default=sa.text("'{}'::jsonb"),
                  comment="TLS certificate info in JSON"),
        sa.Column("analyzed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_http_analyses")),
    )

    # ── scan_events ───────────────────────────────────────────────
    op.create_table(
        "scan_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_job_id", UUID(as_uuid=True),
                  sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False,
                  comment="progress | status_change | warning | error | info"),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("metadata", JSONB, nullable=True, server_default=sa.text("'{}'::jsonb"),
                  comment="Arbitrary event payload"),
        sa.Column("progress", sa.Integer, nullable=True,
                  comment="Progress percentage at the time of this event"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_events")),
    )


def downgrade() -> None:
    op.drop_table("scan_events")
    op.drop_table("http_analyses")
    op.drop_table("port_results")
    op.drop_table("scan_jobs")
    op.drop_table("ip_addresses")
    op.drop_table("scan_targets")
    op.drop_table("cloud_credentials")
    op.drop_table("cloud_providers")
