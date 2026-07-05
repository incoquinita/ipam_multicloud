"""Pydantic schemas for analytics — dashboard, distributions, and timelines.

These schemas are computed by the analytics service from aggregate
queries; they do not map directly from a single ORM row, so they do
not use ``from_attributes``.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class DashboardStats(BaseModel):
    """Top-level dashboard statistics."""

    total_targets: int
    total_scans: int
    active_scans: int
    completed_scans: int
    total_open_ports: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    total_ips: int
    scans_last_7_days: int


class PortDistributionItem(BaseModel):
    """One row in the port-frequency distribution."""

    port: int
    service_name: str
    count: int
    critical_count: int


class PortDistribution(BaseModel):
    """Port frequency distribution across scans."""

    items: list[PortDistributionItem]


class RiskSummary(BaseModel):
    """Aggregate risk counts and average risk score."""

    critical: int
    high: int
    medium: int
    low: int
    total: int
    risk_score_average: float


class ScanTimelineItem(BaseModel):
    """One day in the scan timeline series."""

    date: str = Field(..., description="ISO date string (YYYY-MM-DD)")
    scans: int
    findings: int


class ScanTimeline(BaseModel):
    """Scan and findings timeline series."""

    items: list[ScanTimelineItem]


class CloudProviderStatus(BaseModel):
    """Per-cloud-provider exposure summary."""

    provider_type: str
    total_ips: int
    exposed_ports: int
    last_discovery: datetime | None = None


class CloudStatusResponse(BaseModel):
    """Cloud provider exposure overview across all configured providers."""

    providers: list[CloudProviderStatus]
