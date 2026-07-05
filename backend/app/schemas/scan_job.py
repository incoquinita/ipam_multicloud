"""Pydantic schemas for scan jobs — creation, response, and status."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import ScanType


class ScanJobCreate(BaseModel):
    """Payload for submitting a new scan."""

    target_id: UUID = Field(..., description="Target to scan")
    scan_type: ScanType = ScanType.QUICK
    config: dict | None = Field(
        None, description="Scan configuration overrides",
    )
    ports: list[int] | None = Field(
        None, description="Port list override for this scan",
    )


class ScanJobResponse(BaseModel):
    """Full scan job representation returned from detail endpoints."""

    id: UUID
    target_id: UUID
    scan_type: str
    status: str
    progress: float
    config: dict | None = None
    total_ips: int | None = None
    ips_scanned: int | None = None
    ports_found: int | None = None
    findings_critical: int | None = None
    findings_high: int | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: int | None = None
    error_message: str | None = None
    celery_task_id: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScanStatusResponse(BaseModel):
    """Lightweight status response for progress polling."""

    id: UUID
    status: str
    progress: float
    total_ips: int | None = None
    ips_scanned: int | None = None
    ports_found: int | None = None
    findings_critical: int | None = None
    findings_high: int | None = None
    duration_seconds: int | None = None
    error_message: str | None = None
