"""Pydantic schemas for scan target management."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import TargetType


class ScanTargetCreate(BaseModel):
    """Payload for creating a new scan target."""

    name: str = Field(..., max_length=256, description="Human-readable name")
    description: str | None = None
    target_type: TargetType = TargetType.CIDR
    target_value: str = Field(..., description="CIDR, IP list, provider ID, or hostname")
    ports: list[int] | None = Field(
        None, description="Port list override (None = use default common ports)",
    )
    tags: dict | None = Field(None, description="Arbitrary tags")


class ScanTargetUpdate(BaseModel):
    """Payload for updating a scan target."""

    name: str | None = Field(None, max_length=256)
    description: str | None = None
    target_type: TargetType | None = None
    target_value: str | None = None
    ports: list[int] | None = None
    is_active: bool | None = None
    tags: dict | None = None


class ScanTargetResponse(BaseModel):
    """Schema returned from target endpoints."""

    id: UUID
    name: str
    description: str | None = None
    target_type: str
    target_value: str
    ports: list | None = None
    is_active: bool
    tags: dict | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
