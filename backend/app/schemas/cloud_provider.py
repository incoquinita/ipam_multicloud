"""Pydantic schemas for cloud provider management."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import CloudProviderType


class CloudProviderCreate(BaseModel):
    """Payload for registering a new cloud provider."""

    name: str = Field(..., max_length=128, description="Human-readable name")
    provider_type: CloudProviderType
    description: str | None = None
    regions: list[str] | None = Field(
        None, description="List of regions to scan",
    )
    metadata: dict | None = Field(None, description="Arbitrary provider metadata")


class CloudProviderUpdate(BaseModel):
    """Payload for updating an existing cloud provider."""

    name: str | None = Field(None, max_length=128)
    description: str | None = None
    is_active: bool | None = None
    regions: list[str] | None = None
    metadata: dict | None = None


class CloudProviderResponse(BaseModel):
    """Schema returned from provider endpoints."""

    id: UUID
    name: str
    provider_type: str
    description: str | None = None
    is_active: bool
    regions: str | None = None
    # ``serialization_alias`` keeps the JSON key as ``metadata`` while
    # letting ``from_attributes`` read the ORM column ``metadata_`` — the
    # plain ``alias="metadata"`` would otherwise resolve to SQLAlchemy's
    # reserved ``metadata`` attribute (a MetaData object) and 500.
    metadata_: str | None = Field(None, serialization_alias="metadata")
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True, "populate_by_name": True}
