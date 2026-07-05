"""Cloud provider management endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db
from app.schemas.cloud_provider import (
    CloudProviderCreate,
    CloudProviderResponse,
    CloudProviderUpdate,
)
from app.schemas.common import PaginatedResponse
from app.services.cloud_service import CloudService

router = APIRouter(prefix="/cloud-providers", tags=["Cloud Providers"])


@router.post("/", response_model=CloudProviderResponse, status_code=201)
async def create_provider(
    data: CloudProviderCreate,
    db: AsyncSession = Depends(get_db),
) -> CloudProviderResponse:
    """Register a new cloud provider for IP discovery."""
    service = CloudService(db)
    provider = await service.create_provider(data)
    return CloudProviderResponse.model_validate(provider)


@router.get("/", response_model=PaginatedResponse[CloudProviderResponse])
async def list_providers(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    active_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[CloudProviderResponse]:
    """Return a paginated list of cloud providers."""
    service = CloudService(db)
    skip = (page - 1) * page_size
    providers = await service.list_providers(
        skip=skip, limit=page_size, active_only=active_only,
    )
    items = [CloudProviderResponse.model_validate(p) for p in providers]
    return PaginatedResponse(
        items=items,
        total=len(items),
        page=page,
        page_size=page_size,
        total_pages=max(1, (len(items) + page_size - 1) // page_size),
    )


@router.get("/{provider_id}", response_model=CloudProviderResponse)
async def get_provider(
    provider_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> CloudProviderResponse:
    """Return details for a specific cloud provider."""
    service = CloudService(db)
    provider = await service.get_provider(provider_id)
    return CloudProviderResponse.model_validate(provider)


@router.patch("/{provider_id}", response_model=CloudProviderResponse)
async def update_provider(
    provider_id: UUID,
    data: CloudProviderUpdate,
    db: AsyncSession = Depends(get_db),
) -> CloudProviderResponse:
    """Update an existing cloud provider configuration."""
    service = CloudService(db)
    provider = await service.update_provider(provider_id, data)
    return CloudProviderResponse.model_validate(provider)


@router.delete("/{provider_id}", status_code=204)
async def delete_provider(
    provider_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a cloud provider and its associated data."""
    service = CloudService(db)
    await service.delete_provider(provider_id)
