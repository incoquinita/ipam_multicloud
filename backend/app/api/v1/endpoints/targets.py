"""Scan target management endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db
from app.schemas.common import PaginatedResponse
from app.schemas.scan_target import (
    ScanTargetCreate,
    ScanTargetResponse,
    ScanTargetUpdate,
)
from app.services.target_service import TargetService

router = APIRouter(prefix="/targets", tags=["Targets"])


@router.post("/", response_model=ScanTargetResponse, status_code=201)
async def create_target(
    data: ScanTargetCreate,
    db: AsyncSession = Depends(get_db),
) -> ScanTargetResponse:
    """Register a new scan target."""
    service = TargetService(db)
    target = await service.create_target(data)
    return ScanTargetResponse.model_validate(target)


@router.get("/", response_model=PaginatedResponse[ScanTargetResponse])
async def list_targets(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    active_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[ScanTargetResponse]:
    """Return a paginated list of scan targets."""
    service = TargetService(db)
    skip = (page - 1) * page_size
    targets = await service.list_targets(
        skip=skip, limit=page_size, active_only=active_only,
    )
    items = [ScanTargetResponse.model_validate(t) for t in targets]
    return PaginatedResponse(
        items=items,
        total=len(items),
        page=page,
        page_size=page_size,
        total_pages=max(1, (len(items) + page_size - 1) // page_size),
    )


@router.get("/{target_id}", response_model=ScanTargetResponse)
async def get_target(
    target_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> ScanTargetResponse:
    """Return details for a specific scan target."""
    service = TargetService(db)
    target = await service.get_target(target_id)
    return ScanTargetResponse.model_validate(target)


@router.patch("/{target_id}", response_model=ScanTargetResponse)
async def update_target(
    target_id: UUID,
    data: ScanTargetUpdate,
    db: AsyncSession = Depends(get_db),
) -> ScanTargetResponse:
    """Update an existing scan target."""
    service = TargetService(db)
    target = await service.update_target(target_id, data)
    return ScanTargetResponse.model_validate(target)


@router.delete("/{target_id}", status_code=204)
async def delete_target(
    target_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a scan target."""
    service = TargetService(db)
    await service.delete_target(target_id)
