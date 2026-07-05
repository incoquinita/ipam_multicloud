"""IP address listing endpoint — paginated, filterable discovery view."""

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db
from app.repositories.ip_address_repository import IPAddressRepository
from app.schemas.ip_address import IPAddressListResponse, IPAddressResponse

router = APIRouter(prefix="/ip-addresses", tags=["IP Addresses"])


@router.get("/", response_model=IPAddressListResponse)
async def list_ip_addresses(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    cloud_provider_id: UUID | None = Query(
        None, description="Filter by cloud provider ID",
    ),
    scan_job_id: UUID | None = Query(
        None, description="Filter to IPs scanned by the given job",
    ),
    db: AsyncSession = Depends(get_db),
) -> IPAddressListResponse:
    """Return a paginated list of discovered IP addresses.

    Filterable by ``cloud_provider_id`` (equality on the IP's provider)
    or by ``scan_job_id`` (IPs that produced port results in that job).
    """
    skip = (page - 1) * page_size
    repo = IPAddressRepository(db)
    items, total = await repo.list_ip_addresses(
        skip=skip,
        limit=page_size,
        cloud_provider_id=cloud_provider_id,
        scan_job_id=scan_job_id,
    )
    response_items = [IPAddressResponse.model_validate(ip) for ip in items]
    total_pages = max(1, (total + page_size - 1) // page_size)
    return IPAddressListResponse(
        items=response_items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )
