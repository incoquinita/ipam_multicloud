"""Port result listing endpoint — paginated, filterable findings view."""

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import BadRequestException
from app.dependencies import get_db
from app.repositories.port_result_repository import PortResultRepository
from app.schemas.port_result import PortResultListResponse
from app.schemas.scan_result import PortResultResponse

router = APIRouter(prefix="/port-results", tags=["Port Results"])

# Allowed values for the ``state`` and ``risk_level`` filters — defined
# as plain tuples (rather than imported enums) so the OpenAPI docs show
# the literal strings the frontend sends.
_ALLOWED_STATES = ("open", "closed", "filtered", "unfiltered")
_ALLOWED_RISK_LEVELS = ("critical", "high", "medium", "low", "info")


@router.get("/", response_model=PortResultListResponse)
async def list_port_results(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    scan_job_id: UUID | None = Query(
        None, description="Filter by scan job ID",
    ),
    port: int | None = Query(None, ge=1, le=65535, description="Filter by port number"),
    risk_level: str | None = Query(
        None, description="Filter by risk level (critical, high, medium, low, info)",
    ),
    state: str | None = Query(
        None, description="Filter by port state (open, closed, filtered, unfiltered)",
    ),
    db: AsyncSession = Depends(get_db),
) -> PortResultListResponse:
    """Return a paginated list of port scan results.

    Filterable by ``scan_job_id``, ``port``, ``risk_level`` and
    ``state``. Unknown ``risk_level`` or ``state`` values are rejected
    with 400 so callers cannot silently match nothing.
    """
    if risk_level is not None and risk_level not in _ALLOWED_RISK_LEVELS:
        raise BadRequestException(
            detail=f"risk_level must be one of {', '.join(_ALLOWED_RISK_LEVELS)}",
        )
    if state is not None and state not in _ALLOWED_STATES:
        raise BadRequestException(
            detail=f"state must be one of {', '.join(_ALLOWED_STATES)}",
        )

    skip = (page - 1) * page_size
    repo = PortResultRepository(db)
    items, total = await repo.list_port_results(
        skip=skip,
        limit=page_size,
        scan_job_id=scan_job_id,
        port=port,
        risk_level=risk_level,
        state=state,
    )
    response_items = [PortResultResponse.model_validate(item) for item in items]
    total_pages = max(1, (total + page_size - 1) // page_size)
    return PortResultListResponse(
        items=response_items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )
