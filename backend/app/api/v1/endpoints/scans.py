"""Scan job endpoints — CRUD, submission, and results retrieval."""

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db
from app.models.http_analysis import HttpAnalysis
from app.models.port_result import PortResult
from app.models.scan_job import ScanJob
from app.schemas.analytics import DashboardStats
from app.schemas.common import PaginatedResponse
from app.schemas.port_result import PortResultListResponse
from app.schemas.scan_job import (
    ScanJobCreate,
    ScanJobResponse,
    ScanStatusResponse,
)
from app.schemas.scan_result import (
    HttpAnalysisResponse,
    PortResultResponse,
    ScanResultsResponse,
    ScanResultsSummary,
)
from app.services.scan_service import ScanService

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.get("/stats", response_model=DashboardStats)
async def get_scan_stats(
    db: AsyncSession = Depends(get_db),
) -> DashboardStats:
    """Return aggregate dashboard statistics.

    Powers the frontend ``Dashboard.tsx`` KPI cards. Wired to
    :meth:`ScanRepository.get_dashboard_stats`, which returns a dict
    carrying every key required by ``DashboardStats``.

    Registered before the ``/{scan_id}`` routes so the static ``stats``
    segment is matched before the path-parameter route would try (and
    fail) to coerce it to a UUID.
    """
    service = ScanService(db)
    stats = await service.get_dashboard_stats()
    return DashboardStats(
        total_targets=stats["total_targets"],
        total_scans=stats["total_scans"],
        active_scans=stats["active_scans"],
        completed_scans=stats["completed_scans"],
        total_open_ports=stats["total_open_ports"],
        critical_findings=stats["critical_findings"],
        high_findings=stats["high_findings"],
        medium_findings=stats["medium_findings"],
        low_findings=stats["low_findings"],
        total_ips=stats["total_ips"],
        scans_last_7_days=stats["scans_last_7_days"],
    )


@router.post("/", response_model=ScanJobResponse, status_code=201)
async def create_scan(
    data: ScanJobCreate,
    db: AsyncSession = Depends(get_db),
) -> ScanJobResponse:
    """Submit a new scan job for execution."""
    service = ScanService(db)
    job = await service.create_scan(data)
    return ScanJobResponse.model_validate(job)


@router.get("/", response_model=PaginatedResponse[ScanJobResponse])
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200, alias="size"),
    status: str | None = Query(None, description="Filter by status"),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[ScanJobResponse]:
    """Return a paginated list of scan jobs.

    The ``page_size`` query parameter is exposed to clients as ``size``
    (via ``alias="size"``) to match the frontend pagination contract.
    ``total`` reflects the full matching result set, not just the
    current page.
    """
    service = ScanService(db)
    skip = (page - 1) * page_size
    jobs, total = await service.list_scans(skip=skip, limit=page_size, status=status)
    items = [ScanJobResponse.model_validate(j) for j in jobs]
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        size=page_size,
        pages=max(1, (total + page_size - 1) // page_size),
    )


@router.get("/{scan_id}", response_model=ScanJobResponse)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> ScanJobResponse:
    """Return details for a specific scan job."""
    service = ScanService(db)
    job = await service.get_scan(scan_id)
    return ScanJobResponse.model_validate(job)


@router.get("/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> ScanStatusResponse:
    """Return lightweight status for progress polling."""
    service = ScanService(db)
    job = await service.get_scan(scan_id)
    return ScanStatusResponse(
        id=job.id,
        status=job.status,
        progress=job.progress,
        total_ips=job.total_ips,
        ips_scanned=job.ips_scanned,
        ports_found=job.ports_found,
        findings_critical=job.findings_critical,
        findings_high=job.findings_high,
        duration_seconds=job.duration_seconds,
        error_message=job.error_message,
    )


@router.post("/{scan_id}/cancel", response_model=ScanJobResponse)
async def cancel_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> ScanJobResponse:
    """Cancel a pending, queued, or running scan."""
    service = ScanService(db)
    job = await service.cancel_scan(scan_id)
    return ScanJobResponse.model_validate(job)


# ── Scan results ────────────────────────────────────────────────────


@router.get("/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> ScanResultsResponse:
    """Return the combined results bundle for a scan.

    Includes the scan status, all port results, all HTTP analyses, and
    an aggregate summary.  Port and HTTP results are not paginated on
    this endpoint — use the dedicated ``/results/ports`` and
    ``/results/http`` routes for page-by-page retrieval.
    """
    service = ScanService(db)
    job, port_results, http_analyses = await service.get_scan_results(scan_id)
    return ScanResultsResponse(
        scan_job=_scan_status_from_job(job),
        port_results=[PortResultResponse.model_validate(p) for p in port_results],
        http_analyses=[HttpAnalysisResponse.model_validate(h) for h in http_analyses],
        summary=_build_results_summary(job, port_results, http_analyses),
    )


@router.get("/{scan_id}/results/ports", response_model=PortResultListResponse)
async def get_scan_port_results(
    scan_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200, alias="size"),
    db: AsyncSession = Depends(get_db),
) -> PortResultListResponse:
    """Return a paginated list of port results for a scan."""
    service = ScanService(db)
    skip = (page - 1) * page_size
    results, total = await service.get_port_results(scan_id, skip=skip, limit=page_size)
    items = [PortResultResponse.model_validate(p) for p in results]
    return PortResultListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, (total + page_size - 1) // page_size),
    )


@router.get("/{scan_id}/results/http", response_model=list[HttpAnalysisResponse])
async def get_scan_http_analyses(
    scan_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200, alias="size"),
    db: AsyncSession = Depends(get_db),
) -> list[HttpAnalysisResponse]:
    """Return a paginated list of HTTP analysis results for a scan."""
    service = ScanService(db)
    skip = (page - 1) * page_size
    results, _total = await service.get_http_analyses(scan_id, skip=skip, limit=page_size)
    return [HttpAnalysisResponse.model_validate(h) for h in results]


# ── Helpers ─────────────────────────────────────────────────────────


def _scan_status_from_job(job: ScanJob) -> ScanStatusResponse:
    """Build a ``ScanStatusResponse`` from a ``ScanJob`` ORM instance."""
    return ScanStatusResponse(
        id=job.id,
        status=job.status,
        progress=job.progress,
        total_ips=job.total_ips,
        ips_scanned=job.ips_scanned,
        ports_found=job.ports_found,
        findings_critical=job.findings_critical,
        findings_high=job.findings_high,
        duration_seconds=job.duration_seconds,
        error_message=job.error_message,
    )


def _build_results_summary(
    job: ScanJob,
    port_results: list[PortResult],
    http_analyses: list[HttpAnalysis],
) -> ScanResultsSummary:
    """Aggregate port and HTTP results into a ``ScanResultsSummary``."""
    return ScanResultsSummary(
        total_ports=len(port_results),
        open_ports=sum(1 for p in port_results if p.state == "open"),
        critical_findings=job.findings_critical or 0,
        high_findings=job.findings_high or 0,
        medium_findings=job.findings_medium or 0,
        low_findings=job.findings_low or 0,
        http_analyzed=len(http_analyses),
        static_sites=sum(1 for h in http_analyses if h.is_static),
        login_sites=sum(1 for h in http_analyses if h.has_login),
        rate_limited_sites=sum(1 for h in http_analyses if h.has_rate_limit),
    )
