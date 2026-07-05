"""Scan-specific repository extending the generic CRUD base.

Adds domain-level queries used by the scan service and dashboard.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import Integer, case, cast, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.http_analysis import HttpAnalysis
from app.models.ip_address import IPAddress
from app.models.port_result import PortResult
from app.models.scan_job import ScanJob
from app.models.scan_target import ScanTarget
from app.repositories.base import BaseRepository

# Statuses that count as "in flight" for ``active_scans``.
_ACTIVE_STATUSES = ("pending", "queued", "running")


class ScanRepository(BaseRepository[ScanJob]):
    """Repository for :class:`ScanJob` operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, ScanJob)

    async def get_dashboard_stats(self) -> dict[str, Any]:
        """Return aggregate statistics for the dashboard.

        Returns
        -------
        dict
            All keys required by the ``DashboardStats`` schema
            (``total_targets``, ``total_scans``, ``active_scans``,
            ``completed_scans``, ``total_open_ports``,
            ``critical_findings``, ``high_findings``, ``medium_findings``,
            ``low_findings``, ``total_ips``, ``scans_last_7_days``)
            plus per-status counts (``running``, ``completed``,
            ``failed``, ``queued``, ``pending``) retained for backwards
            compatibility with existing callers.
        """
        # Use a Python-side cutoff so the query is portable across
        # PostgreSQL and SQLite (the test suite runs on aiosqlite).
        seven_days_ago = datetime.now(UTC) - timedelta(days=7)

        scan_stmt = select(
            func.count().label("total_scans"),
            func.sum(cast(ScanJob.findings_critical, Integer)).label("critical_findings"),
            func.sum(cast(ScanJob.findings_high, Integer)).label("high_findings"),
            func.sum(cast(ScanJob.findings_medium, Integer)).label("medium_findings"),
            func.sum(cast(ScanJob.findings_low, Integer)).label("low_findings"),
            func.sum(
                case((ScanJob.status.in_(_ACTIVE_STATUSES), 1), else_=0)
            ).label("active_scans"),
            func.sum(case((ScanJob.status == "completed", 1), else_=0)).label("completed_scans"),
            func.sum(case((ScanJob.status == "running", 1), else_=0)).label("running"),
            func.sum(case((ScanJob.status == "completed", 1), else_=0)).label("completed"),
            func.sum(case((ScanJob.status == "failed", 1), else_=0)).label("failed"),
            func.sum(case((ScanJob.status == "queued", 1), else_=0)).label("queued"),
            func.sum(case((ScanJob.status == "pending", 1), else_=0)).label("pending"),
            func.sum(case((ScanJob.created_at >= seven_days_ago, 1), else_=0)).label(
                "scans_last_7_days"
            ),
        )
        scan_result = await self.session.execute(scan_stmt)
        row = scan_result.one()

        total_open_ports = await self._count_port_results(state="open")
        total_ips = await self._count_rows(IPAddress)
        total_targets = await self._count_rows(ScanTarget)

        return {
            # Schema-facing keys.
            "total_targets": total_targets,
            "total_scans": row.total_scans or 0,
            "active_scans": row.active_scans or 0,
            "completed_scans": row.completed_scans or 0,
            "total_open_ports": total_open_ports,
            "critical_findings": row.critical_findings or 0,
            "high_findings": row.high_findings or 0,
            "medium_findings": row.medium_findings or 0,
            "low_findings": row.low_findings or 0,
            "total_ips": total_ips,
            "scans_last_7_days": row.scans_last_7_days or 0,
            # Backwards-compatible per-status counts.
            "running": row.running or 0,
            "completed": row.completed or 0,
            "failed": row.failed or 0,
            "queued": row.queued or 0,
            "pending": row.pending or 0,
        }

    async def _count_rows(self, model: type[Any]) -> int:
        """Return the total row count for *model*."""
        result = await self.session.execute(select(func.count(model.id)))
        return result.scalar_one() or 0

    async def _count_port_results(self, state: str | None = None) -> int:
        """Return the count of port results, optionally filtered by *state*."""
        stmt = select(func.count(PortResult.id))
        if state is not None:
            stmt = stmt.where(PortResult.state == state)
        result = await self.session.execute(stmt)
        return result.scalar_one() or 0

    async def get_by_status(self, status: str) -> list[ScanJob]:
        """Return all scan jobs matching *status*."""
        stmt = select(ScanJob).where(ScanJob.status == status).order_by(ScanJob.created_at.desc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_scans(self, status: str | None = None) -> int:
        """Return the total number of scan jobs, optionally filtered by *status*.

        Use this for pagination metadata so ``total`` reflects the full
        result set rather than just the current page.
        """
        stmt = select(func.count(ScanJob.id))
        if status is not None:
            stmt = stmt.where(ScanJob.status == status)
        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def update_progress(
        self,
        job_id: UUID,
        progress: float,
        ips_scanned: int | None = None,
        ports_found: int | None = None,
    ) -> None:
        """Update progress counters for a running scan job."""
        values: dict[str, Any] = {"progress": progress}
        if ips_scanned is not None:
            values["ips_scanned"] = ips_scanned
        if ports_found is not None:
            values["ports_found"] = ports_found
        stmt = update(ScanJob).where(ScanJob.id == job_id).values(**values)
        await self.session.execute(stmt)

    # ── Scan result queries ────────────────────────────────────────

    async def get_port_results(
        self,
        scan_id: UUID,
        skip: int = 0,
        limit: int | None = None,
    ) -> list[PortResult]:
        """Return port results for *scan_id*, optionally paginated.

        When *limit* is ``None`` all matching rows are returned (used by
        the combined results endpoint).  Otherwise standard
        offset/limit pagination is applied.
        """
        stmt = (
            select(PortResult)
            .where(PortResult.scan_job_id == scan_id)
            .order_by(PortResult.port, PortResult.protocol)
        )
        if limit is not None:
            stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_http_analyses(
        self,
        scan_id: UUID,
        skip: int = 0,
        limit: int | None = None,
    ) -> list[HttpAnalysis]:
        """Return HTTP analyses for *scan_id*, optionally paginated.

        When *limit* is ``None`` all matching rows are returned (used by
        the combined results endpoint).  Otherwise standard
        offset/limit pagination is applied.
        """
        stmt = (
            select(HttpAnalysis)
            .where(HttpAnalysis.scan_job_id == scan_id)
            .order_by(HttpAnalysis.port)
        )
        if limit is not None:
            stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_port_results(self, scan_id: UUID) -> int:
        """Return the total count of port results for *scan_id*."""
        stmt = select(func.count(PortResult.id)).where(
            PortResult.scan_job_id == scan_id,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one() or 0

    async def count_http_analyses(self, scan_id: UUID) -> int:
        """Return the total count of HTTP analyses for *scan_id*."""
        stmt = select(func.count(HttpAnalysis.id)).where(
            HttpAnalysis.scan_job_id == scan_id,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one() or 0
