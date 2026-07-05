"""PortResult repository — paginated listing with optional filters.

Extends the generic CRUD base with a single domain query used by the
``/port-results`` listing endpoint: filter by scan job, port number,
port state, or risk level. ``PortResult`` exposes all four filter
columns directly, so no joins are required.
"""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.port_result import PortResult
from app.repositories.base import BaseRepository


class PortResultRepository(BaseRepository[PortResult]):
    """Repository for :class:`PortResult` operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, PortResult)

    async def list_port_results(
        self,
        skip: int = 0,
        limit: int = 50,
        scan_job_id: UUID | None = None,
        port: int | None = None,
        risk_level: str | None = None,
        state: str | None = None,
    ) -> tuple[list[PortResult], int]:
        """Return a paginated, filterable list of port results.

        Parameters
        ----------
        skip, limit
            Pagination window.
        scan_job_id, port, risk_level, state
            Optional equality filters; ``None`` leaves the field
            unfiltered.

        Returns
        -------
        (items, total)
            The page of ``PortResult`` rows and the total matching
            count (ignoring pagination).
        """
        count_stmt = select(func.count(PortResult.id))
        page_stmt = select(PortResult)

        if scan_job_id is not None:
            count_stmt = count_stmt.where(PortResult.scan_job_id == scan_job_id)
            page_stmt = page_stmt.where(PortResult.scan_job_id == scan_job_id)
        if port is not None:
            count_stmt = count_stmt.where(PortResult.port == port)
            page_stmt = page_stmt.where(PortResult.port == port)
        if risk_level is not None:
            count_stmt = count_stmt.where(PortResult.risk_level == risk_level)
            page_stmt = page_stmt.where(PortResult.risk_level == risk_level)
        if state is not None:
            count_stmt = count_stmt.where(PortResult.state == state)
            page_stmt = page_stmt.where(PortResult.state == state)

        total = (await self.session.execute(count_stmt)).scalar_one()
        page_stmt = (
            page_stmt.order_by(PortResult.scanned_at.desc()).offset(skip).limit(limit)
        )
        items = list((await self.session.execute(page_stmt)).scalars().all())
        return items, total
