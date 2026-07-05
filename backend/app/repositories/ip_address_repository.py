"""IPAddress repository — paginated listing with optional joins.

Extends the generic CRUD base with a single domain query used by the
``/ip-addresses`` listing endpoint: filter by cloud provider or by the
scan job that scanned the address (via a join through
``port_results``).
"""

from uuid import UUID

from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ip_address import IPAddress
from app.models.port_result import PortResult
from app.repositories.base import BaseRepository


class IPAddressRepository(BaseRepository[IPAddress]):
    """Repository for :class:`IPAddress` operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, IPAddress)

    async def list_ip_addresses(
        self,
        skip: int = 0,
        limit: int = 50,
        cloud_provider_id: UUID | None = None,
        scan_job_id: UUID | None = None,
    ) -> tuple[list[IPAddress], int]:
        """Return a paginated, filterable list of discovered IP addresses.

        Parameters
        ----------
        skip, limit
            Pagination window.
        cloud_provider_id
            Optional equality filter on ``IPAddress.cloud_provider_id``.
        scan_job_id
            Optional filter that restricts the list to IPs scanned by
            the given job — resolved via a join to ``PortResult`` and
            de-duplicated with ``DISTINCT`` since one IP may have many
            port results in the same job.

        Returns
        -------
        (items, total)
            The page of ``IPAddress`` rows and the total matching count
            (ignoring pagination).
        """
        # When joining through PortResult, one IP can appear multiple
        # times (once per port result). DISTINCT keeps both the count
        # and the page query consistent.
        has_scan_filter = scan_job_id is not None

        count_stmt = select(func.count(distinct(IPAddress.id)))
        page_stmt = select(IPAddress).distinct() if has_scan_filter else select(IPAddress)

        if has_scan_filter:
            count_stmt = count_stmt.join(
                PortResult, PortResult.ip_address_id == IPAddress.id
            ).where(PortResult.scan_job_id == scan_job_id)
            page_stmt = page_stmt.join(
                PortResult, PortResult.ip_address_id == IPAddress.id
            ).where(PortResult.scan_job_id == scan_job_id)

        if cloud_provider_id is not None:
            count_stmt = count_stmt.where(IPAddress.cloud_provider_id == cloud_provider_id)
            page_stmt = page_stmt.where(IPAddress.cloud_provider_id == cloud_provider_id)

        total = (await self.session.execute(count_stmt)).scalar_one()
        page_stmt = page_stmt.order_by(IPAddress.discovered_at.desc()).offset(skip).limit(limit)
        items = list((await self.session.execute(page_stmt)).scalars().all())
        return items, total
