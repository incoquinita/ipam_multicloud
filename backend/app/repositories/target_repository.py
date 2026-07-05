"""Target-specific repository extending the generic CRUD base."""


from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_target import ScanTarget
from app.repositories.base import BaseRepository


class TargetRepository(BaseRepository[ScanTarget]):
    """Repository for :class:`ScanTarget` operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, ScanTarget)

    async def get_active_targets(self) -> list[ScanTarget]:
        """Return all active scan targets."""
        stmt = select(ScanTarget).where(ScanTarget.is_active.is_(True))
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def find_by_value(self, target_value: str) -> list[ScanTarget]:
        """Return targets matching a given value (CIDR, IP, hostname)."""
        stmt = select(ScanTarget).where(ScanTarget.target_value == target_value)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
