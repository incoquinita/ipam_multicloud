"""Target management service."""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictException, NotFoundException
from app.models.scan_target import ScanTarget
from app.repositories.target_repository import TargetRepository
from app.schemas.scan_target import ScanTargetCreate, ScanTargetUpdate


class TargetService:
    """High-level scan-target operations."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = TargetRepository(session)

    async def create_target(self, data: ScanTargetCreate) -> ScanTarget:
        """Register a new scan target.

        Raises
        ------
        ConflictException
            If a target with the same value already exists.
        """
        existing = await self.repo.find_by_value(data.target_value)
        if existing:
            raise ConflictException(
                detail=f"Target with value '{data.target_value}' already exists",
            )
        return await self.repo.create(data.model_dump(exclude_unset=True))

    async def get_target(self, target_id: UUID) -> ScanTarget:
        """Return a target or raise."""
        target = await self.repo.get(target_id)
        if target is None:
            raise NotFoundException(detail=f"Target '{target_id}' not found")
        return target

    async def list_targets(
        self,
        skip: int = 0,
        limit: int = 50,
        active_only: bool = False,
    ) -> list[ScanTarget]:
        """Return scan targets."""
        if active_only:
            return await self.repo.get_active_targets()
        return await self.repo.list(skip=skip, limit=limit)

    async def update_target(self, target_id: UUID, data: ScanTargetUpdate) -> ScanTarget:
        """Update a scan target."""
        target = await self.repo.get(target_id)
        if target is None:
            raise NotFoundException(detail=f"Target '{target_id}' not found")
        updated = await self.repo.update(target_id, data.model_dump(exclude_unset=True))
        if updated is None:
            raise NotFoundException(detail=f"Target '{target_id}' not found")
        return updated

    async def delete_target(self, target_id: UUID) -> None:
        """Delete a scan target."""
        deleted = await self.repo.delete(target_id)
        if not deleted:
            raise NotFoundException(detail=f"Target '{target_id}' not found")
