"""Cloud-provider-specific repository extending the generic CRUD base."""


from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.cloud_provider import CloudProvider
from app.repositories.base import BaseRepository


class CloudRepository(BaseRepository[CloudProvider]):
    """Repository for :class:`CloudProvider` operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, CloudProvider)

    async def get_active_providers(self) -> list[CloudProvider]:
        """Return all active cloud providers."""
        stmt = (
            select(CloudProvider)
            .where(CloudProvider.is_active.is_(True))
            .options(selectinload(CloudProvider.credentials))
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_type(self, provider_type: str) -> list[CloudProvider]:
        """Return providers matching a given type (aws, azure, gcp, oci)."""
        stmt = select(CloudProvider).where(CloudProvider.provider_type == provider_type)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_with_credentials(self, id: str) -> CloudProvider | None:
        """Return a provider eagerly loaded with its credentials."""
        stmt = (
            select(CloudProvider)
            .where(CloudProvider.id == id)
            .options(selectinload(CloudProvider.credentials))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
