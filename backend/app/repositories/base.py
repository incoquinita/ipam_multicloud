"""Generic async CRUD repository.

Provides a type-safe base class that domain-specific repositories
extend.  All methods accept and return trusted, parsed data.
"""

from typing import Any, Generic, TypeVar
from uuid import UUID

from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import Base
from app.core.exceptions import NotFoundException

ModelT = TypeVar("ModelT", bound=Base)


class BaseRepository(Generic[ModelT]):
    """Generic CRUD operations for a SQLAlchemy model.

    Parameters
    ----------
    session : AsyncSession
        The async database session to use for all operations.
    model : type[ModelT]
        The SQLAlchemy model class.
    """

    def __init__(self, session: AsyncSession, model: type[ModelT]) -> None:
        self.session = session
        self.model = model

    async def create(self, data: dict[str, Any]) -> ModelT:
        """Create a new entity from *data* and return it."""
        instance = self.model(**data)
        self.session.add(instance)
        await self.session.flush()
        await self.session.refresh(instance)
        return instance

    async def get(self, id: UUID) -> ModelT | None:
        """Return the entity with *id*, or ``None`` if not found."""
        stmt = select(self.model).where(self.model.id == id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_or_raise(self, id: UUID) -> ModelT:
        """Return the entity with *id*, or raise ``NotFoundException``."""
        instance = await self.get(id)
        if instance is None:
            raise NotFoundException(
                detail=f"{self.model.__name__} with id '{id}' not found",
            )
        return instance

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: dict[str, Any] | None = None,
    ) -> list[ModelT]:
        """Return a paginated list of entities.

        Parameters
        ----------
        skip : int
            Number of records to skip (offset).
        limit : int
            Maximum number of records to return.
        filters : dict | None
            Equality filters applied via ``WHERE`` clause.
        """
        stmt = select(self.model).offset(skip).limit(limit)
        if filters:
            for key, value in filters.items():
                column = getattr(self.model, key, None)
                if column is not None:
                    stmt = stmt.where(column == value)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count(self, filters: dict[str, Any] | None = None) -> int:
        """Return the total count of entities, optionally filtered."""
        stmt = select(func.count(self.model.id))
        if filters:
            for key, value in filters.items():
                column = getattr(self.model, key, None)
                if column is not None:
                    stmt = stmt.where(column == value)
        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def update(self, id: UUID, data: dict[str, Any]) -> ModelT | None:
        """Update the entity with *id* using *data* and return it.

        Returns ``None`` if the entity does not exist.
        """
        instance = await self.get(id)
        if instance is None:
            return None
        for key, value in data.items():
            if hasattr(instance, key):
                setattr(instance, key, value)
        await self.session.flush()
        await self.session.refresh(instance)
        return instance

    async def delete(self, id: UUID) -> bool:
        """Delete the entity with *id*.

        Returns ``True`` if a row was deleted, ``False`` otherwise.
        """
        stmt = sa_delete(self.model).where(self.model.id == id)
        result = await self.session.execute(stmt)
        return result.rowcount > 0
