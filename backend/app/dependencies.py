"""Shared FastAPI dependencies.

Provides ready-to-use dependency callables for database sessions and
the rate limiter so endpoint files don't need to import from core
or middleware packages directly.
"""

from collections.abc import AsyncGenerator

from fastapi import Request
from slowapi import Limiter
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db as _get_db


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session (alias for :func:`app.core.database.get_db`).

    Import this from endpoint modules instead of importing from
    ``app.core.database`` directly.
    """
    async for session in _get_db():
        yield session


def get_rate_limiter(request: Request) -> Limiter:
    """Return the application-wide rate limiter instance.

    Used in routes that need per-endpoint limit overrides:

    .. code-block:: python

        @router.get("/login")
        @limiter.limit(settings.AUTH_RATE_LIMIT)
        async def login(limiter: Limiter = Depends(get_rate_limiter)):
            ...
    """
    limiter: Limiter = request.app.state.limiter
    return limiter
