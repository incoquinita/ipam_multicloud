"""Health check endpoint.

Returns the liveness status of the application and its dependencies
(database, Redis, etc.).  Used by orchestrators and load balancers.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_db

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)) -> dict:
    """Return application health status.

    Checks database and Redis connectivity and reports the current
    application version.
    """
    settings = get_settings()
    status = "healthy"
    db_status = "ok"
    redis_status = "unknown"

    # Check database connectivity.
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "unreachable"
        status = "degraded"

    # Check Redis connectivity.
    try:
        import redis as sync_redis
        r = sync_redis.from_url(settings.REDIS_URL, socket_connect_timeout=2)
        r.ping()
        r.close()
        redis_status = "ok"
    except Exception:
        redis_status = "unreachable"
        if status != "degraded":
            status = "degraded"

    return {
        "status": status,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "database": db_status,
        "redis": redis_status,
    }
