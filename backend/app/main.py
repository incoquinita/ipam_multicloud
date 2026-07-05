"""FastAPI application factory with lifespan management.

Call ``create_app()`` to get a fully configured FastAPI instance with
middleware, exception handlers, and router registration.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from httpx import AsyncClient, Limits, Timeout
from prometheus_fastapi_instrumentator import Instrumentator

from app.api.v1.endpoints.health import router as health_router
from app.api.v1.router import v1_router
from app.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, logger
from app.middleware.rate_limit import configure_rate_limiter
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan context manager.

    Startup
    -------
    - Configures structured logging.
    - Initialises the shared Redis connection pool.
    - Initialises the shared HTTPX client with connection limits.
    - Registers exception handlers.

    Shutdown
    --------
    - Closes the Redis connection pool.
    - Closes the HTTPX client.
    """
    configure_logging()
    logger.info(
        "Starting %s v%s (env: %s)",
        settings.APP_NAME,
        settings.APP_VERSION,
        settings.ENVIRONMENT,
    )

    # ── Startup ──────────────────────────────────────────────────
    # Shared Redis client for progress pub/sub.
    redis_client = aioredis.from_url(
        settings.REDIS_URL,
        password=settings.REDIS_PASSWORD or None,
        decode_responses=True,
        max_connections=20,
    )
    app.state.redis = redis_client

    # Shared HTTPX client for scanner HTTP analysis.
    http_client = AsyncClient(
        timeout=Timeout(connect=5.0, read=30.0),
        limits=Limits(max_connections=200, max_keepalive_connections=50),
        verify=False,
    )
    app.state.http_client = http_client

    # Register custom exception handlers.
    register_exception_handlers(app)

    yield

    # ── Shutdown ─────────────────────────────────────────────────
    await redis_client.close()
    await http_client.aclose()
    logger.info("Application shutdown complete")


def create_app() -> FastAPI:
    """Build and return a configured FastAPI application instance.

    Middleware order (outermost first):
        1. CORS
        2. Security Headers
        3. Request ID
        4. SlowAPI Rate Limiter
        5. Prometheus Instrumentator
    """
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        lifespan=lifespan,
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        openapi_url="/openapi.json" if settings.DEBUG else None,
    )

    # ── Middleware ────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIDMiddleware)

    # Rate limiting (slowapi): sets app.state.limiter, registers the
    # RateLimitExceeded handler, and adds SlowAPIMiddleware.
    configure_rate_limiter(app)

    # Prometheus metrics: instruments every request and exposes /metrics
    # without authentication for Prometheus scraping.
    Instrumentator().instrument(app).expose(app, endpoint="/metrics")

    # ── Routers ────────────────────────────────────────────────────
    app.include_router(health_router)  # /health (root-level liveness)
    app.include_router(v1_router)  # /api/v1/* (versioned API)

    return app


# Module-level app instance for ASGI servers (uvicorn, gunicorn).
app = create_app()
