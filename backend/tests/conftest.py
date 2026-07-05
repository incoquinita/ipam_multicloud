"""Pytest configuration and async fixtures.

Provides a test database session, a test FastAPI client, and reusable
test data factories.

Database compatibility
----------------------
Production models declare ``JSONB`` columns (PostgreSQL-specific).  The
test database is in-memory SQLite, whose type compiler cannot render
``JSONB``.  Rather than mutate the production models, we register a
SQLAlchemy compile hook at import time that rewrites ``JSONB`` → ``JSON``
for the SQLite dialect only.  The hook is scoped to ``"sqlite"`` so
PostgreSQL behaviour is untouched in non-test environments.
"""

from collections.abc import AsyncGenerator
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.pool import StaticPool
from sqlalchemy.types import JSON

from app.core.database import Base, get_db
from app.core.exceptions import register_exception_handlers
from app.dependencies import get_db as get_db_dependency
from app.main import create_app

# ── Test-environment overrides ────────────────────────────────────
# Disable the slowapi rate limiter for the whole session.  The limiter
# is a module-level singleton whose in-memory counters persist across
# tests; without this, successive register/login calls in the same
# minute would hit the 5/10-per-minute limits and produce spurious 429s.
from app.middleware.rate_limit import rate_limiter

rate_limiter.enabled = False


# ── SQLite ↔ PostgreSQL type bridge ────────────────────────────────
# Render ``JSONB`` as plain ``JSON`` when targeting SQLite so that the
# ORM models can be materialised on the in-memory test database without
# editing a single production line.  PostgreSQL compiles ``JSONB``
# natively, so the hook is a no-op outside the SQLite dialect.
@compiles(JSONB, "sqlite")
def _compile_jsonb_as_json(element: Any, compiler: Any, **kw: Any) -> str:  # noqa: ARG001
    """Compile ``JSONB`` columns as ``JSON`` for the SQLite dialect."""
    return compiler.visit_JSON(JSON(), **kw)


# Use an in-memory SQLite database for tests.
# ``StaticPool`` keeps a single connection alive so every session sees
# the same schema and rows — required because SQLite in-memory databases
# are per-connection and would otherwise disappear between the
# ``setup_database`` fixture and the per-test ``db_session``.
TEST_DATABASE_URL = "sqlite+aiosqlite://"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    poolclass=StaticPool,
    connect_args={"check_same_thread": False},
)
test_session_factory = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


@pytest.fixture(scope="session")
def event_loop():
    """Create a single event loop for the test session."""
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(autouse=True)
async def setup_database() -> AsyncGenerator[None, None]:
    """Create all tables before each test and drop them after."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield a fresh async session for each test."""
    async with test_session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Yield an HTTPX AsyncClient wired to the test app.

    The Prometheus instrumentator middleware (``prometheus_fastapi_
    instrumentator 8.0.0``) is incompatible with FastAPI 0.137's
    ``_IncludedRouter`` internals — its ``_get_route_name`` helper
    assumes every route exposes ``.path`` and raises ``AttributeError``
    on every request.  Metrics are not exercised by the test suite, so
    we strip the middleware before the stack is built.  Production
    behaviour is untouched.
    """

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app = create_app()
    # Override both ``get_db`` callables: the domain endpoints import the
    # wrapper from ``app.dependencies``, while some core paths reference
    # the original from ``app.core.database``.  Overriding both ensures
    # every request lands on the test session.
    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_db_dependency] = _override_get_db

    # The lifespan (which registers exception handlers) does not execute
    # under ``ASGITransport``; register them explicitly so ``AppException``
    # subclasses are mapped to their HTTP status codes.
    register_exception_handlers(app)

    # Strip the Prometheus middleware — it crashes on every request due
    # to a library incompatibility (see docstring above).
    app.user_middleware = [
        m for m in app.user_middleware
        if "PrometheusInstrumentator" not in m.cls.__name__
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ── Authentication fixtures ──────────────────────────────────────


@pytest_asyncio.fixture
async def auth_headers(db_session: AsyncSession) -> dict[str, str]:
    """Create an active test user and return ``Authorization`` headers.

    The returned dict carries a valid bearer access token that the
    ``get_current_user`` dependency will accept.  Use it for any
    endpoint protected by ``get_current_active_user``.
    """
    from app.core.security import hash_password
    from app.models.user import User
    from app.services.auth_service import AuthService

    user = User(
        email="testuser@example.com",
        username="testuser",
        hashed_password=hash_password("TestPassword123!"),
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    tokens = AuthService.create_tokens(user)
    return {"Authorization": f"Bearer {tokens.access_token}"}


@pytest_asyncio.fixture
async def superuser_headers(db_session: AsyncSession) -> dict[str, str]:
    """Create a test superuser and return ``Authorization`` headers."""
    from app.core.security import hash_password
    from app.models.user import User
    from app.services.auth_service import AuthService

    user = User(
        email="superuser@example.com",
        username="superuser",
        hashed_password=hash_password("SuperPassword123!"),
        is_superuser=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    tokens = AuthService.create_tokens(user)
    return {"Authorization": f"Bearer {tokens.access_token}"}


@pytest_asyncio.fixture
async def inactive_user_headers(db_session: AsyncSession) -> dict[str, str]:
    """Create an inactive test user and return ``Authorization`` headers.

    The token decodes successfully, but ``get_current_active_user``
    rejects the user with 403 (``is_active=False``).
    """
    from app.core.security import hash_password
    from app.models.user import User
    from app.services.auth_service import AuthService

    user = User(
        email="inactive@example.com",
        username="inactive",
        hashed_password=hash_password("InactivePassword123!"),
        is_active=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    tokens = AuthService.create_tokens(user)
    return {"Authorization": f"Bearer {tokens.access_token}"}


# ── Test data factories ──────────────────────────────────────────

@pytest.fixture
def sample_target_data() -> dict[str, Any]:
    """Return a dict suitable for creating a scan target."""
    return {
        "name": "Test Target",
        "target_type": "cidr",
        "target_value": "10.0.0.0/24",
        "ports": [80, 443, 22],
    }


@pytest.fixture
def sample_provider_data() -> dict[str, Any]:
    """Return a dict suitable for creating a cloud provider."""
    return {
        "name": "Test AWS",
        "provider_type": "aws",
        "regions": ["us-east-1", "us-west-2"],
    }


@pytest.fixture
def sample_scan_data() -> dict[str, Any]:
    """Return a dict for creating a scan job (requires a target_id)."""
    return {
        "target_id": str(uuid4()),
        "scan_type": "quick",
        "config": {"timeout": 5},
    }
