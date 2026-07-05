"""Shared fixtures for Celery worker task tests.

Worker task tests are pure unit tests — they mock the database session,
scanner engine, and Redis pub/sub.  Override the root conftest's autouse
``setup_database`` fixture with a no-op so worker tests stay fast and
isolated.
"""

from collections.abc import AsyncGenerator

import pytest_asyncio


@pytest_asyncio.fixture(autouse=True)
async def setup_database() -> AsyncGenerator[None, None]:
    """No-op override of the root conftest DB fixture for worker unit tests."""
    yield
