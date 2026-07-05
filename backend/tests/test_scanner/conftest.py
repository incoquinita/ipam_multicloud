"""Shared fixtures for scanner component tests.

Scanner component tests are pure unit tests — they mock network I/O and
need no database.  The root ``conftest.py`` defines an autouse
``setup_database`` fixture that builds every ORM table on SQLite before
each test.  That works now that JSONB is bridged to JSON, but it is
wasteful for tests that never touch the database.  Override it here
with a no-op so scanner unit tests stay fast and isolated.
"""

from collections.abc import AsyncGenerator

import pytest_asyncio


@pytest_asyncio.fixture(autouse=True)
async def setup_database() -> AsyncGenerator[None, None]:
    """No-op override of the root DB fixture for scanner unit tests."""
    yield
