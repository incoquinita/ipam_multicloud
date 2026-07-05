"""Shared fixtures for provider unit tests.

Provider tests are pure unit tests — they mock the cloud SDK clients
(boto3, Azure SDK, OCI SDK, GCP SDK) and need no database.  Override
the root conftest's autouse ``setup_database`` fixture with a no-op so
provider tests stay fast and isolated.
"""

from collections.abc import AsyncGenerator

import pytest_asyncio


@pytest_asyncio.fixture(autouse=True)
async def setup_database() -> AsyncGenerator[None, None]:
    """No-op override of the root conftest DB fixture for provider unit tests."""
    yield
