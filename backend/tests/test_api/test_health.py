"""Health endpoint tests."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient) -> None:
    """Verify the health endpoint returns expected structure."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200

    data = response.json()
    assert "status" in data
    assert "version" in data
    assert "environment" in data
    assert "database" in data
    assert "redis" in data


@pytest.mark.asyncio
async def test_health_method_not_allowed(client: AsyncClient) -> None:
    """POST to /health should return 405."""
    response = await client.post("/api/v1/health")
    assert response.status_code == 405
