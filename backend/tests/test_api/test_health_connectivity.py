"""Health check connectivity tests.

Verifies the health endpoint is accessible at both /health and /api/v1/health,
returns the expected status structure, and rejects invalid methods.

The Redis dependency check is stubbed so the endpoint reports ``healthy``
rather than ``degraded`` (the real Redis is unavailable in the test env).
"""

from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient


@pytest.fixture
def _mock_redis(monkeypatch):
    """Patch ``redis.from_url`` so the health check sees a reachable Redis."""
    fake_client = MagicMock()
    fake_client.ping.return_value = True
    fake_client.close.return_value = None
    monkeypatch.setattr("redis.from_url", lambda *_a, **_kw: fake_client)
    return fake_client


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient, _mock_redis) -> None:
    """Test that the /api/v1/health endpoint returns correct structure."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "1.0.0"
    assert data["database"] == "ok"
    assert data["redis"] == "ok"


@pytest.mark.asyncio
async def test_root_health_endpoint(client: AsyncClient, _mock_redis) -> None:
    """Test that /health returns correct structure."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "1.0.0"


@pytest.mark.asyncio
async def test_health_method_not_allowed(client: AsyncClient) -> None:
    """Test that POST to /api/v1/health returns 405."""
    response = await client.post("/api/v1/health")
    assert response.status_code == 405
