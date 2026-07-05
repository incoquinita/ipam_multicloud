"""IP address listing endpoint integration tests.

Exercises ``GET /api/v1/ip-addresses/`` — paginated, filterable by
cloud provider and scan job.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cloud_provider import CloudProvider
from app.models.ip_address import IPAddress


async def _seed_ips(db: AsyncSession) -> tuple[CloudProvider, list[IPAddress]]:
    """Persist a provider with three IP addresses and return them."""
    provider = CloudProvider(name="AWS Test", provider_type="aws")
    db.add(provider)
    await db.flush()

    ips = [
        IPAddress(ip_address="10.0.0.1", cloud_provider_id=provider.id, region="us-east-1"),
        IPAddress(ip_address="10.0.0.2", cloud_provider_id=provider.id, region="us-east-1"),
        IPAddress(ip_address="192.168.1.1", cloud_provider_id=provider.id, region="us-west-2"),
    ]
    db.add_all(ips)
    await db.commit()
    for ip in ips:
        await db.refresh(ip)
    return provider, ips


@pytest.mark.asyncio
async def test_list_ip_addresses_returns_paginated_list(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /ip-addresses/ returns all IPs with pagination metadata."""
    _provider, _ips = await _seed_ips(db_session)

    response = await client.get(
        "/api/v1/ip-addresses/",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3
    assert data["page"] == 1
    assert data["total_pages"] == 1
    # Each item must expose the address field (aliased from ip_address).
    for item in data["items"]:
        assert "address" in item
        assert "id" in item


@pytest.mark.asyncio
async def test_list_ip_addresses_respects_page_size(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /ip-addresses/ with page_size=2 returns two items on page 1."""
    _provider, _ips = await _seed_ips(db_session)

    response = await client.get(
        "/api/v1/ip-addresses/?page=1&page_size=2",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert len(data["items"]) == 2
    assert data["total_pages"] == 2


@pytest.mark.asyncio
async def test_list_ip_addresses_filters_by_provider(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /ip-addresses/ with cloud_provider_id returns only that provider's IPs."""
    provider, _ips = await _seed_ips(db_session)

    response = await client.get(
        f"/api/v1/ip-addresses/?cloud_provider_id={provider.id}",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    for item in data["items"]:
        assert item["cloud_provider_id"] == str(provider.id)


@pytest.mark.asyncio
async def test_list_ip_addresses_returns_401_without_auth(client: AsyncClient) -> None:
    """GET /ip-addresses/ without auth returns 401."""
    response = await client.get("/api/v1/ip-addresses/")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_list_ip_addresses_empty_db_returns_empty_list(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """GET /ip-addresses/ on an empty DB returns zero total and empty items."""
    response = await client.get(
        "/api/v1/ip-addresses/",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["items"] == []
