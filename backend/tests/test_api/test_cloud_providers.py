"""Cloud provider endpoint integration tests.

Exercises the ``/api/v1/cloud-providers`` CRUD lifecycle: create, list
(with the active-only filter), get, update, and delete — plus the 404
error path and the auth guard.
"""

from uuid import uuid4

import pytest
from httpx import AsyncClient


def _provider_payload(name: str = "AWS Prod") -> dict[str, object]:
    return {
        "name": name,
        "provider_type": "aws",
        "regions": ["us-east-1", "us-west-2"],
    }


# ── POST /api/v1/cloud-providers/ ──────────────────────────────────


@pytest.mark.asyncio
async def test_create_provider_returns_201(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """POST creates a provider and returns the serialised row."""
    response = await client.post(
        "/api/v1/cloud-providers/", json=_provider_payload(), headers=auth_headers,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "AWS Prod"
    assert data["provider_type"] == "aws"
    assert data["is_active"] is True


# ── GET /api/v1/cloud-providers/ ───────────────────────────────────


@pytest.mark.asyncio
async def test_list_providers_returns_paginated_list(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """GET returns a paginated list of providers."""
    await client.post(
        "/api/v1/cloud-providers/", json=_provider_payload(name="A"), headers=auth_headers,
    )
    await client.post(
        "/api/v1/cloud-providers/", json=_provider_payload(name="B"), headers=auth_headers,
    )

    response = await client.get("/api/v1/cloud-providers/", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 2


@pytest.mark.asyncio
async def test_list_providers_active_only_filter(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """active_only=true excludes deactivated providers."""
    create = await client.post(
        "/api/v1/cloud-providers/", json=_provider_payload(), headers=auth_headers,
    )
    provider_id = create.json()["id"]
    await client.patch(
        f"/api/v1/cloud-providers/{provider_id}",
        json={"is_active": False},
        headers=auth_headers,
    )

    response = await client.get(
        "/api/v1/cloud-providers/?active_only=true", headers=auth_headers,
    )
    assert response.status_code == 200
    assert response.json()["total"] == 0


# ── GET /api/v1/cloud-providers/{id} ───────────────────────────────


@pytest.mark.asyncio
async def test_get_provider_returns_row(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """GET by id returns the provider."""
    create = await client.post(
        "/api/v1/cloud-providers/", json=_provider_payload(), headers=auth_headers,
    )
    provider_id = create.json()["id"]

    response = await client.get(
        f"/api/v1/cloud-providers/{provider_id}", headers=auth_headers,
    )
    assert response.status_code == 200
    assert response.json()["id"] == provider_id


@pytest.mark.asyncio
async def test_get_provider_returns_404_for_missing(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """GET for a non-existent provider returns 404."""
    response = await client.get(
        f"/api/v1/cloud-providers/{uuid4()}", headers=auth_headers,
    )
    assert response.status_code == 404


# ── PATCH /api/v1/cloud-providers/{id} ─────────────────────────────


@pytest.mark.asyncio
async def test_update_provider_changes_name(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """PATCH updates the provider name."""
    create = await client.post(
        "/api/v1/cloud-providers/", json=_provider_payload(), headers=auth_headers,
    )
    provider_id = create.json()["id"]

    response = await client.patch(
        f"/api/v1/cloud-providers/{provider_id}",
        json={"name": "Renamed"},
        headers=auth_headers,
    )
    assert response.status_code == 200
    assert response.json()["name"] == "Renamed"


@pytest.mark.asyncio
async def test_update_provider_returns_404_for_missing(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """PATCH for a non-existent provider returns 404."""
    response = await client.patch(
        f"/api/v1/cloud-providers/{uuid4()}", json={"name": "X"}, headers=auth_headers,
    )
    assert response.status_code == 404


# ── DELETE /api/v1/cloud-providers/{id} ────────────────────────────


@pytest.mark.asyncio
async def test_delete_provider_returns_204(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """DELETE removes the provider."""
    create = await client.post(
        "/api/v1/cloud-providers/", json=_provider_payload(), headers=auth_headers,
    )
    provider_id = create.json()["id"]

    response = await client.delete(
        f"/api/v1/cloud-providers/{provider_id}", headers=auth_headers,
    )
    assert response.status_code == 204
    follow = await client.get(
        f"/api/v1/cloud-providers/{provider_id}", headers=auth_headers,
    )
    assert follow.status_code == 404


@pytest.mark.asyncio
async def test_delete_provider_returns_404_for_missing(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """DELETE for a non-existent provider returns 404."""
    response = await client.delete(
        f"/api/v1/cloud-providers/{uuid4()}", headers=auth_headers,
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_provider_endpoints_require_auth(client: AsyncClient) -> None:
    """Every provider endpoint rejects unauthenticated requests with 401."""
    assert (await client.post("/api/v1/cloud-providers/", json=_provider_payload())).status_code == 401
    assert (await client.get("/api/v1/cloud-providers/")).status_code == 401
