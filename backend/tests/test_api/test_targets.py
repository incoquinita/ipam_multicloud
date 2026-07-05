"""Scan target endpoint integration tests.

Exercises the ``/api/v1/targets`` CRUD lifecycle: create, list (with the
active-only filter), get, update, and delete — plus the 404/409 error
paths surfaced by the service layer.
"""

from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


def _target_payload(value: str = "10.0.0.0/24", name: str = "Target A") -> dict[str, object]:
    return {"name": name, "target_type": "cidr", "target_value": value}


# ── POST /api/v1/targets/ ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_target_returns_201(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """POST creates a target and returns the serialised row."""
    response = await client.post(
        "/api/v1/targets/", json=_target_payload(), headers=auth_headers,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Target A"
    assert data["target_value"] == "10.0.0.0/24"
    assert data["is_active"] is True


@pytest.mark.asyncio
async def test_create_target_rejects_duplicate_with_409(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """A duplicate target value is rejected with 409."""
    await client.post(
        "/api/v1/targets/", json=_target_payload(), headers=auth_headers,
    )
    response = await client.post(
        "/api/v1/targets/", json=_target_payload(name="Dup"), headers=auth_headers,
    )
    assert response.status_code == 409


# ── GET /api/v1/targets/ ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_targets_returns_paginated_list(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """GET returns a paginated list of targets."""
    await client.post(
        "/api/v1/targets/", json=_target_payload(value="10.0.0.0/24"), headers=auth_headers,
    )
    await client.post(
        "/api/v1/targets/", json=_target_payload(value="10.0.1.0/24", name="B"), headers=auth_headers,
    )

    response = await client.get("/api/v1/targets/", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 2
    assert len(data["items"]) >= 2


@pytest.mark.asyncio
async def test_list_targets_active_only_filter(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """active_only=true excludes deactivated targets."""
    create = await client.post(
        "/api/v1/targets/", json=_target_payload(), headers=auth_headers,
    )
    target_id = create.json()["id"]
    await client.patch(
        f"/api/v1/targets/{target_id}",
        json={"is_active": False},
        headers=auth_headers,
    )

    response = await client.get(
        "/api/v1/targets/?active_only=true", headers=auth_headers,
    )
    assert response.status_code == 200
    assert response.json()["total"] == 0


# ── GET /api/v1/targets/{id} ───────────────────────────────────────


@pytest.mark.asyncio
async def test_get_target_returns_row(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """GET by id returns the target."""
    create = await client.post(
        "/api/v1/targets/", json=_target_payload(), headers=auth_headers,
    )
    target_id = create.json()["id"]

    response = await client.get(f"/api/v1/targets/{target_id}", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["id"] == target_id


@pytest.mark.asyncio
async def test_get_target_returns_404_for_missing(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """GET for a non-existent target returns 404."""
    response = await client.get(f"/api/v1/targets/{uuid4()}", headers=auth_headers)
    assert response.status_code == 404


# ── PATCH /api/v1/targets/{id} ─────────────────────────────────────


@pytest.mark.asyncio
async def test_update_target_changes_name(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """PATCH updates the target name."""
    create = await client.post(
        "/api/v1/targets/", json=_target_payload(), headers=auth_headers,
    )
    target_id = create.json()["id"]

    response = await client.patch(
        f"/api/v1/targets/{target_id}", json={"name": "Renamed"}, headers=auth_headers,
    )
    assert response.status_code == 200
    assert response.json()["name"] == "Renamed"


@pytest.mark.asyncio
async def test_update_target_returns_404_for_missing(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """PATCH for a non-existent target returns 404."""
    response = await client.patch(
        f"/api/v1/targets/{uuid4()}", json={"name": "X"}, headers=auth_headers,
    )
    assert response.status_code == 404


# ── DELETE /api/v1/targets/{id} ────────────────────────────────────


@pytest.mark.asyncio
async def test_delete_target_returns_204(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """DELETE removes the target."""
    create = await client.post(
        "/api/v1/targets/", json=_target_payload(), headers=auth_headers,
    )
    target_id = create.json()["id"]

    response = await client.delete(f"/api/v1/targets/{target_id}", headers=auth_headers)
    assert response.status_code == 204
    # Follow-up GET confirms the row is gone.
    follow = await client.get(f"/api/v1/targets/{target_id}", headers=auth_headers)
    assert follow.status_code == 404


@pytest.mark.asyncio
async def test_delete_target_returns_404_for_missing(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """DELETE for a non-existent target returns 404."""
    response = await client.delete(f"/api/v1/targets/{uuid4()}", headers=auth_headers)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_target_endpoints_require_auth(client: AsyncClient) -> None:
    """Every target endpoint rejects unauthenticated requests with 401."""
    assert (await client.post("/api/v1/targets/", json=_target_payload())).status_code == 401
    assert (await client.get("/api/v1/targets/")).status_code == 401
