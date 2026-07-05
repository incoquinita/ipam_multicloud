"""Cloud credential endpoint integration tests.

Exercises the ``/api/v1/credentials`` CRUD lifecycle through the test
ASGI client.  Every endpoint requires an authenticated, active user —
enforced at the router level via ``get_current_active_user``.
"""

from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cloud_provider import CloudProvider


async def _create_provider(db: AsyncSession, name: str = "Test AWS") -> CloudProvider:
    """Persist and return a cloud provider for credential attachment."""
    provider = CloudProvider(name=name, provider_type="aws")
    db.add(provider)
    await db.commit()
    await db.refresh(provider)
    return provider


def _credential_payload(provider_id: str) -> dict[str, object]:
    """Build a credential creation body."""
    return {
        "cloud_provider_id": provider_id,
        "provider_type": "access_key",
        "name": "AWS Production Key",
        "credentials": {
            "access_key_id": "AKIATESTKEY",
            "secret_access_key": "secret123",
        },
    }


# ── POST /api/v1/credentials/ ─────────────────────────────────────


@pytest.mark.asyncio
async def test_create_credential_returns_201_with_masked_response(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """POST creates a credential and never exposes the encrypted secret."""
    provider = await _create_provider(db_session)

    response = await client.post(
        "/api/v1/credentials/",
        json=_credential_payload(str(provider.id)),
        headers=auth_headers,
    )

    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "AWS Production Key"
    assert data["provider_type"] == "access_key"
    assert "id" in data
    # The encrypted blob must never appear in the response.
    assert "encrypted_data" not in data
    assert "credentials" not in data


@pytest.mark.asyncio
async def test_create_credential_returns_404_for_missing_provider(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """POST with a non-existent provider ID returns 404."""
    response = await client.post(
        "/api/v1/credentials/",
        json=_credential_payload(str(uuid4())),
        headers=auth_headers,
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_create_credential_returns_401_without_auth(
    client: AsyncClient, db_session: AsyncSession,
) -> None:
    """POST without an auth header returns 401."""
    provider = await _create_provider(db_session)

    response = await client.post(
        "/api/v1/credentials/",
        json=_credential_payload(str(provider.id)),
    )

    assert response.status_code == 401


# ── GET /api/v1/credentials/ ──────────────────────────────────────


@pytest.mark.asyncio
async def test_list_credentials_returns_existing(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET lists previously created credentials (masked)."""
    provider = await _create_provider(db_session)

    # Create two credentials.
    for i in range(2):
        payload = _credential_payload(str(provider.id))
        payload["name"] = f"Key {i}"
        await client.post("/api/v1/credentials/", json=payload, headers=auth_headers)

    response = await client.get("/api/v1/credentials/", headers=auth_headers)

    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 2
    assert len(data["items"]) >= 2
    # No item exposes the encrypted blob.
    for item in data["items"]:
        assert "encrypted_data" not in item


@pytest.mark.asyncio
async def test_list_credentials_returns_401_without_auth(client: AsyncClient) -> None:
    """GET without an auth header returns 401."""
    response = await client.get("/api/v1/credentials/")
    assert response.status_code == 401


# ── GET /api/v1/credentials/{id} ──────────────────────────────────


@pytest.mark.asyncio
async def test_get_credential_by_id_returns_masked(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET by ID returns the credential without the encrypted blob."""
    provider = await _create_provider(db_session)
    create_resp = await client.post(
        "/api/v1/credentials/",
        json=_credential_payload(str(provider.id)),
        headers=auth_headers,
    )
    credential_id = create_resp.json()["id"]

    response = await client.get(
        f"/api/v1/credentials/{credential_id}",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == credential_id
    assert "encrypted_data" not in data


@pytest.mark.asyncio
async def test_get_credential_returns_404_for_missing_id(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """GET with a non-existent ID returns 404."""
    response = await client.get(
        f"/api/v1/credentials/{uuid4()}",
        headers=auth_headers,
    )
    assert response.status_code == 404


# ── DELETE /api/v1/credentials/{id} ───────────────────────────────


@pytest.mark.asyncio
async def test_delete_credential_returns_204(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """DELETE removes the credential and returns 204 No Content."""
    provider = await _create_provider(db_session)
    create_resp = await client.post(
        "/api/v1/credentials/",
        json=_credential_payload(str(provider.id)),
        headers=auth_headers,
    )
    credential_id = create_resp.json()["id"]

    response = await client.delete(
        f"/api/v1/credentials/{credential_id}",
        headers=auth_headers,
    )

    assert response.status_code == 204
    # Subsequent GET should 404.
    follow_up = await client.get(
        f"/api/v1/credentials/{credential_id}",
        headers=auth_headers,
    )
    assert follow_up.status_code == 404


@pytest.mark.asyncio
async def test_delete_credential_returns_404_for_missing_id(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """DELETE with a non-existent ID returns 404."""
    response = await client.delete(
        f"/api/v1/credentials/{uuid4()}",
        headers=auth_headers,
    )
    assert response.status_code == 404
