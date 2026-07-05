"""Auth endpoint integration tests.

Exercises the ``/api/v1/auth`` router end-to-end through the test
ASGI client: register, login, refresh, and profile retrieval.
"""

import pytest
from httpx import AsyncClient

_EMAIL = "alice@example.com"
_USERNAME = "alice"
_PASSWORD = "Sup3rSecret!123"


def _register_payload(
    email: str = _EMAIL,
    username: str = _USERNAME,
    password: str = _PASSWORD,
) -> dict[str, str]:
    """Build a register request body with sane defaults."""
    return {"email": email, "username": username, "password": password}


# ── POST /api/v1/auth/register ────────────────────────────────────


@pytest.mark.asyncio
async def test_register_returns_201_with_valid_data(client: AsyncClient) -> None:
    """Register with a valid payload returns 201 and the user public shape."""
    response = await client.post("/api/v1/auth/register", json=_register_payload())

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == _EMAIL
    assert data["username"] == _USERNAME
    assert data["is_active"] is True
    assert data["is_superuser"] is False
    assert "id" in data
    # The password must never appear in the response.
    assert "password" not in data
    assert "hashed_password" not in data


@pytest.mark.asyncio
async def test_register_returns_409_on_duplicate_email(client: AsyncClient) -> None:
    """Registering twice with the same email returns 409."""
    payload = _register_payload()
    await client.post("/api/v1/auth/register", json=payload)

    # Second call with the same email but a different username.
    duplicate = _register_payload(username="alice2")
    response = await client.post("/api/v1/auth/register", json=duplicate)

    assert response.status_code == 409
    assert "code" in response.json()


@pytest.mark.asyncio
async def test_register_returns_409_on_duplicate_username(client: AsyncClient) -> None:
    """Registering twice with the same username returns 409."""
    await client.post("/api/v1/auth/register", json=_register_payload())

    duplicate = _register_payload(email="bob@example.com")
    response = await client.post("/api/v1/auth/register", json=duplicate)

    assert response.status_code == 409


@pytest.mark.asyncio
async def test_register_returns_422_on_invalid_email(client: AsyncClient) -> None:
    """Register with a malformed email returns 422."""
    payload = _register_payload(email="not-an-email")
    response = await client.post("/api/v1/auth/register", json=payload)

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_returns_422_on_short_password(client: AsyncClient) -> None:
    """Register with a password shorter than 8 chars returns 422."""
    payload = _register_payload(password="short")
    response = await client.post("/api/v1/auth/register", json=payload)

    assert response.status_code == 422


# ── POST /api/v1/auth/login ───────────────────────────────────────


@pytest.mark.asyncio
async def test_login_returns_200_with_valid_credentials(client: AsyncClient) -> None:
    """Login with correct credentials returns 200 and a token pair."""
    await client.post("/api/v1/auth/register", json=_register_payload())

    response = await client.post(
        "/api/v1/auth/login",
        json={"username": _USERNAME, "password": _PASSWORD},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0


@pytest.mark.asyncio
async def test_login_returns_401_with_wrong_password(client: AsyncClient) -> None:
    """Login with a wrong password returns 401."""
    await client.post("/api/v1/auth/register", json=_register_payload())

    response = await client.post(
        "/api/v1/auth/login",
        json={"username": _USERNAME, "password": "wrong-password"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_returns_422_on_missing_fields(client: AsyncClient) -> None:
    """Login with a missing password field returns 422."""
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": _USERNAME},
    )

    assert response.status_code == 422


# ── POST /api/v1/auth/refresh ─────────────────────────────────────


@pytest.mark.asyncio
async def test_refresh_returns_200_with_valid_refresh_token(client: AsyncClient) -> None:
    """Exchanging a valid refresh token returns 200 with a new pair."""
    await client.post("/api/v1/auth/register", json=_register_payload())
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": _USERNAME, "password": _PASSWORD},
    )
    refresh_token = login.json()["refresh_token"]

    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_refresh_returns_401_with_invalid_token(client: AsyncClient) -> None:
    """Exchanging an invalid refresh token returns 401."""
    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "not-a-jwt"},
    )

    assert response.status_code == 401


# ── GET /api/v1/auth/me ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_me_returns_200_with_valid_token(client: AsyncClient) -> None:
    """GET /me with a valid access token returns the user profile."""
    await client.post("/api/v1/auth/register", json=_register_payload())
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": _USERNAME, "password": _PASSWORD},
    )
    access_token = login.json()["access_token"]

    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["username"] == _USERNAME
    assert data["email"] == _EMAIL


@pytest.mark.asyncio
async def test_me_returns_401_without_token(client: AsyncClient) -> None:
    """GET /me without a token returns 401."""
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_returns_401_with_invalid_token(client: AsyncClient) -> None:
    """GET /me with a malformed token returns 401."""
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer not-a-jwt"},
    )
    assert response.status_code == 401
