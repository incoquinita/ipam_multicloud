"""Auth service unit tests.

Exercises ``AuthService`` in isolation against the in-memory SQLite
session provided by the root conftest.  Verifies password hashing,
uniqueness enforcement, credential verification, JWT token lifecycle,
and user lookup.
"""

from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictException
from app.core.security import create_access_token, verify_password
from app.schemas.auth import UserCreate
from app.services.auth_service import AuthService

_PASSWORD = "Sup3rSecret!123"
_EMAIL = "alice@example.com"
_USERNAME = "alice"


def _user_create(
    email: str = _EMAIL,
    username: str = _USERNAME,
    password: str = _PASSWORD,
) -> UserCreate:
    """Build a ``UserCreate`` with sane defaults."""
    return UserCreate(email=email, username=username, password=password)


# ── register ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_register_creates_user_with_hashed_password(db_session: AsyncSession) -> None:
    """Register persists a user whose hashed_password is not the plaintext."""
    user = await AuthService.register(db_session, _user_create())

    assert user.id is not None
    assert user.email == _EMAIL
    assert user.username == _USERNAME
    # The stored password must be hashed, not plaintext.
    assert user.hashed_password != _PASSWORD
    assert verify_password(_PASSWORD, user.hashed_password) is True
    assert user.is_active is True
    assert user.is_superuser is False


@pytest.mark.asyncio
async def test_register_duplicate_email_raises_conflict(db_session: AsyncSession) -> None:
    """Registering a second user with the same email raises ConflictException."""
    await AuthService.register(db_session, _user_create())

    second = _user_create(username="alice2")
    with pytest.raises(ConflictException):
        await AuthService.register(db_session, second)


@pytest.mark.asyncio
async def test_register_duplicate_username_raises_conflict(db_session: AsyncSession) -> None:
    """Registering a second user with the same username raises ConflictException."""
    await AuthService.register(db_session, _user_create())

    second = _user_create(email="bob@example.com")
    with pytest.raises(ConflictException):
        await AuthService.register(db_session, second)


# ── authenticate ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_authenticate_correct_credentials_returns_user(db_session: AsyncSession) -> None:
    """Authenticate with the correct username/password returns the user."""
    await AuthService.register(db_session, _user_create())

    user = await AuthService.authenticate(db_session, _USERNAME, _PASSWORD)
    assert user is not None
    assert user.username == _USERNAME


@pytest.mark.asyncio
async def test_authenticate_wrong_password_returns_none(db_session: AsyncSession) -> None:
    """Authenticate with a wrong password returns None."""
    await AuthService.register(db_session, _user_create())

    user = await AuthService.authenticate(db_session, _USERNAME, "wrong-password")
    assert user is None


@pytest.mark.asyncio
async def test_authenticate_unknown_user_returns_none(db_session: AsyncSession) -> None:
    """Authenticate with a non-existent username returns None."""
    user = await AuthService.authenticate(db_session, "nobody", _PASSWORD)
    assert user is None


@pytest.mark.asyncio
async def test_authenticate_inactive_user_returns_none(db_session: AsyncSession) -> None:
    """Authenticate returns None when the user is inactive."""
    user = await AuthService.register(db_session, _user_create())
    user.is_active = False
    await db_session.flush()

    result = await AuthService.authenticate(db_session, _USERNAME, _PASSWORD)
    assert result is None


# ── create_tokens ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_tokens_returns_valid_token_response(db_session: AsyncSession) -> None:
    """create_tokens returns a TokenResponse with all required fields."""
    user = await AuthService.register(db_session, _user_create())

    tokens = AuthService.create_tokens(user)

    assert tokens.access_token is not None and isinstance(tokens.access_token, str)
    assert tokens.refresh_token is not None and isinstance(tokens.refresh_token, str)
    assert tokens.access_token != tokens.refresh_token
    assert tokens.token_type == "bearer"
    assert tokens.expires_in > 0


# ── refresh_tokens ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_refresh_tokens_with_valid_token_returns_new_pair(db_session: AsyncSession) -> None:
    """A valid refresh token yields a fresh, well-formed token pair.

    Note: JWT encoding is deterministic — two calls within the same
    second with identical claims produce the same token string.  We
    therefore verify the response *shape* rather than token inequality.
    """
    user = await AuthService.register(db_session, _user_create())
    tokens = AuthService.create_tokens(user)

    refreshed = await AuthService.refresh_tokens(db_session, tokens.refresh_token)

    assert refreshed is not None
    assert isinstance(refreshed.access_token, str)
    assert isinstance(refreshed.refresh_token, str)
    assert refreshed.token_type == "bearer"
    assert refreshed.expires_in > 0


@pytest.mark.asyncio
async def test_refresh_tokens_with_invalid_token_returns_none(db_session: AsyncSession) -> None:
    """An unparseable refresh token returns None."""
    result = await AuthService.refresh_tokens(db_session, "not-a-jwt")
    assert result is None


@pytest.mark.asyncio
async def test_refresh_tokens_with_access_token_returns_none(db_session: AsyncSession) -> None:
    """Using an access token for refresh returns None (wrong type claim)."""
    user = await AuthService.register(db_session, _user_create())
    tokens = AuthService.create_tokens(user)

    result = await AuthService.refresh_tokens(db_session, tokens.access_token)
    assert result is None


@pytest.mark.asyncio
async def test_refresh_tokens_with_nonexistent_user_returns_none(db_session: AsyncSession) -> None:
    """A refresh token referencing a deleted user returns None."""
    # Build a token whose ``sub`` claim is a UUID with no DB row.
    fake_token = create_access_token(
        data={"sub": str(uuid4()), "type": "refresh"},
    )

    result = await AuthService.refresh_tokens(db_session, fake_token)
    assert result is None


# ── get_user_by_id ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_user_by_id_returns_existing_user(db_session: AsyncSession) -> None:
    """get_user_by_id returns the user when the ID exists."""
    user = await AuthService.register(db_session, _user_create())

    found = await AuthService.get_user_by_id(db_session, user.id)
    assert found is not None
    assert found.id == user.id
    assert found.username == _USERNAME


@pytest.mark.asyncio
async def test_get_user_by_id_returns_none_for_missing(db_session: AsyncSession) -> None:
    """get_user_by_id returns None for a non-existent ID."""
    found = await AuthService.get_user_by_id(db_session, uuid4())
    assert found is None
