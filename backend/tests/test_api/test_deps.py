"""Dependency callable unit tests.

Exercises ``get_current_user``, ``get_current_active_user``, and
``require_superuser`` directly — calling each with a crafted token or
user object and asserting the return value or raised exception.

Calling the async dependencies directly (rather than through a test
client) keeps the assertions precise: we control exactly which token
claims and user flags reach each function, and we do not need a
superuser-protected route (none exist in the v1 router yet) to verify
``require_superuser``.
"""

from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_active_user, get_current_user, require_superuser
from app.core.exceptions import ForbiddenException, UnauthorizedException
from app.core.security import create_access_token, hash_password
from app.models.user import User
from app.services.auth_service import AuthService


async def _make_user(
    db: AsyncSession,
    username: str = "dep_user",
    is_active: bool = True,
    is_superuser: bool = False,
) -> User:
    """Persist and return a user with the given flags."""
    user = User(
        email=f"{username}@example.com",
        username=username,
        hashed_password=hash_password("Password123!"),
        is_active=is_active,
        is_superuser=is_superuser,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


# ── get_current_user ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_current_user_with_valid_token_returns_user(db_session: AsyncSession) -> None:
    """A valid access token resolves to the matching user row."""
    user = await _make_user(db_session)
    token = create_access_token(
        data={"sub": str(user.id), "username": user.username, "type": "access"},
    )

    result = await get_current_user(token=token, db=db_session)
    assert result.id == user.id
    assert result.username == user.username


@pytest.mark.asyncio
async def test_get_current_user_with_invalid_token_raises_unauthorized(
    db_session: AsyncSession,
) -> None:
    """A malformed token raises UnauthorizedException (401)."""
    with pytest.raises(UnauthorizedException):
        await get_current_user(token="not-a-jwt", db=db_session)


@pytest.mark.asyncio
async def test_get_current_user_with_refresh_token_raises_unauthorized(
    db_session: AsyncSession,
) -> None:
    """A refresh token (wrong type claim) is rejected by get_current_user."""
    user = await _make_user(db_session)
    # Build a token with type=refresh (wrong type for access-gated endpoints).
    token = create_access_token(
        data={"sub": str(user.id), "type": "refresh"},
    )

    with pytest.raises(UnauthorizedException):
        await get_current_user(token=token, db=db_session)


@pytest.mark.asyncio
async def test_get_current_user_with_nonexistent_user_raises_unauthorized(
    db_session: AsyncSession,
) -> None:
    """A token referencing a deleted user raises UnauthorizedException."""
    token = create_access_token(
        data={"sub": str(uuid4()), "type": "access"},
    )

    with pytest.raises(UnauthorizedException):
        await get_current_user(token=token, db=db_session)


@pytest.mark.asyncio
async def test_get_current_user_with_non_string_subject_raises_unauthorized(
    db_session: AsyncSession, monkeypatch,
) -> None:
    """A token whose ``sub`` is not a string is rejected at the boundary.

    A real JWT cannot carry a non-string ``sub`` (jose rejects it on
    decode), so ``decode_access_token`` is stubbed to return the
    invalid-claim payload directly — exercising the subject-type guard.
    """
    monkeypatch.setattr(
        "app.api.deps.decode_access_token",
        lambda _token: {"sub": 12345, "type": "access"},
    )

    with pytest.raises(UnauthorizedException, match="Invalid token subject"):
        await get_current_user(token="stubbed", db=db_session)


@pytest.mark.asyncio
async def test_get_current_user_with_non_uuid_subject_raises_unauthorized(
    db_session: AsyncSession,
) -> None:
    """A token whose ``sub`` is not a UUID is rejected at the boundary."""
    token = create_access_token(data={"sub": "not-a-uuid", "type": "access"})

    with pytest.raises(UnauthorizedException, match="Invalid token subject"):
        await get_current_user(token=token, db=db_session)


# ── get_current_active_user ───────────────────────────────────────


@pytest.mark.asyncio
async def test_get_current_active_user_with_active_user_returns_user(
    db_session: AsyncSession,
) -> None:
    """An active user passes through unchanged."""
    user = await _make_user(db_session, is_active=True)

    result = await get_current_active_user(current_user=user)
    assert result.id == user.id
    assert result.is_active is True


@pytest.mark.asyncio
async def test_get_current_active_user_with_inactive_user_raises_forbidden(
    db_session: AsyncSession,
) -> None:
    """An inactive user triggers ForbiddenException (403)."""
    user = await _make_user(db_session, is_active=False)

    with pytest.raises(ForbiddenException):
        await get_current_active_user(current_user=user)


# ── require_superuser ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_require_superuser_with_superuser_returns_user(
    db_session: AsyncSession,
) -> None:
    """A superuser passes the superuser gate."""
    user = await _make_user(db_session, is_superuser=True)

    result = await require_superuser(current_user=user)
    assert result.id == user.id
    assert result.is_superuser is True


@pytest.mark.asyncio
async def test_require_superuser_with_non_superuser_raises_forbidden(
    db_session: AsyncSession,
) -> None:
    """A non-superuser triggers ForbiddenException (403)."""
    user = await _make_user(db_session, is_superuser=False)

    with pytest.raises(ForbiddenException):
        await require_superuser(current_user=user)


@pytest.mark.asyncio
async def test_require_superuser_with_inactive_user_propagates_forbidden(
    db_session: AsyncSession,
) -> None:
    """require_superuser also rejects inactive users (via get_current_active_user).

    In practice, ``require_superuser`` depends on ``get_current_active_user``,
    so an inactive user is rejected before the superuser check.  Here we
    pass an inactive user directly to verify the superuser gate itself
    raises ForbiddenException for the non-superuser flag.
    """
    user = await _make_user(db_session, is_active=False, is_superuser=False)

    with pytest.raises(ForbiddenException):
        await require_superuser(current_user=user)


# ── Integration: AuthService tokens flow through deps ──────────────


@pytest.mark.asyncio
async def test_full_token_pipeline_resolves_through_get_current_user(
    db_session: AsyncSession,
) -> None:
    """Tokens issued by AuthService.create_tokens are accepted by get_current_user."""
    from app.schemas.auth import UserCreate

    user = await AuthService.register(
        db_session,
        UserCreate(email="pipe@example.com", username="pipe", password="Password123!"),
    )
    await db_session.commit()
    tokens = AuthService.create_tokens(user)

    resolved = await get_current_user(token=tokens.access_token, db=db_session)
    assert resolved.id == user.id
