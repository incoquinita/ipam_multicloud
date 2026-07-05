"""Authentication service.

Handles user registration, credential verification, and JWT token
lifecycle (access + refresh).  All DB-touching methods accept an
``AsyncSession`` explicitly so they can be invoked from any request
or task context without per-request state.
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictException
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.models.user import User
from app.schemas.auth import TokenResponse, UserCreate

# Access tokens are short-lived (15m); refresh tokens live for days.
_ACCESS_TOKEN_EXPIRE_MINUTES = 15


class AuthService:
    """Stateless authentication operations."""

    @staticmethod
    async def register(db: AsyncSession, user_create: UserCreate) -> User:
        """Create a new user after checking email/username uniqueness.

        Raises
        ------
        ConflictException
            If the email or username is already registered.
        """
        existing_email = await db.execute(
            select(User).where(User.email == user_create.email),
        )
        if existing_email.scalar_one_or_none() is not None:
            raise ConflictException(detail="Email already registered")

        existing_username = await db.execute(
            select(User).where(User.username == user_create.username),
        )
        if existing_username.scalar_one_or_none() is not None:
            raise ConflictException(detail="Username already taken")

        user = User(
            email=user_create.email,
            username=user_create.username,
            hashed_password=hash_password(user_create.password),
        )
        db.add(user)
        await db.flush()
        await db.refresh(user)
        return user

    @staticmethod
    async def authenticate(
        db: AsyncSession, username: str, password: str,
    ) -> User | None:
        """Return the user if *username* / *password* match, else ``None``."""
        result = await db.execute(
            select(User).where(User.username == username),
        )
        user = result.scalar_one_or_none()
        if user is None:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        if not user.is_active:
            return None
        return user

    @staticmethod
    def create_tokens(user: User) -> TokenResponse:
        """Issue a fresh access (15m) + refresh (7d) token pair for *user*."""
        access_token = create_access_token(
            data={
                "sub": str(user.id),
                "username": user.username,
                "type": "access",
            },
            expires_delta=_ACCESS_TOKEN_EXPIRE_MINUTES,
        )
        refresh_token = create_refresh_token(
            data={"sub": str(user.id)},
        )
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    @staticmethod
    async def refresh_tokens(
        db: AsyncSession, refresh_token: str,
    ) -> TokenResponse | None:
        """Validate *refresh_token* and issue a new token pair.

        Returns ``None`` if the token is invalid, expired, or references
        an unknown or inactive user.
        """
        payload = decode_access_token(refresh_token)
        if payload is None:
            return None
        if payload.get("type") != "refresh":
            return None

        sub = payload.get("sub")
        if not isinstance(sub, str):
            return None
        try:
            user_id = UUID(sub)
        except (ValueError, TypeError):
            return None

        user = await AuthService.get_user_by_id(db, user_id)
        if user is None or not user.is_active:
            return None
        return AuthService.create_tokens(user)

    @staticmethod
    async def get_user_by_id(db: AsyncSession, user_id: UUID) -> User | None:
        """Return the user with *user_id*, or ``None`` if not found."""
        result = await db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()
