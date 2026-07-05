"""Authentication and authorization dependencies.

Provides FastAPI dependency callables that decode the JWT bearer token,
load the active user, and enforce role-based access control.  These
dependencies are the single entry point for protecting any v1 endpoint.

Flow::

    oauth2_scheme ─► get_current_user ─► get_current_active_user ─► require_superuser
"""

from uuid import UUID

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ForbiddenException, UnauthorizedException
from app.core.security import decode_access_token
from app.dependencies import get_db
from app.models.user import User
from app.services.auth_service import AuthService

# ``tokenUrl`` is the OpenAPI hint Swagger UI uses for the Authorize flow.
# The actual login endpoint accepts a JSON body (LoginRequest) for
# frontend compatibility rather than the OAuth2 form-encoded flow.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Decode the bearer token and return the authenticated user.

    Raises
    ------
    UnauthorizedException
        If the token is missing, malformed, expired, references an
        unknown user, or is not an access token.

    Notes
    -----
    JWT decode errors are handled inside :func:`decode_access_token`
    which returns ``None`` for any ``JWTError`` — this boundary parser
    keeps the caller free of try/except noise.
    """
    payload = decode_access_token(token)
    if payload is None:
        raise UnauthorizedException(detail="Invalid or expired token")

    if payload.get("type") != "access":
        raise UnauthorizedException(detail="Invalid token type")

    sub = payload.get("sub")
    if not isinstance(sub, str):
        raise UnauthorizedException(detail="Invalid token subject")

    try:
        user_id = UUID(sub)
    except (ValueError, TypeError):
        raise UnauthorizedException(detail="Invalid token subject") from None

    user = await AuthService.get_user_by_id(db, user_id)
    if user is None:
        raise UnauthorizedException(detail="User not found")

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Return the current user if their account is active, else 403."""
    if not current_user.is_active:
        raise ForbiddenException(detail="Inactive user")
    return current_user


async def require_superuser(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """Return the current user if they hold superuser privileges, else 403."""
    if not current_user.is_superuser:
        raise ForbiddenException(detail="Superuser privileges required")
    return current_user
