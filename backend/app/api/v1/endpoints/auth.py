"""Authentication endpoints — register, login, refresh, and profile.

All endpoints are mounted under ``/api/v1/auth`` and produce JSON
responses.  Login and register are rate-limited per IP to slow brute
force attempts; refresh relies on the global rate limiter.
"""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.exceptions import UnauthorizedException
from app.dependencies import get_db
from app.middleware.rate_limit import rate_limiter
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    TokenRefresh,
    TokenResponse,
    UserCreate,
    UserResponse,
)
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserResponse, status_code=201)
@rate_limiter.limit("5/minute")
async def register(
    request: Request,  # noqa: ARG001 - required by slowapi decorator
    data: UserCreate,
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Register a new user account.

    Rate-limited to 5 requests per minute per IP to slow abuse.
    """
    user = await AuthService.register(db, data)
    return UserResponse.model_validate(user)


@router.post("/login", response_model=TokenResponse)
@rate_limiter.limit("10/minute")
async def login(
    request: Request,  # noqa: ARG001 - required by slowapi decorator
    data: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticate credentials and issue an access + refresh token pair.

    Rate-limited to 10 requests per minute per IP to slow brute force.
    Returns 401 if the username/password pair is invalid or the user
    is inactive — the message is intentionally generic.
    """
    user = await AuthService.authenticate(db, data.username, data.password)
    if user is None:
        raise UnauthorizedException(detail="Invalid username or password")
    return AuthService.create_tokens(user)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    data: TokenRefresh,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Exchange a valid refresh token for a new token pair.

    Returns 401 if the refresh token is invalid, expired, or references
    an inactive user.
    """
    token_pair = await AuthService.refresh_tokens(db, data.refresh_token)
    if token_pair is None:
        raise UnauthorizedException(detail="Invalid or expired refresh token")
    return token_pair


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)) -> UserResponse:
    """Return the profile of the authenticated user."""
    return UserResponse.model_validate(current_user)
