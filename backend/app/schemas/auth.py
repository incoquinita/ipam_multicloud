"""Pydantic schemas for authentication — registration, login, and tokens."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    """Payload for registering a new user."""

    email: EmailStr = Field(..., description="Unique email address")
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern=r"^[A-Za-z0-9_]+$",
        description="Unique username (letters, digits, underscore)",
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Account password (plaintext; hashed at rest)",
    )


class UserResponse(BaseModel):
    """Public user representation returned from auth endpoints."""

    id: UUID
    email: str
    username: str
    is_active: bool
    is_superuser: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    """Credentials submitted to obtain a token pair."""

    username: str
    password: str


class TokenResponse(BaseModel):
    """Access + refresh token pair issued after login or refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenRefresh(BaseModel):
    """Payload for exchanging a refresh token for a new pair."""

    refresh_token: str
