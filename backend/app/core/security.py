"""Security utilities: JWT creation/verification and field-level encryption.

All cryptographic operations use the keys and algorithms defined in
:mod:`app.config`.  Inputs are parsed at the boundary so internal
callers receive trusted, typed values.
"""

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
from cryptography.fernet import Fernet
from jose import JWTError, jwt

from app.config import get_settings

settings = get_settings()


# ── Password hashing ─────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """Return a bcrypt hash of *plain*.

    Uses the ``bcrypt`` library directly rather than the unmaintained
    ``passlib`` wrapper, which is incompatible with bcrypt 5.x.
    """
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Return ``True`` if *plain* matches *hashed*.

    ``bcrypt.checkpw`` raises ``ValueError`` when *hashed* is malformed;
    we treat any such failure as a non-match (Fail Loud at the boundary,
    predictable boolean return for callers).
    """
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


# ── JWT ──────────────────────────────────────────────────────────

def create_access_token(data: dict[str, Any], expires_delta: int | None = None) -> str:
    """Create a signed JWT containing *data*.

    Parameters
    ----------
    data : dict[str, Any]
        Claims to embed in the token.
    expires_delta : int | None
        Lifetime in minutes.  Defaults to ``settings.ACCESS_TOKEN_EXPIRE_MINUTES``.

    Returns
    -------
    str
        Encoded JWT string.
    """
    to_encode = data.copy()
    default_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    expire_minutes = expires_delta if expires_delta is not None else default_minutes
    expire = datetime.now(UTC) + timedelta(minutes=expire_minutes)
    to_encode["exp"] = expire
    token: str = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token


def create_refresh_token(data: dict[str, Any], expires_days: int | None = None) -> str:
    """Create a signed JWT refresh token containing *data*.

    The token always carries a ``type: refresh`` claim and a lifetime
    of *expires_days* (defaults to ``settings.REFRESH_TOKEN_EXPIRE_DAYS``).

    Returns
    -------
    str
        Encoded JWT string.
    """
    to_encode = data.copy()
    default_days = settings.REFRESH_TOKEN_EXPIRE_DAYS
    expire_days = expires_days if expires_days is not None else default_days
    expire = datetime.now(UTC) + timedelta(days=expire_days)
    to_encode["exp"] = expire
    to_encode["type"] = "refresh"
    token: str = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> dict[str, Any] | None:
    """Decode and validate a JWT.

    Returns the payload dict on success, or ``None`` if the token is
    expired or otherwise invalid.  Works for both access and refresh
    tokens — callers inspect the ``type`` claim to distinguish them.
    """
    try:
        payload: dict[str, Any] = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except JWTError:
        return None


# ── Field-level encryption ───────────────────────────────────────

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    """Return a cached Fernet instance, deriving a valid key if needed.

    ``settings.ENCRYPTION_KEY`` is expected to be a valid Fernet key
    (32 URL-safe base64 bytes).  In development it often is not, so when
    the raw value is rejected a valid key is derived by hashing it with
    SHA-256 and base64-encoding the digest — mirroring the fallback used
    by :class:`app.services.credential_service.CloudCredentialService`.
    """
    global _fernet
    if _fernet is not None:
        return _fernet

    raw_key = settings.ENCRYPTION_KEY.encode()
    try:
        fernet = Fernet(raw_key)
    except (ValueError, TypeError):
        derived = base64.urlsafe_b64encode(hashlib.sha256(raw_key).digest())
        fernet = Fernet(derived)
    _fernet = fernet
    return fernet


def encrypt_value(plain_text: str) -> str:
    """Encrypt a string value (e.g. cloud credential secret) for storage."""
    return _get_fernet().encrypt(plain_text.encode()).decode()


def decrypt_value(cipher_text: str) -> str:
    """Decrypt a value previously encrypted with :func:`encrypt_value`."""
    return _get_fernet().decrypt(cipher_text.encode()).decode()
