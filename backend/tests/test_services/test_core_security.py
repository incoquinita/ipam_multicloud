"""Security utility unit tests.

Exercises password verification (including the malformed-hash guard),
JWT creation/decode round-trips, the invalid-token guard, and the
field-level encrypt/decrypt helpers.
"""

from __future__ import annotations

import pytest

from app.core import security
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decrypt_value,
    encrypt_value,
    hash_password,
    verify_password,
)


# ── Password hashing ───────────────────────────────────────────────


def test_hash_and_verify_password_round_trip() -> None:
    """A hashed password verifies against the original plaintext."""
    hashed = hash_password("S3cret!")
    assert hashed != "S3cret!"
    assert verify_password("S3cret!", hashed) is True
    assert verify_password("wrong", hashed) is False


def test_verify_password_returns_false_on_malformed_hash() -> None:
    """A malformed hash fails fast as a non-match rather than raising."""
    assert verify_password("anything", "not-a-real-bcrypt-hash") is False


# ── JWT ────────────────────────────────────────────────────────────


def test_create_and_decode_access_token_round_trips() -> None:
    """An access token decodes back to the embedded claims."""
    token = create_access_token({"sub": "user-1"}, expires_delta=60)
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "user-1"
    assert "exp" in payload


def test_decode_access_token_returns_none_for_garbage() -> None:
    """An invalid token returns None instead of raising."""
    assert decode_access_token("not.a.jwt") is None


def test_create_refresh_token_carries_type_claim() -> None:
    """A refresh token carries the ``type: refresh`` claim."""
    token = create_refresh_token({"sub": "user-1"}, expires_days=7)
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "user-1"
    assert payload["type"] == "refresh"


# ── Field-level encryption ─────────────────────────────────────────


def test_encrypt_and_decrypt_value_round_trips() -> None:
    """encrypt_value / decrypt_value are inverses."""
    cipher = encrypt_value("super-secret")
    assert cipher != "super-secret"
    assert decrypt_value(cipher) == "super-secret"


def test_get_fernet_falls_back_to_derived_key(monkeypatch) -> None:
    """A non-Fernet encryption key triggers the SHA-256 derivation fallback."""
    # Reset the cached instance so the fallback path runs again.
    monkeypatch.setattr(security, "_fernet", None)
    # Force a key that Fernet will reject, exercising the except branch.
    monkeypatch.setattr(security.settings, "ENCRYPTION_KEY", "short-bad-key")

    cipher = encrypt_value("round-trip")
    assert decrypt_value(cipher) == "round-trip"
