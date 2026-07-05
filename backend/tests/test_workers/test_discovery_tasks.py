"""Celery discovery task unit tests.

Exercises ``run_cloud_discovery`` and ``_decrypt_credential`` with
mocked provider factory, DB session, and Redis.  The Fernet-based
credential decryption is tested with a real encrypt/decrypt round-trip.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from app.providers.base import DiscoveredIP, ProviderCredential
from app.workers.discovery_tasks import (
    _decrypt_credential,
    _make_sync_session,
    run_cloud_discovery,
)

# ── _make_sync_session ────────────────────────────────────────────


def test_make_sync_session_strips_asyncpg_suffix() -> None:
    """_make_sync_session replaces ``postgresql+asyncpg`` with ``postgresql``."""
    with patch("app.workers.discovery_tasks.create_engine") as mock_engine, \
         patch("app.workers.discovery_tasks.sessionmaker"):
        _make_sync_session()

    sync_url = mock_engine.call_args.args[0]
    assert "+asyncpg" not in sync_url


# ── _decrypt_credential ───────────────────────────────────────────


def test_decrypt_credential_round_trips_fernet_encryption() -> None:
    """A credential encrypted with the app's Fernet key decrypts correctly."""
    import base64
    import hashlib

    from cryptography.fernet import Fernet

    from app.config import get_settings
    raw_key = get_settings().ENCRYPTION_KEY.encode()
    try:
        fernet = Fernet(raw_key)
    except (ValueError, TypeError):
        fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw_key).digest()))

    fields = {"access_key_id": "AKIATEST", "secret_access_key": "secret123"}
    encrypted = fernet.encrypt(json.dumps(fields).encode()).decode()

    cred = MagicMock()
    cred.id = "cred-1"
    cred.credential_type = "access_key"
    cred.encrypted_data = encrypted

    result = _decrypt_credential(cred)

    assert isinstance(result, ProviderCredential)
    assert result.credential_type == "access_key"
    assert result.fields == fields


def test_decrypt_credential_raises_on_missing_data() -> None:
    """A credential with no encrypted_data raises ValueError."""
    cred = MagicMock()
    cred.id = "cred-empty"
    cred.encrypted_data = ""

    with pytest.raises(ValueError, match="no encrypted data"):
        _decrypt_credential(cred)


def test_decrypt_credential_raises_on_corrupt_data() -> None:
    """Corrupt encrypted data raises ValueError."""
    cred = MagicMock()
    cred.id = "cred-corrupt"
    cred.encrypted_data = "not-valid-fernet-token"

    with pytest.raises(ValueError, match="Failed to decrypt"):
        _decrypt_credential(cred)


# ── run_cloud_discovery ───────────────────────────────────────────


def _mock_provider(ips: list[DiscoveredIP] | None = None) -> MagicMock:
    """Build a mock CloudProvider with async discovery methods."""
    async def _discover_ips():
        return ips or []
    async def _discover_rules():
        return []
    async def _discover_lbs():
        return []
    async def _health():
        return True
    async def _get_regions():
        return ["us-east-1"]

    provider = MagicMock()
    provider.discover_ip_addresses = _discover_ips
    provider.discover_security_rules = _discover_rules
    provider.discover_load_balancers = _discover_lbs
    provider.health_check = _health
    provider.get_regions = _get_regions
    return provider


def _mock_cloud_provider_orm(
    provider_id: str = "provider-1",
    name: str = "Test AWS",
    provider_type: str = "aws",
    is_active: bool = True,
    credentials: list[MagicMock] | None = None,
) -> MagicMock:
    """Build a mock CloudProvider ORM instance."""
    return MagicMock(
        id=provider_id,
        name=name,
        provider_type=provider_type,
        is_active=is_active,
        credentials=credentials or [],
    )


def _mock_credential_orm(
    cred_id: str = "cred-1",
    is_active: bool = True,
    fields: dict | None = None,
) -> MagicMock:
    """Build a mock CloudCredential ORM with Fernet-encrypted data."""
    import base64
    import hashlib

    from cryptography.fernet import Fernet

    from app.config import get_settings
    raw_key = get_settings().ENCRYPTION_KEY.encode()
    try:
        fernet = Fernet(raw_key)
    except (ValueError, TypeError):
        fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw_key).digest()))

    encrypted = fernet.encrypt(json.dumps(fields or {}).encode()).decode()

    return MagicMock(
        id=cred_id,
        credential_name="test-cred",
        credential_type="access_key",
        is_active=is_active,
        encrypted_data=encrypted,
    )


def _mock_session(provider: MagicMock | None = None) -> MagicMock:
    """Build a mock sync Session for discovery_tasks."""
    session = MagicMock()
    # ``_load_provider_with_credentials`` uses ``session.scalars(stmt).first()``.
    scalars_result = MagicMock()
    scalars_result.first.return_value = provider
    session.scalars.return_value = scalars_result
    # ``_persist_discovered_ips`` uses ``session.scalar(...)`` and ``session.add(...)``.
    session.scalar.return_value = None  # No existing IP → insert path.
    return session


def test_run_cloud_discovery_persists_discovered_ips() -> None:
    """Discovery discovers IPs and persists them to the database."""
    discovered = [
        DiscoveredIP(ip_address="10.0.0.1", resource_type="ec2_instance"),
        DiscoveredIP(ip_address="10.0.0.2", resource_type="ec2_instance"),
    ]
    mock_provider = _mock_provider(ips=discovered)
    cred = _mock_credential_orm(fields={"access_key_id": "AKIATEST"})
    provider_orm = _mock_cloud_provider_orm(credentials=[cred])
    session = _mock_session(provider=provider_orm)

    with patch("app.workers.discovery_tasks._make_sync_session", return_value=lambda: session), \
         patch("app.workers.discovery_tasks.get_provider", return_value=mock_provider), \
         patch("app.workers.discovery_tasks.publish_progress"):
        result = run_cloud_discovery.apply(args=("provider-1",)).result

    assert result["ips_discovered"] == 2
    assert result["errors"] == []
    # The session should have been committed (IPs persisted) and closed.
    session.commit.assert_called()
    session.close.assert_called()


def test_run_cloud_discovery_returns_error_for_missing_provider() -> None:
    """When the provider does not exist, discovery returns an error summary."""
    session = MagicMock()
    scalars_result = MagicMock()
    scalars_result.first.return_value = None  # Provider not found.
    session.scalars.return_value = scalars_result

    with patch("app.workers.discovery_tasks._make_sync_session", return_value=lambda: session), \
         patch("app.workers.discovery_tasks.publish_progress"):
        result = run_cloud_discovery.apply(args=("nonexistent",)).result

    assert result["ips_discovered"] == 0
    assert len(result["errors"]) >= 1
    assert "not found" in result["errors"][0].lower()


def test_run_cloud_discovery_returns_error_for_inactive_provider() -> None:
    """An inactive provider is skipped with an error message."""
    provider_orm = _mock_cloud_provider_orm(is_active=False)
    session = _mock_session(provider=provider_orm)

    with patch("app.workers.discovery_tasks._make_sync_session", return_value=lambda: session), \
         patch("app.workers.discovery_tasks.publish_progress"):
        result = run_cloud_discovery.apply(args=("provider-1",)).result

    assert result["ips_discovered"] == 0
    assert any("not active" in e.lower() for e in result["errors"])


def test_run_cloud_discovery_returns_error_for_no_active_credentials() -> None:
    """A provider with no active credentials returns an error."""
    cred = _mock_credential_orm(is_active=False)
    provider_orm = _mock_cloud_provider_orm(credentials=[cred])
    session = _mock_session(provider=provider_orm)

    with patch("app.workers.discovery_tasks._make_sync_session", return_value=lambda: session), \
         patch("app.workers.discovery_tasks.publish_progress"):
        result = run_cloud_discovery.apply(args=("provider-1",)).result

    assert result["ips_discovered"] == 0
    assert any("no active credentials" in e.lower() for e in result["errors"])


def test_run_cloud_discovery_deduplicates_ips_across_credentials() -> None:
    """Duplicate IPs from multiple credentials are deduplicated before persisting."""
    discovered = [
        DiscoveredIP(ip_address="10.0.0.1", resource_type="ec2_instance"),
    ]
    mock_provider = _mock_provider(ips=discovered)
    cred1 = _mock_credential_orm(cred_id="cred-1", fields={"key": "v1"})
    cred2 = _mock_credential_orm(cred_id="cred-2", fields={"key": "v2"})
    provider_orm = _mock_cloud_provider_orm(credentials=[cred1, cred2])
    session = _mock_session(provider=provider_orm)

    with patch("app.workers.discovery_tasks._make_sync_session", return_value=lambda: session), \
         patch("app.workers.discovery_tasks.get_provider", return_value=mock_provider), \
         patch("app.workers.discovery_tasks.publish_progress"):
        result = run_cloud_discovery.apply(args=("provider-1",)).result

    # Both credentials discover the same IP; it should be persisted once.
    assert result["ips_discovered"] == 1
