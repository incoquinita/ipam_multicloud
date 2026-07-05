"""Credential service unit tests.

Exercises the Fernet encrypt/decrypt round-trip, credential listing and
counting with filters, the decrypt-and-parse path, and the error guards
(missing provider, missing credential, undecryptable blob).
"""

from uuid import uuid4

import pytest

from app.core.exceptions import NotFoundException
from app.models.cloud_credential import CloudCredential
from app.models.cloud_provider import CloudProvider
from app.services.credential_service import CloudCredentialService


@pytest.fixture
async def provider(db_session) -> CloudProvider:
    """Persist a cloud provider for credential FKs."""
    p = CloudProvider(name="AWS Test", provider_type="aws", is_active=True)
    db_session.add(p)
    await db_session.commit()
    await db_session.refresh(p)
    return p


# ── encrypt / decrypt round-trip ───────────────────────────────────


@pytest.mark.asyncio
async def test_encrypt_and_store_round_trips(db_session, provider) -> None:
    """Encrypted credentials decrypt back to the original fields."""
    service = CloudCredentialService(db_session)
    cred = await service.encrypt_and_store(
        cloud_provider_id=provider.id,
        credential_type="access_key",
        credential_name="default",
        fields_dict={"access_key": "AKIA...", "secret_key": "shh"},
    )

    assert cred.encrypted_data != "AKIA..."
    parsed = service.decrypt_credential(cred)
    assert parsed.credential_type == "access_key"
    assert parsed.fields == {"access_key": "AKIA...", "secret_key": "shh"}


@pytest.mark.asyncio
async def test_decrypt_and_parse_raises_not_found(db_session) -> None:
    """decrypt_and_parse on a missing id raises NotFoundException."""
    service = CloudCredentialService(db_session)
    with pytest.raises(NotFoundException):
        await service.decrypt_and_parse(uuid4())


@pytest.mark.asyncio
async def test_decrypt_credential_rejects_empty_blob(db_session, provider) -> None:
    """decrypt_credential fails fast on a credential with no data."""
    service = CloudCredentialService(db_session)
    cred = CloudCredential(
        cloud_provider_id=provider.id,
        credential_type="access_key",
        credential_name="empty",
        encrypted_data="",
        is_active=True,
    )
    db_session.add(cred)
    await db_session.flush()

    with pytest.raises(ValueError, match="no encrypted data"):
        service.decrypt_credential(cred)


@pytest.mark.asyncio
async def test_decrypt_credential_rejects_garbage_blob(db_session, provider) -> None:
    """decrypt_credential wraps undecryptable data in a ValueError."""
    service = CloudCredentialService(db_session)
    cred = CloudCredential(
        cloud_provider_id=provider.id,
        credential_type="access_key",
        credential_name="garbage",
        encrypted_data="not-a-real-fernet-token",
        is_active=True,
    )
    db_session.add(cred)
    await db_session.flush()

    with pytest.raises(ValueError, match="Failed to decrypt"):
        service.decrypt_credential(cred)


# ── create_credential ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_credential_raises_for_missing_provider(db_session) -> None:
    """create_credential refuses to encrypt for a non-existent provider."""
    service = CloudCredentialService(db_session)
    with pytest.raises(NotFoundException):
        await service.create_credential(
            cloud_provider_id=uuid4(),
            credential_type="access_key",
            credential_name="default",
            fields={"access_key": "x"},
        )


@pytest.mark.asyncio
async def test_create_credential_stores_for_known_provider(db_session, provider) -> None:
    """create_credential encrypts and stores when the provider exists."""
    service = CloudCredentialService(db_session)
    cred = await service.create_credential(
        cloud_provider_id=provider.id,
        credential_type="access_key",
        credential_name="default",
        fields={"access_key": "AKIA"},
    )
    assert cred.credential_name == "default"
    assert cred.is_active is True


# ── list / count ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_and_count_credentials_with_filters(db_session, provider) -> None:
    """list/count honour the provider and active-only filters."""
    service = CloudCredentialService(db_session)
    await service.create_credential(
        cloud_provider_id=provider.id,
        credential_type="access_key",
        credential_name="active",
        fields={"access_key": "a"},
    )

    all_creds = await service.list_credentials()
    assert len(all_creds) == 1
    for_provider = await service.list_credentials(cloud_provider_id=provider.id)
    assert len(for_provider) == 1
    active_only = await service.list_credentials(active_only=True)
    assert len(active_only) == 1

    assert await service.count_credentials() == 1
    assert await service.count_credentials(cloud_provider_id=provider.id) == 1
    assert await service.count_credentials(active_only=True) == 1


@pytest.mark.asyncio
async def test_get_active_credentials_for_provider(db_session, provider) -> None:
    """get_active_credentials_for_provider returns only active rows."""
    service = CloudCredentialService(db_session)
    await service.create_credential(
        cloud_provider_id=provider.id,
        credential_type="access_key",
        credential_name="a",
        fields={"k": "v"},
    )
    active = await service.get_active_credentials_for_provider(provider.id)
    assert len(active) == 1
    assert active[0].is_active is True


@pytest.mark.asyncio
async def test_get_decrypted_credentials_skips_bad_rows(db_session, provider) -> None:
    """Undecryptable credentials are skipped, not fatal."""
    service = CloudCredentialService(db_session)
    # One good credential.
    await service.create_credential(
        cloud_provider_id=provider.id,
        credential_type="access_key",
        credential_name="good",
        fields={"k": "v"},
    )
    # One bad credential (empty blob) directly in the session.
    db_session.add(CloudCredential(
        cloud_provider_id=provider.id,
        credential_type="access_key",
        credential_name="bad",
        encrypted_data="",
        is_active=True,
    ))
    await db_session.commit()

    decrypted = await service.get_decrypted_credentials_for_provider(provider.id)
    # Only the good credential decrypts; the bad one is skipped.
    assert len(decrypted) == 1
    assert decrypted[0].fields == {"k": "v"}


# ── get_by_id / delete ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_by_id_raises_not_found(db_session) -> None:
    """get_by_id on a missing id raises NotFoundException."""
    service = CloudCredentialService(db_session)
    with pytest.raises(NotFoundException):
        await service.get_by_id(uuid4())


@pytest.mark.asyncio
async def test_delete_credential_removes_row(db_session, provider) -> None:
    """delete_credential removes the row."""
    service = CloudCredentialService(db_session)
    cred = await service.create_credential(
        cloud_provider_id=provider.id,
        credential_type="access_key",
        credential_name="del",
        fields={"k": "v"},
    )

    await service.delete_credential(cred.id)
    with pytest.raises(NotFoundException):
        await service.get_by_id(cred.id)


@pytest.mark.asyncio
async def test_delete_credential_raises_not_found(db_session) -> None:
    """delete_credential on a missing id raises NotFoundException."""
    service = CloudCredentialService(db_session)
    with pytest.raises(NotFoundException):
        await service.delete_credential(uuid4())
