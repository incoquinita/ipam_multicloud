"""Cloud service unit tests.

Exercises ``CloudService`` CRUD (create/get/list/update/delete) and the
discovery orchestration (``run_discovery``) with a mocked provider
instance — no real cloud API calls are made.
"""

from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundException
from app.models.cloud_credential import CloudCredential
from app.models.cloud_provider import CloudProvider
from app.providers.base import DiscoveredIP, ProviderCredential
from app.schemas.cloud_provider import CloudProviderCreate, CloudProviderUpdate
from app.services.cloud_service import CloudService


def _create_payload(name: str = "AWS Prod") -> CloudProviderCreate:
    return CloudProviderCreate(
        name=name, provider_type="aws", regions=["us-east-1", "us-west-2"],
    )


# ── CRUD ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_provider_flattens_regions_to_csv(db_session) -> None:
    """create_provider joins the regions list into a comma-separated string."""
    service = CloudService(db_session)
    provider = await service.create_provider(_create_payload())

    assert provider.id is not None
    assert provider.regions == "us-east-1,us-west-2"
    assert provider.is_active is True


@pytest.mark.asyncio
async def test_get_provider_raises_not_found(db_session) -> None:
    """get_provider on a missing id raises NotFoundException."""
    from uuid import uuid4
    service = CloudService(db_session)
    with pytest.raises(NotFoundException):
        await service.get_provider(uuid4())


@pytest.mark.asyncio
async def test_list_providers_returns_all_and_active_only(db_session) -> None:
    """list_providers returns all, or just active when active_only=True."""
    service = CloudService(db_session)
    created = await service.create_provider(_create_payload(name="A"))
    await service.update_provider(
        created.id, CloudProviderUpdate(is_active=False),
    )
    await service.create_provider(_create_payload(name="B"))

    assert len(await service.list_providers()) == 2
    assert len(await service.list_providers(active_only=True)) == 1


@pytest.mark.asyncio
async def test_update_provider_changes_name_and_regions(db_session) -> None:
    """update_provider applies name and regions updates."""
    service = CloudService(db_session)
    created = await service.create_provider(_create_payload())

    updated = await service.update_provider(
        created.id,
        CloudProviderUpdate(name="Renamed", regions=["eu-west-1"]),
    )
    assert updated.name == "Renamed"
    assert updated.regions == "eu-west-1"


@pytest.mark.asyncio
async def test_update_provider_raises_not_found(db_session) -> None:
    """update_provider on a missing id raises NotFoundException."""
    from uuid import uuid4
    service = CloudService(db_session)
    with pytest.raises(NotFoundException):
        await service.update_provider(uuid4(), CloudProviderUpdate(name="X"))


@pytest.mark.asyncio
async def test_delete_provider_removes_row(db_session) -> None:
    """delete_provider removes the row."""
    service = CloudService(db_session)
    created = await service.create_provider(_create_payload())

    await service.delete_provider(created.id)
    with pytest.raises(NotFoundException):
        await service.get_provider(created.id)


@pytest.mark.asyncio
async def test_delete_provider_raises_not_found(db_session) -> None:
    """delete_provider on a missing id raises NotFoundException."""
    from uuid import uuid4
    service = CloudService(db_session)
    with pytest.raises(NotFoundException):
        await service.delete_provider(uuid4())


# ── run_discovery orchestration ────────────────────────────────────


async def _seed_active_provider_with_credential(db: AsyncSession) -> CloudProvider:
    """Persist an active provider with one (dummy) encrypted credential."""
    provider = CloudProvider(name="AWS Disc", provider_type="aws", is_active=True)
    db.add(provider)
    await db.flush()
    db.add(CloudCredential(
        cloud_provider_id=provider.id,
        credential_type="access_key",
        credential_name="default",
        encrypted_data="dummy-blob",
        is_active=True,
    ))
    await db.commit()
    # Reload with the credentials relationship populated.
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    stmt = (
        select(CloudProvider)
        .where(CloudProvider.id == provider.id)
        .options(selectinload(CloudProvider.credentials))
    )
    result = await db.execute(stmt)
    return result.scalar_one()


@pytest.mark.asyncio
async def test_run_discovery_no_providers_returns_empty_summary(db_session) -> None:
    """run_discovery with no active providers returns a zero-IP summary."""
    service = CloudService(db_session)
    summary = await service.run_discovery()

    assert summary["total_ips"] == 0
    assert summary["provider_breakdown"] == {}
    assert summary["errors"] == []


@pytest.mark.asyncio
async def test_run_discovery_persists_discovered_ips(
    db_session, monkeypatch,
) -> None:
    """run_discovery decrypts credentials, calls the provider, and stores IPs."""
    provider = await _seed_active_provider_with_credential(db_session)
    service = CloudService(db_session)

    # Bypass real decryption — return a parsed credential.
    monkeypatch.setattr(
        service.credential_service,
        "decrypt_credential",
        lambda cred: ProviderCredential(
            credential_type="access_key",
            fields={"access_key": "AKIA", "secret_key": "shh"},
        ),
    )

    # Fake provider instance whose discover methods return canned data.
    fake = AsyncMock()
    fake.discover_ip_addresses.return_value = [
        DiscoveredIP(ip_address="10.0.0.1", resource_type="aws_instance", region="us-east-1"),
        DiscoveredIP(ip_address="10.0.0.2", resource_type="aws_instance", region="us-east-1"),
    ]
    fake.discover_security_rules.return_value = []
    fake.discover_load_balancers.return_value = []
    monkeypatch.setattr("app.services.cloud_service.get_provider", lambda _pt, _c: fake)

    summary = await service.run_discovery()

    assert summary["total_ips"] == 2
    assert summary["provider_breakdown"]["AWS Disc"] == 2
    assert summary["errors"] == []
    fake.discover_ip_addresses.assert_awaited_once()
    fake.discover_security_rules.assert_awaited_once()
    fake.discover_load_balancers.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_discovery_provider_without_credentials_records_error(
    db_session,
) -> None:
    """A provider with no credentials is skipped and logged in errors."""
    provider = CloudProvider(name="No Cred", provider_type="aws", is_active=True)
    db_session.add(provider)
    await db_session.commit()

    service = CloudService(db_session)
    summary = await service.run_discovery()

    assert summary["total_ips"] == 0
    assert any("no active credentials" in e for e in summary["errors"])


@pytest.mark.asyncio
async def test_run_discovery_handles_provider_instantiation_failure(
    db_session, monkeypatch,
) -> None:
    """A factory that raises is recorded as an error, not a crash."""
    provider = await _seed_active_provider_with_credential(db_session)
    service = CloudService(db_session)
    monkeypatch.setattr(
        service.credential_service,
        "decrypt_credential",
        lambda cred: ProviderCredential(credential_type="access_key", fields={}),
    )

    def _boom(_pt, _c):
        raise RuntimeError("factory down")
    monkeypatch.setattr("app.services.cloud_service.get_provider", _boom)

    summary = await service.run_discovery()
    assert any("failed to instantiate provider" in e for e in summary["errors"])
    assert summary["total_ips"] == 0
