"""Target service unit tests.

Exercises ``TargetService`` CRUD: create (with duplicate-value conflict),
get (missing → NotFound), list (active-only branch), update, and delete.
"""

from uuid import uuid4

import pytest

from app.core.exceptions import ConflictException, NotFoundException
from app.schemas.scan_target import ScanTargetCreate, ScanTargetUpdate
from app.services.target_service import TargetService


def _create_payload(value: str = "10.0.0.0/24", name: str = "Target A") -> ScanTargetCreate:
    return ScanTargetCreate(name=name, target_type="cidr", target_value=value)


# ── create ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_target_persists_row(db_session) -> None:
    """Creating a target returns the stored row."""
    service = TargetService(db_session)
    target = await service.create_target(_create_payload())

    assert target.id is not None
    assert target.name == "Target A"
    assert target.target_value == "10.0.0.0/24"
    assert target.is_active is True


@pytest.mark.asyncio
async def test_create_target_rejects_duplicate_value(db_session) -> None:
    """A second target with the same value raises ConflictException."""
    service = TargetService(db_session)
    await service.create_target(_create_payload(value="10.0.0.0/24"))

    with pytest.raises(ConflictException):
        await service.create_target(_create_payload(value="10.0.0.0/24", name="Dup"))


# ── get ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_target_returns_row(db_session) -> None:
    """get_target returns the stored target by id."""
    service = TargetService(db_session)
    created = await service.create_target(_create_payload())

    fetched = await service.get_target(created.id)
    assert fetched.id == created.id


@pytest.mark.asyncio
async def test_get_target_raises_not_found(db_session) -> None:
    """get_target on a missing id raises NotFoundException."""
    service = TargetService(db_session)
    with pytest.raises(NotFoundException):
        await service.get_target(uuid4())


# ── list ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_targets_returns_all(db_session) -> None:
    """list_targets returns every stored target."""
    service = TargetService(db_session)
    await service.create_target(_create_payload(value="10.0.0.0/24", name="A"))
    await service.create_target(_create_payload(value="10.0.1.0/24", name="B"))

    targets = await service.list_targets()
    assert len(targets) == 2


@pytest.mark.asyncio
async def test_list_targets_active_only_filters_inactive(db_session) -> None:
    """active_only returns just the active targets."""
    service = TargetService(db_session)
    created = await service.create_target(_create_payload())
    # Deactivate the target, then verify the active-only filter excludes it.
    await service.update_target(created.id, ScanTargetUpdate(is_active=False))

    active = await service.list_targets(active_only=True)
    assert active == []
    # The unfiltered list still includes the inactive row.
    all_targets = await service.list_targets()
    assert len(all_targets) == 1


# ── update ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_target_changes_name(db_session) -> None:
    """update_target applies the provided fields."""
    service = TargetService(db_session)
    created = await service.create_target(_create_payload())

    updated = await service.update_target(created.id, ScanTargetUpdate(name="Renamed"))
    assert updated.name == "Renamed"


@pytest.mark.asyncio
async def test_update_target_raises_not_found(db_session) -> None:
    """update_target on a missing id raises NotFoundException."""
    service = TargetService(db_session)
    with pytest.raises(NotFoundException):
        await service.update_target(uuid4(), ScanTargetUpdate(name="X"))


# ── delete ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_delete_target_removes_row(db_session) -> None:
    """delete_target removes the row so a follow-up get raises."""
    service = TargetService(db_session)
    created = await service.create_target(_create_payload())

    await service.delete_target(created.id)
    with pytest.raises(NotFoundException):
        await service.get_target(created.id)


@pytest.mark.asyncio
async def test_delete_target_raises_not_found(db_session) -> None:
    """delete_target on a missing id raises NotFoundException."""
    service = TargetService(db_session)
    with pytest.raises(NotFoundException):
        await service.delete_target(uuid4())
