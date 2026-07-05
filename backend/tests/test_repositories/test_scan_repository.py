"""Scan repository tests."""

from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.scan_repository import ScanRepository


@pytest.mark.asyncio
async def test_create_scan_job(db_session: AsyncSession) -> None:
    """Creating a scan job should persist and return it."""
    repo = ScanRepository(db_session)
    target_id = uuid4()

    job = await repo.create({
        "target_id": target_id,
        "scan_type": "quick",
        "status": "pending",
    })

    assert job.id is not None
    assert job.target_id == target_id
    assert job.scan_type == "quick"
    assert job.status == "pending"


@pytest.mark.asyncio
async def test_get_scan_job(db_session: AsyncSession) -> None:
    """Getting a scan job by ID should return the correct entity."""
    repo = ScanRepository(db_session)
    target_id = uuid4()

    created = await repo.create({
        "target_id": target_id,
        "scan_type": "quick",
        "status": "queued",
    })

    fetched = await repo.get(created.id)
    assert fetched is not None
    assert fetched.id == created.id
    assert fetched.status == "queued"


@pytest.mark.asyncio
async def test_get_nonexistent_job_returns_none(db_session: AsyncSession) -> None:
    """Getting a nonexistent job should return None."""
    repo = ScanRepository(db_session)
    result = await repo.get(uuid4())
    assert result is None


@pytest.mark.asyncio
async def test_get_dashboard_stats_empty(db_session: AsyncSession) -> None:
    """Dashboard stats should return zeros when no jobs exist."""
    repo = ScanRepository(db_session)
    stats = await repo.get_dashboard_stats()

    assert stats["total_scans"] == 0
    assert stats["running"] == 0
    assert stats["completed"] == 0
    assert stats["failed"] == 0


@pytest.mark.asyncio
async def test_update_progress(db_session: AsyncSession) -> None:
    """Updating scan progress should persist the changes."""
    repo = ScanRepository(db_session)
    job = await repo.create({
        "target_id": uuid4(),
        "scan_type": "quick",
        "status": "running",
    })

    await repo.update_progress(job.id, progress=50.0, ips_scanned=10, ports_found=5)

    updated = await repo.get(job.id)
    assert updated is not None
    assert updated.progress == 50.0
    assert updated.ips_scanned == 10
    assert updated.ports_found == 5
