"""Scan service tests."""

from uuid import uuid4

import pytest

from app.core.exceptions import BadRequestException, NotFoundException
from app.models.ip_address import IPAddress
from app.models.scan_job import ScanJob
from app.models.scan_target import ScanTarget
from app.schemas.scan_job import ScanJobCreate
from app.services.scan_service import ScanService


@pytest.mark.asyncio
async def test_create_scan_with_nonexistent_target_raises(db_session) -> None:
    """Creating a scan with a nonexistent target should raise NotFound."""
    service = ScanService(db_session)
    fake_id = uuid4()
    data = ScanJobCreate(target_id=fake_id, scan_type="quick")

    with pytest.raises(NotFoundException):
        await service.create_scan(data)


@pytest.mark.asyncio
async def test_get_nonexistent_scan_raises(db_session) -> None:
    """Getting a nonexistent scan job should raise NotFound."""
    service = ScanService(db_session)
    fake_id = uuid4()

    with pytest.raises(NotFoundException):
        await service.get_scan(fake_id)


@pytest.mark.asyncio
async def test_list_scans_returns_empty_with_zero_total(db_session) -> None:
    """Listing scans when none exist should return an empty page and zero total."""
    service = ScanService(db_session)
    scans, total = await service.list_scans()
    assert isinstance(scans, list)
    assert len(scans) == 0
    assert total == 0


# ── _expand_cidr_target ────────────────────────────────────────────


def test_expand_cidr_target_wraps_single_ip() -> None:
    """A bare IP (no slash) is wrapped as a single host dict."""
    hosts = ScanService._expand_cidr_target("10.0.0.1")
    assert hosts == [{"host": "10.0.0.1"}]


def test_expand_cidr_target_wraps_hostname() -> None:
    """A hostname (no slash) is wrapped as a single host dict."""
    hosts = ScanService._expand_cidr_target("example.com")
    assert hosts == [{"host": "example.com"}]


def test_expand_cidr_target_expands_small_range() -> None:
    """A /30 CIDR expands to its usable hosts."""
    hosts = ScanService._expand_cidr_target("10.0.0.0/30")
    # /30 has 4 addresses, 2 usable hosts (.1 and .2).
    assert [h["host"] for h in hosts] == ["10.0.0.1", "10.0.0.2"]


def test_expand_cidr_target_rejects_oversized_range() -> None:
    """A CIDR exceeding the expansion cap raises ValueError."""
    with pytest.raises(ValueError, match="exceeding the maximum"):
        ScanService._expand_cidr_target("10.0.0.0/24", max_expansion=4)


# ── _resolve_cloud_targets ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_resolve_cloud_targets_rejects_bad_uuid(db_session) -> None:
    """A non-UUID provider id raises BadRequestException."""
    service = ScanService(db_session)
    with pytest.raises(BadRequestException, match="Invalid cloud provider id"):
        await service._resolve_cloud_targets("not-a-uuid")


@pytest.mark.asyncio
async def test_resolve_cloud_targets_raises_without_discovered_ips(db_session) -> None:
    """A provider with no discovered IPs raises BadRequestException."""
    service = ScanService(db_session)
    provider_id = str(uuid4())
    with pytest.raises(BadRequestException, match="No discovered IPs"):
        await service._resolve_cloud_targets(provider_id)


@pytest.mark.asyncio
async def test_resolve_cloud_targets_returns_discovered_ips(db_session) -> None:
    """Discovered IPs for a provider are returned as host dicts."""
    from app.models.cloud_provider import CloudProvider
    provider = CloudProvider(name="P", provider_type="aws", is_active=True)
    db_session.add(provider)
    await db_session.flush()
    db_session.add(IPAddress(ip_address="10.0.0.9", cloud_provider_id=provider.id))
    await db_session.commit()

    service = ScanService(db_session)
    hosts = await service._resolve_cloud_targets(str(provider.id))
    assert hosts == [{"host": "10.0.0.9"}]


# ── create_scan ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_scan_dispatches_to_celery(db_session, monkeypatch) -> None:
    """create_scan persists a pending job and calls run_port_scan.delay."""
    target = ScanTarget(name="T", target_type="cidr", target_value="10.0.0.0/30")
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    # Stub the Celery dispatch so no broker is required.
    delay_calls: list[dict] = []
    monkeypatch.setattr(
        "app.services.scan_service.run_port_scan.delay",
        lambda **kwargs: delay_calls.append(kwargs),
    )

    service = ScanService(db_session)
    job = await service.create_scan(ScanJobCreate(target_id=target.id, scan_type="quick"))

    assert job.status == "pending"
    assert job.target_id == target.id
    assert len(delay_calls) == 1
    assert delay_calls[0]["scan_job_id"] == str(job.id)


@pytest.mark.asyncio
async def test_create_scan_rejects_inactive_target(db_session) -> None:
    """create_scan on an inactive target raises BadRequestException."""
    target = ScanTarget(name="T", target_type="cidr", target_value="10.0.0.1", is_active=False)
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    service = ScanService(db_session)
    with pytest.raises(BadRequestException, match="inactive target"):
        await service.create_scan(ScanJobCreate(target_id=target.id, scan_type="quick"))


# ── cancel_scan ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cancel_scan_marks_running_job_cancelled(db_session) -> None:
    """cancel_scan on a running job sets status to cancelled."""
    target = ScanTarget(name="T", target_type="cidr", target_value="10.0.0.1")
    db_session.add(target)
    await db_session.flush()
    job = ScanJob(target_id=target.id, scan_type="quick", status="running", progress=10.0)
    db_session.add(job)
    await db_session.commit()
    await db_session.refresh(job)

    service = ScanService(db_session)
    cancelled = await service.cancel_scan(job.id)
    assert cancelled.status == "cancelled"


@pytest.mark.asyncio
async def test_cancel_scan_rejects_completed_job(db_session) -> None:
    """cancel_scan on a completed job raises BadRequestException."""
    target = ScanTarget(name="T", target_type="cidr", target_value="10.0.0.1")
    db_session.add(target)
    await db_session.flush()
    job = ScanJob(target_id=target.id, scan_type="quick", status="completed", progress=100.0)
    db_session.add(job)
    await db_session.commit()
    await db_session.refresh(job)

    service = ScanService(db_session)
    with pytest.raises(BadRequestException, match="Cannot cancel scan in status 'completed'"):
        await service.cancel_scan(job.id)


# ── scan results ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_scan_results_returns_bundle(db_session) -> None:
    """get_scan_results returns the job, port results, and HTTP analyses."""
    from app.models.http_analysis import HttpAnalysis
    from app.models.port_result import PortResult
    target = ScanTarget(name="T", target_type="cidr", target_value="10.0.0.1")
    db_session.add(target)
    await db_session.flush()
    job = ScanJob(target_id=target.id, scan_type="quick", status="completed", progress=100.0)
    db_session.add(job)
    await db_session.flush()
    ip = IPAddress(ip_address="10.0.0.1")
    db_session.add(ip)
    await db_session.flush()
    db_session.add(PortResult(
        scan_job_id=job.id, ip_address_id=ip.id, port=22, protocol="tcp",
        state="open", risk_level="high", risk_score=7.5,
    ))
    db_session.add(HttpAnalysis(
        scan_job_id=job.id, ip_address_id=ip.id, port=80, url="http://10.0.0.1",
    ))
    await db_session.commit()

    service = ScanService(db_session)
    found_job, ports, http = await service.get_scan_results(job.id)
    assert found_job.id == job.id
    assert len(ports) == 1
    assert len(http) == 1


@pytest.mark.asyncio
async def test_get_port_results_returns_page_and_total(db_session) -> None:
    """get_port_results returns a page and the total count."""
    from app.models.port_result import PortResult
    target = ScanTarget(name="T", target_type="cidr", target_value="10.0.0.1")
    db_session.add(target)
    await db_session.flush()
    job = ScanJob(target_id=target.id, scan_type="quick", status="completed", progress=100.0)
    db_session.add(job)
    await db_session.flush()
    ip = IPAddress(ip_address="10.0.0.1")
    db_session.add(ip)
    await db_session.flush()
    db_session.add(PortResult(
        scan_job_id=job.id, ip_address_id=ip.id, port=22, protocol="tcp", state="open",
    ))
    db_session.add(PortResult(
        scan_job_id=job.id, ip_address_id=ip.id, port=80, protocol="tcp", state="open",
    ))
    await db_session.commit()

    service = ScanService(db_session)
    ports, total = await service.get_port_results(job.id, skip=0, limit=1)
    assert len(ports) == 1
    assert total == 2


@pytest.mark.asyncio
async def test_get_http_analyses_returns_page_and_total(db_session) -> None:
    """get_http_analyses returns a page and the total count."""
    from app.models.http_analysis import HttpAnalysis
    target = ScanTarget(name="T", target_type="cidr", target_value="10.0.0.1")
    db_session.add(target)
    await db_session.flush()
    job = ScanJob(target_id=target.id, scan_type="quick", status="completed", progress=100.0)
    db_session.add(job)
    await db_session.flush()
    ip = IPAddress(ip_address="10.0.0.1")
    db_session.add(ip)
    await db_session.flush()
    db_session.add(HttpAnalysis(
        scan_job_id=job.id, ip_address_id=ip.id, port=80, url="http://10.0.0.1",
    ))
    await db_session.commit()

    service = ScanService(db_session)
    http, total = await service.get_http_analyses(job.id)
    assert len(http) == 1
    assert total == 1


@pytest.mark.asyncio
async def test_get_scan_results_raises_not_found(db_session) -> None:
    """get_scan_results on a missing scan raises NotFoundException."""
    service = ScanService(db_session)
    with pytest.raises(NotFoundException):
        await service.get_scan_results(uuid4())
