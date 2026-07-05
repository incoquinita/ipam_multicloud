"""Port result listing endpoint integration tests.

Exercises ``GET /api/v1/port-results/`` — paginated, filterable by
scan job, port number, risk level, and port state.  Invalid filter
values are rejected with 400 so callers cannot silently match nothing.
"""


import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ip_address import IPAddress
from app.models.port_result import PortResult
from app.models.scan_job import ScanJob
from app.models.scan_target import ScanTarget


async def _seed_port_results(db: AsyncSession) -> tuple[ScanJob, list[PortResult]]:
    """Persist a scan job with three port results (varied risk and state)."""
    target = ScanTarget(name="PR Target", target_type="cidr", target_value="10.0.0.0/24")
    db.add(target)
    await db.flush()

    job = ScanJob(target_id=target.id, scan_type="quick", status="completed", progress=100.0)
    db.add(job)
    await db.flush()

    ip = IPAddress(ip_address="10.0.0.10")
    db.add(ip)
    await db.flush()

    ports = [
        PortResult(
            scan_job_id=job.id, ip_address_id=ip.id, port=22, protocol="tcp",
            state="open", risk_level="high", risk_score=7.5,
        ),
        PortResult(
            scan_job_id=job.id, ip_address_id=ip.id, port=80, protocol="tcp",
            state="open", risk_level="medium", risk_score=4.5,
        ),
        PortResult(
            scan_job_id=job.id, ip_address_id=ip.id, port=443, protocol="tcp",
            state="closed", risk_level="low", risk_score=2.0,
        ),
    ]
    db.add_all(ports)
    await db.commit()
    for p in ports:
        await db.refresh(p)
    return job, ports


# ── GET /api/v1/port-results/ ─────────────────────────────────────


@pytest.mark.asyncio
async def test_list_port_results_returns_paginated_list(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /port-results/ returns all results with pagination metadata."""
    _job, _ports = await _seed_port_results(db_session)

    response = await client.get(
        "/api/v1/port-results/",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3
    assert data["page"] == 1
    assert data["total_pages"] == 1


@pytest.mark.asyncio
async def test_list_port_results_filters_by_risk_level(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /port-results/?risk_level=high returns only HIGH-risk results."""
    _job, _ports = await _seed_port_results(db_session)

    response = await client.get(
        "/api/v1/port-results/?risk_level=high",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["risk_level"] == "high"


@pytest.mark.asyncio
async def test_list_port_results_filters_by_state(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /port-results/?state=open returns only open-state results."""
    _job, _ports = await _seed_port_results(db_session)

    response = await client.get(
        "/api/v1/port-results/?state=open",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    for item in data["items"]:
        assert item["state"] == "open"


@pytest.mark.asyncio
async def test_list_port_results_filters_by_scan_job(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /port-results/?scan_job_id=... returns only results for that job."""
    job, _ports = await _seed_port_results(db_session)

    response = await client.get(
        f"/api/v1/port-results/?scan_job_id={job.id}",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    for item in data["items"]:
        assert item["scan_job_id"] == str(job.id)


@pytest.mark.asyncio
async def test_list_port_results_filters_by_port(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /port-results/?port=22 returns only results for port 22."""
    _job, _ports = await _seed_port_results(db_session)

    response = await client.get(
        "/api/v1/port-results/?port=22",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["port"] == 22


# ── Invalid filters ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_port_results_returns_400_on_invalid_risk_level(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """GET /port-results/?risk_level=bogus returns 400."""
    response = await client.get(
        "/api/v1/port-results/?risk_level=bogus",
        headers=auth_headers,
    )

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_list_port_results_returns_400_on_invalid_state(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """GET /port-results/?state=bogus returns 400."""
    response = await client.get(
        "/api/v1/port-results/?state=bogus",
        headers=auth_headers,
    )

    assert response.status_code == 400


# ── Auth ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_port_results_returns_401_without_auth(client: AsyncClient) -> None:
    """GET /port-results/ without auth returns 401."""
    response = await client.get("/api/v1/port-results/")
    assert response.status_code == 401
