"""Scan results and dashboard endpoint integration tests.

Exercises the scan-results bundle, paginated port/HTTP result listings,
and the aggregate dashboard stats endpoint.  Each test seeds a scan job
with related port results and HTTP analyses, then verifies the response
shape returned by the v1 endpoints.
"""

from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.http_analysis import HttpAnalysis
from app.models.ip_address import IPAddress
from app.models.port_result import PortResult
from app.models.scan_job import ScanJob
from app.models.scan_target import ScanTarget


async def _seed_scan_with_results(
    db: AsyncSession,
) -> tuple[ScanJob, list[PortResult], list[HttpAnalysis]]:
    """Persist a scan job with two port results and one HTTP analysis.

    Returns the ``(job, port_results, http_analyses)`` triple so tests
    can assert against specific IDs.
    """
    target = ScanTarget(name="Target A", target_type="cidr", target_value="10.0.0.0/24")
    db.add(target)
    await db.flush()

    job = ScanJob(
        target_id=target.id,
        scan_type="quick",
        status="completed",
        progress=100.0,
        total_ips=1,
        ips_scanned=1,
        ports_found=2,
    )
    db.add(job)
    await db.flush()

    ip = IPAddress(ip_address="10.0.0.1")
    db.add(ip)
    await db.flush()

    port1 = PortResult(
        scan_job_id=job.id,
        ip_address_id=ip.id,
        port=22,
        protocol="tcp",
        state="open",
        service_name="SSH",
        risk_level="high",
        risk_score=7.5,
    )
    port2 = PortResult(
        scan_job_id=job.id,
        ip_address_id=ip.id,
        port=80,
        protocol="tcp",
        state="open",
        service_name="HTTP",
        risk_level="medium",
        risk_score=4.5,
    )
    db.add_all([port1, port2])
    await db.flush()

    http1 = HttpAnalysis(
        scan_job_id=job.id,
        ip_address_id=ip.id,
        port=80,
        url="http://10.0.0.1:80",
        status_code=200,
        is_static=False,
        has_login=False,
        has_rate_limit=False,
    )
    db.add(http1)
    await db.commit()
    await db.refresh(job)
    await db.refresh(port1)
    await db.refresh(port2)
    await db.refresh(http1)

    return job, [port1, port2], [http1]


# ── GET /api/v1/scans/{id}/results ────────────────────────────────


@pytest.mark.asyncio
async def test_get_scan_results_returns_combined_bundle(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /results returns the scan status, port results, HTTP analyses, and summary."""
    job, _ports, _http = await _seed_scan_with_results(db_session)

    response = await client.get(
        f"/api/v1/scans/{job.id}/results",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["scan_job"]["id"] == str(job.id)
    assert len(data["port_results"]) == 2
    assert len(data["http_analyses"]) == 1
    summary = data["summary"]
    assert summary["total_ports"] == 2
    assert summary["open_ports"] == 2
    assert summary["http_analyzed"] == 1


@pytest.mark.asyncio
async def test_get_scan_results_returns_404_for_missing_scan(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """GET /results for a non-existent scan returns 404."""
    response = await client.get(
        f"/api/v1/scans/{uuid4()}/results",
        headers=auth_headers,
    )
    assert response.status_code == 404


# ── GET /api/v1/scans/{id}/results/ports ──────────────────────────


@pytest.mark.asyncio
async def test_get_scan_port_results_returns_paginated_list(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /results/ports returns a paginated port-result list."""
    job, _ports, _http = await _seed_scan_with_results(db_session)

    response = await client.get(
        f"/api/v1/scans/{job.id}/results/ports",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2
    assert data["page"] == 1
    assert data["total_pages"] == 1


@pytest.mark.asyncio
async def test_get_scan_port_results_respects_page_size(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /results/ports with size=1 returns one item and two total pages."""
    job, _ports, _http = await _seed_scan_with_results(db_session)

    response = await client.get(
        f"/api/v1/scans/{job.id}/results/ports?page=1&size=1",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["items"]) == 1
    assert data["total_pages"] == 2


# ── GET /api/v1/scans/{id}/results/http ───────────────────────────


@pytest.mark.asyncio
async def test_get_scan_http_analyses_returns_list(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /results/http returns a list of HTTP analysis objects."""
    job, _ports, _http = await _seed_scan_with_results(db_session)

    response = await client.get(
        f"/api/v1/scans/{job.id}/results/http",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["port"] == 80


# ── GET /api/v1/scans/stats ───────────────────────────────────────


@pytest.mark.asyncio
async def test_get_scan_stats_returns_dashboard_shape(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /stats returns the aggregate dashboard statistics."""
    await _seed_scan_with_results(db_session)

    response = await client.get(
        "/api/v1/scans/stats",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total_scans"] >= 1
    assert data["total_open_ports"] >= 2
    assert data["total_ips"] >= 1
    assert "critical_findings" in data
    assert "high_findings" in data
    assert "scans_last_7_days" in data


@pytest.mark.asyncio
async def test_get_scan_stats_returns_401_without_auth(client: AsyncClient) -> None:
    """GET /stats without auth returns 401."""
    response = await client.get("/api/v1/scans/stats")
    assert response.status_code == 401
