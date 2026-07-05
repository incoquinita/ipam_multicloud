"""Analytics endpoint integration tests.

Exercises the ``/api/v1/analytics`` routes: timeline, port distribution,
and risk summary.  Each endpoint delegates to ``AnalyticsService``
aggregation queries and parses the result into a typed schema at the
boundary.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ip_address import IPAddress
from app.models.port_result import PortResult
from app.models.scan_job import ScanJob
from app.models.scan_target import ScanTarget


async def _seed_analytics_data(db: AsyncSession) -> None:
    """Persist a scan with port results so analytics queries return data."""
    target = ScanTarget(name="Analytics Target", target_type="cidr", target_value="10.0.0.0/24")
    db.add(target)
    await db.flush()

    job = ScanJob(
        target_id=target.id,
        scan_type="quick",
        status="completed",
        progress=100.0,
        ports_found=3,
        findings_critical=1,
        findings_high=1,
        findings_medium=1,
    )
    db.add(job)
    await db.flush()

    ip = IPAddress(ip_address="10.0.0.5")
    db.add(ip)
    await db.flush()

    # Three open port results with distinct risk levels.
    for port, risk, score in [(22, "high", 7.5), (3389, "critical", 9.5), (443, "low", 2.0)]:
        db.add(PortResult(
            scan_job_id=job.id,
            ip_address_id=ip.id,
            port=port,
            protocol="tcp",
            state="open",
            risk_level=risk,
            risk_score=score,
        ))
    await db.commit()


# ── GET /api/v1/analytics/timeline ────────────────────────────────


@pytest.mark.asyncio
async def test_timeline_returns_list_of_days(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /timeline returns a ScanTimeline with an items list."""
    await _seed_analytics_data(db_session)

    response = await client.get(
        "/api/v1/analytics/timeline?days=30",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert isinstance(data["items"], list)
    # At least one day should have data (the seeded scan).
    assert len(data["items"]) >= 1
    first = data["items"][0]
    assert "date" in first
    assert "scans" in first
    assert "findings" in first


@pytest.mark.asyncio
async def test_timeline_returns_401_without_auth(client: AsyncClient) -> None:
    """GET /timeline without auth returns 401."""
    response = await client.get("/api/v1/analytics/timeline")
    assert response.status_code == 401


# ── GET /api/v1/analytics/port-distribution ───────────────────────


@pytest.mark.asyncio
async def test_port_distribution_returns_open_ports(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /port-distribution returns the most frequently found open ports."""
    await _seed_analytics_data(db_session)

    response = await client.get(
        "/api/v1/analytics/port-distribution?limit=10",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert isinstance(data["items"], list)
    assert len(data["items"]) >= 1
    first = data["items"][0]
    assert "port" in first
    assert "count" in first
    assert "critical_count" in first


# ── GET /api/v1/analytics/risk-summary ────────────────────────────


@pytest.mark.asyncio
async def test_risk_summary_returns_aggregate_counts(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict[str, str],
) -> None:
    """GET /risk-summary returns aggregate risk counts and average score."""
    await _seed_analytics_data(db_session)

    response = await client.get(
        "/api/v1/analytics/risk-summary",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 3
    assert data["critical"] >= 1
    assert data["high"] >= 1
    assert data["low"] >= 1
    assert isinstance(data["risk_score_average"], float | int)


@pytest.mark.asyncio
async def test_risk_summary_empty_db_returns_zeros(
    client: AsyncClient, auth_headers: dict[str, str],
) -> None:
    """GET /risk-summary on an empty DB returns zero counts."""
    response = await client.get(
        "/api/v1/analytics/risk-summary",
        headers=auth_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["critical"] == 0
    assert data["risk_score_average"] == 0.0
