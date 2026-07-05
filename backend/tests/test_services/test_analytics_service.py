"""Analytics service unit tests.

Exercises the aggregation queries that the endpoint tests do not cover
directly: ``get_risk_distribution``, ``get_scan_timeline``,
``get_total_ip_count`` and ``get_alive_ip_count``.
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ip_address import IPAddress
from app.models.port_result import PortResult
from app.models.scan_job import ScanJob
from app.models.scan_target import ScanTarget
from app.services.analytics_service import AnalyticsService


async def _seed(db: AsyncSession) -> ScanJob:
    """Persist a scan with port results and IPs so analytics return data."""
    target = ScanTarget(name="A", target_type="cidr", target_value="10.0.0.0/24")
    db.add(target)
    await db.flush()

    job = ScanJob(
        target_id=target.id, scan_type="quick", status="completed", progress=100.0,
    )
    db.add(job)
    await db.flush()

    ip = IPAddress(ip_address="10.0.0.5")
    db.add(ip)
    await db.flush()

    # Three open port results with distinct lowercase risk levels — the
    # case the production RiskClassifier now emits after the bug fix.
    for port, risk, score in [(22, "high", 7.5), (3389, "critical", 9.5), (443, "low", 2.0)]:
        db.add(PortResult(
            scan_job_id=job.id, ip_address_id=ip.id, port=port,
            protocol="tcp", state="open", risk_level=risk, risk_score=score,
        ))
    await db.commit()
    return job


# ── get_risk_distribution ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_risk_distribution_counts_levels(db_session) -> None:
    """get_risk_distribution returns per-level counts and the average score."""
    await _seed(db_session)
    service = AnalyticsService(db_session)

    dist = await service.get_risk_distribution()
    assert dist["critical"] == 1
    assert dist["high"] == 1
    assert dist["low"] == 1
    assert dist["total"] == 3
    # Average of 7.5, 9.5, 2.0 = 6.33...
    assert dist["risk_score_average"] > 0


@pytest.mark.asyncio
async def test_get_risk_distribution_empty_db_returns_zeros(db_session) -> None:
    """get_risk_distribution on an empty DB returns zero counts."""
    service = AnalyticsService(db_session)
    dist = await service.get_risk_distribution()
    assert dist["total"] == 0
    assert dist["risk_score_average"] == 0.0


# ── get_scan_timeline ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_scan_timeline_returns_one_row_per_day(db_session) -> None:
    """get_scan_timeline aggregates scans and findings per day."""
    await _seed(db_session)
    service = AnalyticsService(db_session)

    timeline = await service.get_scan_timeline(days=30)
    assert len(timeline) >= 1
    first = timeline[0]
    assert "date" in first
    assert first["scans"] >= 1


@pytest.mark.asyncio
async def test_get_scan_timeline_empty_db_returns_empty_list(db_session) -> None:
    """get_scan_timeline on an empty DB returns an empty list."""
    service = AnalyticsService(db_session)
    assert await service.get_scan_timeline(days=7) == []


# ── IP counts ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_total_ip_count_and_alive_count(db_session) -> None:
    """get_total_ip_count and get_alive_ip_count reflect seeded IPs."""
    db_session.add(IPAddress(ip_address="10.0.0.1", is_alive=True))
    db_session.add(IPAddress(ip_address="10.0.0.2", is_alive=False))
    await db_session.commit()

    service = AnalyticsService(db_session)
    assert await service.get_total_ip_count() == 2
    assert await service.get_alive_ip_count() == 1


@pytest.mark.asyncio
async def test_get_total_ip_count_empty_db_returns_zero(db_session) -> None:
    """get_total_ip_count on an empty DB returns zero."""
    service = AnalyticsService(db_session)
    assert await service.get_total_ip_count() == 0
    assert await service.get_alive_ip_count() == 0
