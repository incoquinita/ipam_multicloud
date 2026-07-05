"""Analytics service — aggregates scan results for dashboards and reports."""

from typing import Any

from sqlalchemy import Integer, case, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ip_address import IPAddress
from app.models.port_result import PortResult
from app.models.scan_job import ScanJob
from app.repositories.scan_repository import ScanRepository


class AnalyticsService:
    """Aggregation queries for scan analytics."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.scan_repo = ScanRepository(session)

    async def get_top_open_ports(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the most frequently found open ports across all scans.

        Each row carries ``port``, ``service_name`` (most frequently
        observed service for that port, or ``"unknown"`` if none was
        detected), ``count`` (total open results for the port) and
        ``critical_count`` (results tagged ``risk_level='critical'``).
        """
        stmt = (
            select(
                PortResult.port,
                func.count(PortResult.id).label("cnt"),
                func.max(PortResult.service_name).label("service_name"),
                func.sum(
                    case((PortResult.risk_level == "critical", 1), else_=0)
                ).label("critical_count"),
            )
            .where(PortResult.state == "open")
            .group_by(PortResult.port)
            .order_by(func.count(PortResult.id).desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return [
            {
                "port": row.port,
                "service_name": row.service_name or "unknown",
                "count": row.cnt,
                "critical_count": row.critical_count or 0,
            }
            for row in result
        ]

    async def get_risk_distribution(self) -> dict[str, Any]:
        """Return aggregate risk counts and the average risk score.

        Keys: ``critical``, ``high``, ``medium``, ``low``, ``total`` and
        ``risk_score_average`` (mean of ``PortResult.risk_score`` across
        all rows with a non-null score).
        """
        by_level_stmt = (
            select(
                PortResult.risk_level,
                func.count(PortResult.id).label("cnt"),
            )
            .where(PortResult.risk_level.isnot(None))
            .group_by(PortResult.risk_level)
        )
        by_level_result = await self.session.execute(by_level_stmt)
        counts: dict[str, int] = {row.risk_level: row.cnt for row in by_level_result}

        avg_score_stmt = (
            select(func.avg(PortResult.risk_score))
            .where(PortResult.risk_score.isnot(None))
        )
        avg_score_result = await self.session.execute(avg_score_stmt)
        avg_score = avg_score_result.scalar() or 0.0

        critical = counts.get("critical", 0)
        high = counts.get("high", 0)
        medium = counts.get("medium", 0)
        low = counts.get("low", 0)
        total = critical + high + medium + low

        return {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "total": total,
            "risk_score_average": float(avg_score),
        }

    async def get_scan_timeline(
        self, days: int = 30,
    ) -> list[dict[str, Any]]:
        """Return scan counts and total findings per day for the last *days*.

        Each row carries ``date`` (ISO ``YYYY-MM-DD``), ``scans`` (jobs
        created that day) and ``findings`` (sum of all finding buckets
        across the jobs created that day).
        """
        # Use a Python-side cutoff so the query is portable across
        # PostgreSQL and SQLite (the test suite runs on aiosqlite, which
        # lacks ``make_interval``).
        from datetime import UTC, datetime, timedelta

        cutoff = datetime.now(UTC) - timedelta(days=days)
        stmt = (
            select(
                func.date(ScanJob.created_at).label("day"),
                func.count(ScanJob.id).label("scans"),
                func.sum(
                    cast(ScanJob.findings_critical, Integer)
                    + cast(ScanJob.findings_high, Integer)
                    + cast(ScanJob.findings_medium, Integer)
                    + cast(ScanJob.findings_low, Integer)
                ).label("findings"),
            )
            .where(ScanJob.created_at >= cutoff)
            .group_by(func.date(ScanJob.created_at))
            .order_by(func.date(ScanJob.created_at))
        )
        result = await self.session.execute(stmt)
        return [
            {
                "date": str(row.day),
                "scans": row.scans or 0,
                "findings": row.findings or 0,
            }
            for row in result
        ]

    async def get_total_ip_count(self) -> int:
        """Return total discovered IP addresses."""
        stmt = select(func.count(IPAddress.id))
        result = await self.session.execute(stmt)
        return result.scalar_one() or 0

    async def get_alive_ip_count(self) -> int:
        """Return count of IPs marked as alive."""
        stmt = select(func.count(IPAddress.id)).where(IPAddress.is_alive.is_(True))
        result = await self.session.execute(stmt)
        return result.scalar_one() or 0
