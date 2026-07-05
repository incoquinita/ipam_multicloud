"""Analytics endpoints — timeline, distributions, and risk summaries.

These endpoints expose the aggregation queries in
:class:`AnalyticsService` to the API. The service returns plain dicts
shaped to match the analytics schemas; the endpoints parse them into
typed responses at the boundary (Parse, Don't Validate).
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db
from app.schemas.analytics import (
    PortDistribution,
    PortDistributionItem,
    RiskSummary,
    ScanTimeline,
    ScanTimelineItem,
)
from app.services.analytics_service import AnalyticsService

router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("/timeline", response_model=ScanTimeline)
async def get_scan_timeline(
    days: int = Query(30, ge=1, le=365, description="Number of days to include"),
    db: AsyncSession = Depends(get_db),
) -> ScanTimeline:
    """Return scan counts and findings per day for the last *days*."""
    service = AnalyticsService(db)
    rows = await service.get_scan_timeline(days=days)
    items = [
        ScanTimelineItem(date=row["date"], scans=row["scans"], findings=row["findings"])
        for row in rows
    ]
    return ScanTimeline(items=items)


@router.get("/port-distribution", response_model=PortDistribution)
async def get_port_distribution(
    limit: int = Query(20, ge=1, le=200, description="Maximum number of ports to return"),
    db: AsyncSession = Depends(get_db),
) -> PortDistribution:
    """Return the most frequently discovered open ports."""
    service = AnalyticsService(db)
    rows = await service.get_top_open_ports(limit=limit)
    items = [
        PortDistributionItem(
            port=row["port"],
            service_name=row["service_name"],
            count=row["count"],
            critical_count=row["critical_count"],
        )
        for row in rows
    ]
    return PortDistribution(items=items)


@router.get("/risk-summary", response_model=RiskSummary)
async def get_risk_summary(
    db: AsyncSession = Depends(get_db),
) -> RiskSummary:
    """Return aggregate risk counts and average risk score."""
    service = AnalyticsService(db)
    summary = await service.get_risk_distribution()
    return RiskSummary(
        critical=summary["critical"],
        high=summary["high"],
        medium=summary["medium"],
        low=summary["low"],
        total=summary["total"],
        risk_score_average=summary["risk_score_average"],
    )
