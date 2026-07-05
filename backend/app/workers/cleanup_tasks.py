"""Periodic Celery tasks for maintenance and cleanup.

Tasks in this module are scheduled via ``celery beat`` using the
``on_after_configure`` signal.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.models.http_analysis import HttpAnalysis
from app.models.port_result import PortResult
from app.models.scan_event import ScanEvent
from app.models.scan_job import ScanJob
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

# Terminal statuses eligible for cleanup — running jobs are never deleted.
_TERMINAL_STATUSES: tuple[str, ...] = ("completed", "failed")


def _make_sync_session() -> sessionmaker[Session]:
    """Build a sync SQLAlchemy session factory for the worker.

    Mirrors the pattern in ``scan_result_service``: take the async
    ``DATABASE_URL`` and strip the async driver suffix so the sync
    engine can connect from the Celery worker process.
    """
    settings = get_settings()
    sync_url = (
        settings.DATABASE_URL
        .replace("postgresql+asyncpg", "postgresql")
        .replace("postgresql+psycopg", "postgresql")
    )
    engine = create_engine(sync_url, pool_pre_ping=True)
    return sessionmaker(bind=engine)


def _delete_and_count(session: Session, stmt: Any) -> int:
    """Execute a DELETE statement and return the number of rows removed.

    SQLAlchemy 2.0 returns a ``CursorResult`` for DELETE statements that
    exposes ``rowcount`` at runtime, but the type stubs widen the return
    of ``session.execute`` to ``Result[Any]`` which lacks the attribute.
    """
    result = session.execute(stmt)
    return result.rowcount  # type: ignore[attr-defined, no-any-return]


@celery_app.task(  # type: ignore[untyped-decorator]
    bind=True,
    queue="cleanup",
    acks_late=True,
)
def cleanup_old_scans(  # type: ignore[no-untyped-def]
    self,  # noqa: ARG001  # Required by Celery's bind=True protocol.
    retention_days: int | None = None,
) -> dict[str, Any]:
    """Delete scan jobs and related data older than the retention window.

    Related ``port_results``, ``http_analyses``, and ``scan_events``
    are deleted first to respect foreign-key constraints, then the
    parent ``scan_jobs`` rows are removed.  Only jobs in a terminal
    state (``completed`` or ``failed``) are eligible — running jobs
    are never deleted.

    Parameters
    ----------
    retention_days : int or None
        Age threshold in days.  Defaults to ``SCAN_RETENTION_DAYS``
        from application settings (90 days).

    Returns
    -------
    dict
        Cleanup summary with deleted counts per table.
    """
    settings = get_settings()
    days = retention_days if retention_days is not None else settings.SCAN_RETENTION_DAYS
    cutoff = datetime.now(UTC) - timedelta(days=days)
    logger.info(
        "Cleanup task started — removing scan jobs older than %s", cutoff.isoformat(),
    )

    session_factory = _make_sync_session()
    session = session_factory()

    try:
        # ── Find expired terminal-state scan jobs ──────────────────
        expired_job_ids: list[Any] = list(
            session.scalars(
                select(ScanJob.id).where(
                    ScanJob.created_at < cutoff,
                    ScanJob.status.in_(_TERMINAL_STATUSES),
                ),
            ).all(),
        )

        executed_at = datetime.now(UTC).isoformat()

        # Guard: nothing to do — skip the DELETE statements entirely.
        if not expired_job_ids:
            logger.info("No expired scan jobs to clean up.")
            return _summary(days, executed_at)

        # ── Delete dependents first (FK constraints) ───────────────
        deleted_port_results = _delete_and_count(
            session,
            delete(PortResult).where(PortResult.scan_job_id.in_(expired_job_ids)),
        )
        deleted_http_analyses = _delete_and_count(
            session,
            delete(HttpAnalysis).where(HttpAnalysis.scan_job_id.in_(expired_job_ids)),
        )
        deleted_scan_events = _delete_and_count(
            session,
            delete(ScanEvent).where(ScanEvent.scan_job_id.in_(expired_job_ids)),
        )

        # ── Delete the parent scan jobs last ───────────────────────
        deleted_scan_jobs = _delete_and_count(
            session,
            delete(ScanJob).where(ScanJob.id.in_(expired_job_ids)),
        )

        session.commit()

        logger.info(
            "Cleanup complete — deleted %d scan job(s), %d port result(s), "
            "%d http analyse(s), %d scan event(s).",
            deleted_scan_jobs,
            deleted_port_results,
            deleted_http_analyses,
            deleted_scan_events,
        )

        return {
            "task": "cleanup_old_scans",
            "retention_days": days,
            "executed_at": executed_at,
            "deleted": {
                "scan_jobs": deleted_scan_jobs,
                "port_results": deleted_port_results,
                "http_analyses": deleted_http_analyses,
                "scan_events": deleted_scan_events,
            },
        }

    except Exception:
        session.rollback()
        logger.exception("Cleanup task failed.")
        raise
    finally:
        session.close()


def _summary(days: int, executed_at: str) -> dict[str, Any]:
    """Build a zero-deletion cleanup summary for the early-exit path."""
    return {
        "task": "cleanup_old_scans",
        "retention_days": days,
        "executed_at": executed_at,
        "deleted": {
            "scan_jobs": 0,
            "port_results": 0,
            "http_analyses": 0,
            "scan_events": 0,
        },
    }


@celery_app.on_after_configure.connect  # type: ignore[untyped-decorator]
def setup_periodic_tasks(sender, **kwargs) -> None:  # type: ignore[no-untyped-def]  # noqa: ARG001
    """Configure the periodic task schedule.

    Registered schedules:
    - ``daily-cleanup``: runs ``cleanup_old_scans`` once per day.
    """
    sender.add_periodic_task(
        timedelta(days=1),
        cleanup_old_scans.s(),
        name="daily-cleanup",
    )
