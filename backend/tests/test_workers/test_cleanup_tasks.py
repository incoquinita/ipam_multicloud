"""Celery cleanup task unit tests.

Exercises ``cleanup_old_scans`` and ``_make_sync_session`` with mocked
DB sessions and engine creation.  No real database connections are made.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.workers.cleanup_tasks import _make_sync_session, cleanup_old_scans

# ── _make_sync_session ────────────────────────────────────────────


def test_make_sync_session_strips_asyncpg_suffix() -> None:
    """_make_sync_session replaces ``postgresql+asyncpg`` with ``postgresql``."""
    with patch("app.workers.cleanup_tasks.create_engine") as mock_engine, \
         patch("app.workers.cleanup_tasks.sessionmaker") as mock_sessionmaker:
        _make_sync_session()

    # The URL passed to create_engine must not contain the async driver suffix.
    call_args = mock_engine.call_args
    sync_url = call_args.args[0] if call_args.args else call_args.kwargs.get("url", "")
    assert "+asyncpg" not in sync_url
    assert "+psycopg" not in sync_url
    mock_sessionmaker.assert_called_once()


def test_make_sync_session_strips_psycopg_suffix() -> None:
    """_make_sync_session also handles the ``postgresql+psycopg`` driver."""
    with patch("app.workers.cleanup_tasks.get_settings") as mock_settings, \
         patch("app.workers.cleanup_tasks.create_engine") as mock_engine, \
         patch("app.workers.cleanup_tasks.sessionmaker"):
        mock_settings.return_value = MagicMock(
            DATABASE_URL="postgresql+psycopg://user:pass@host/db",
            SCAN_RETENTION_DAYS=90,
        )
        _make_sync_session()

    sync_url = mock_engine.call_args.args[0]
    assert sync_url == "postgresql://user:pass@host/db"


# ── cleanup_old_scans ─────────────────────────────────────────────


def _mock_session_factory(session: MagicMock) -> MagicMock:
    """Build a mock sessionmaker that returns the given session."""
    factory = MagicMock()
    factory.return_value = session
    return factory


def _mock_session(expired_job_ids: list[str] | None = None) -> MagicMock:
    """Build a mock sync Session with configurable expired-job query result.

    The cleanup task calls ``session.scalars(select(...)).all()`` to find
    expired jobs, then ``session.execute(delete(...))`` for each table.
    The mock returns the given list of IDs from the first query, and a
    mock result with ``rowcount=1`` for each DELETE.
    """
    session = MagicMock()

    # ``scalars(...).all()`` returns the expired job IDs.
    scalars_result = MagicMock()
    scalars_result.all.return_value = expired_job_ids or []
    session.scalars.return_value = scalars_result

    # Each ``session.execute(delete_stmt)`` returns a result with rowcount.
    delete_result = MagicMock()
    delete_result.rowcount = 1
    session.execute.return_value = delete_result

    return session


def test_cleanup_old_scans_deletes_expired_terminal_jobs() -> None:
    """cleanup_old_scans deletes jobs older than the retention window."""
    expired_ids = ["job-1", "job-2"]
    session = _mock_session(expired_job_ids=expired_ids)
    factory = _mock_session_factory(session)

    with patch("app.workers.cleanup_tasks._make_sync_session", return_value=factory), \
         patch("app.workers.cleanup_tasks.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(SCAN_RETENTION_DAYS=90)
        result = cleanup_old_scans.apply(args=(None,)).result

    assert result["task"] == "cleanup_old_scans"
    assert result["deleted"]["scan_jobs"] >= 1
    # The session should have been committed and closed.
    session.commit.assert_called_once()
    session.close.assert_called_once()


def test_cleanup_old_scans_no_expired_jobs_returns_early() -> None:
    """When no expired jobs exist, cleanup returns a zero-deletion summary."""
    session = _mock_session(expired_job_ids=[])
    factory = _mock_session_factory(session)

    with patch("app.workers.cleanup_tasks._make_sync_session", return_value=factory), \
         patch("app.workers.cleanup_tasks.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(SCAN_RETENTION_DAYS=90)
        result = cleanup_old_scans.apply(args=(None,)).result

    assert result["deleted"]["scan_jobs"] == 0
    assert result["deleted"]["port_results"] == 0
    # No DELETE statements should have been executed.
    session.execute.assert_not_called()
    session.commit.assert_not_called()
    session.close.assert_called_once()


def test_cleanup_old_scans_rolls_back_on_exception() -> None:
    """If a DB error occurs, the session is rolled back and the error re-raised."""
    session = _mock_session(expired_job_ids=["job-1"])
    session.execute.side_effect = Exception("DB error")
    factory = _mock_session_factory(session)

    with patch("app.workers.cleanup_tasks._make_sync_session", return_value=factory), \
         patch("app.workers.cleanup_tasks.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(SCAN_RETENTION_DAYS=90)
        with pytest.raises(Exception, match="DB error"):
            cleanup_old_scans.apply(args=(None,)).get()

    session.rollback.assert_called_once()
    session.close.assert_called_once()


def test_cleanup_old_scans_uses_custom_retention_days() -> None:
    """cleanup_old_scans respects a custom retention_days argument."""
    session = _mock_session(expired_job_ids=[])
    factory = _mock_session_factory(session)

    with patch("app.workers.cleanup_tasks._make_sync_session", return_value=factory), \
         patch("app.workers.cleanup_tasks.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(SCAN_RETENTION_DAYS=90)
        result = cleanup_old_scans.apply(args=(30,)).result

    assert result["retention_days"] == 30
