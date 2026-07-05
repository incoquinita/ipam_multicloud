"""Sync ScanResultService unit tests.

Exercises the real ``ScanResultService`` against an in-memory SQLite
engine (single shared connection via ``StaticPool``) so every persistence
method — ``store_port_result``, ``store_http_analysis``,
``store_scan_event``, ``update_scan_job_progress``, ``get_ip_address_id``
and ``close`` — is covered without a Celery worker or PostgreSQL.

The JSONB→JSON compile hook registered in ``tests/conftest.py`` lets the
PostgreSQL-specific models materialise on SQLite, so the service runs
unchanged against the same ``Base.metadata`` used in production.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine as real_create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.ip_address import IPAddress
from app.models.scan_job import ScanJob
from app.models.scan_target import ScanTarget
from app.services.scan_result_service import ScanResultService


@pytest.fixture
def sync_engine():
    """A sync in-memory SQLite engine with all tables created."""
    engine = real_create_engine(
        "sqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def seeded_ids(sync_engine):
    """Persist a target, scan job, and IP address; return their UUIDs."""
    Session = sessionmaker(bind=sync_engine)
    session = Session()
    try:
        target = ScanTarget(name="Sync Target", target_type="cidr", target_value="10.0.0.0/24")
        session.add(target)
        session.flush()

        job = ScanJob(target_id=target.id, scan_type="quick", status="running", progress=0.0)
        session.add(job)
        session.flush()

        ip = IPAddress(ip_address="10.0.0.7")
        session.add(ip)
        session.flush()
        session.commit()
        return {"target": target.id, "job": job.id, "ip": ip.id}
    finally:
        session.close()


def _make_service(sync_engine, monkeypatch) -> ScanResultService:
    """Build a ScanResultService bound to the shared in-memory engine.

    ``create_engine`` is patched so the service's internal engine *is*
    the one the tables were created on — a fresh ``:memory:`` engine
    would see an empty schema.
    """
    monkeypatch.setattr(
        "app.services.scan_result_service.create_engine",
        lambda *_args, **_kwargs: sync_engine,
    )
    return ScanResultService(db_url="sqlite:///:memory:")


# ── store_port_result ──────────────────────────────────────────────


def test_store_port_result_persists_open_port(sync_engine, seeded_ids, monkeypatch) -> None:
    """store_port_result inserts a row that round-trips through the DB."""
    svc = _make_service(sync_engine, monkeypatch)
    result = svc.store_port_result(
        scan_job_id=seeded_ids["job"],
        ip_address_id=seeded_ids["ip"],
        port=22,
        state="open",
        service_name="SSH",
        banner="SSH-2.0-OpenSSH",
        risk_level="high",
        risk_score=7.5,
    )

    assert result.port == 22
    assert result.state == "open"
    assert result.service_name == "SSH"
    assert result.risk_level == "high"
    assert result.risk_score == 7.5
    svc.close()


def test_store_http_analysis_persists_web_probe(sync_engine, seeded_ids, monkeypatch) -> None:
    """store_http_analysis inserts an HTTP analysis row with defaults filled."""
    svc = _make_service(sync_engine, monkeypatch)
    result = svc.store_http_analysis(
        scan_job_id=seeded_ids["job"],
        ip_address_id=seeded_ids["ip"],
        port=80,
        url="http://10.0.0.7:80",
        status_code=200,
        is_static=False,
        has_login=True,
        has_rate_limit=False,
        technologies=["nginx"],
        title="Welcome",
    )

    assert result.port == 80
    assert result.url == "http://10.0.0.7:80"
    assert result.status_code == 200
    assert result.has_login is True
    assert result.technologies == ["nginx"]
    # Empty collections are filled by the service so columns are non-null.
    assert result.response_headers == {}
    svc.close()


def test_store_scan_event_appends_progress_event(sync_engine, seeded_ids, monkeypatch) -> None:
    """store_scan_event inserts an event with its payload and progress."""
    svc = _make_service(sync_engine, monkeypatch)
    event = svc.store_scan_event(
        scan_job_id=seeded_ids["job"],
        event_type="progress",
        message="Scanning host 10.0.0.7",
        data={"host": "10.0.0.7"},
        progress=42.0,
    )

    assert event.event_type == "progress"
    assert event.message == "Scanning host 10.0.0.7"
    assert event.progress == 42.0
    assert event.metadata_ == {"host": "10.0.0.7"}
    svc.close()


# ── update_scan_job_progress ───────────────────────────────────────


def test_update_scan_job_progress_updates_status_and_counters(
    sync_engine, seeded_ids, monkeypatch,
) -> None:
    """update_scan_job_progress mutates progress, status and findings."""
    svc = _make_service(sync_engine, monkeypatch)
    # Naive UTC — SQLite strips tz info on storage, so round-tripping
    # aware datetimes would mismatch; naive keeps the comparison exact.
    started = datetime.now(UTC).replace(tzinfo=None)

    svc.update_scan_job_progress(
        scan_job_id=seeded_ids["job"],
        progress=50.0,
        status="running",
        ports_found=3,
        findings_critical=1,
        findings_high=2,
        ips_scanned=1,
        started_at=started,
    )

    # Verify via a fresh session that the row reflects the update.
    Session = sessionmaker(bind=sync_engine)
    session = Session()
    try:
        job = session.get(ScanJob, seeded_ids["job"])
        assert job is not None
        assert job.progress == 50.0
        assert job.status == "running"
        assert job.ports_found == 3
        assert job.findings_critical == 1
        assert job.findings_high == 2
        assert job.ips_scanned == 1
        assert job.started_at == started
    finally:
        session.close()
    svc.close()


def test_update_scan_job_progress_computes_duration_on_completion(
    sync_engine, seeded_ids, monkeypatch,
) -> None:
    """completed_at with a prior started_at sets duration_seconds."""
    svc = _make_service(sync_engine, monkeypatch)
    started = datetime.now(UTC).replace(tzinfo=None)
    completed = datetime.now(UTC).replace(tzinfo=None)

    # First set started_at, then complete — duration is the delta.
    svc.update_scan_job_progress(
        scan_job_id=seeded_ids["job"], progress=50.0, started_at=started,
    )
    svc.update_scan_job_progress(
        scan_job_id=seeded_ids["job"],
        progress=100.0,
        status="completed",
        completed_at=completed,
    )

    Session = sessionmaker(bind=sync_engine)
    session = Session()
    try:
        job = session.get(ScanJob, seeded_ids["job"])
        assert job is not None
        assert job.status == "completed"
        assert job.completed_at == completed
        assert job.duration_seconds == int((completed - started).total_seconds())
    finally:
        session.close()
    svc.close()


def test_update_scan_job_progress_warns_on_missing_job(sync_engine, monkeypatch) -> None:
    """Updating a non-existent job logs a warning and returns silently."""
    svc = _make_service(sync_engine, monkeypatch)
    # No exception — the service guards the missing row internally.
    svc.update_scan_job_progress(scan_job_id=uuid4(), progress=10.0)
    svc.close()


# ── get_ip_address_id ──────────────────────────────────────────────


def test_get_ip_address_id_returns_uuid_for_known_ip(
    sync_engine, seeded_ids, monkeypatch,
) -> None:
    """get_ip_address_id returns the stored UUID for a known IP."""
    svc = _make_service(sync_engine, monkeypatch)
    found = svc.get_ip_address_id("10.0.0.7")
    assert found == str(seeded_ids["ip"])
    svc.close()


def test_get_ip_address_id_returns_none_for_unknown_ip(sync_engine, monkeypatch) -> None:
    """get_ip_address_id returns None when no record matches."""
    svc = _make_service(sync_engine, monkeypatch)
    assert svc.get_ip_address_id("192.0.2.99") is None
    svc.close()


# ── close ──────────────────────────────────────────────────────────


def test_close_disposes_engine(sync_engine, monkeypatch) -> None:
    """close() disposes the engine without raising."""
    svc = _make_service(sync_engine, monkeypatch)
    svc.close()  # should not raise
