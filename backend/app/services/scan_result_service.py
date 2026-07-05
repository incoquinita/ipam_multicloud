"""Sync persistence service for storing scan results from Celery tasks.

Uses a synchronous SQLAlchemy engine because Celery tasks run in
separate worker processes (not in the async FastAPI server loop).
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.models.http_analysis import HttpAnalysis
from app.models.ip_address import IPAddress
from app.models.port_result import PortResult
from app.models.scan_event import ScanEvent
from app.models.scan_job import ScanJob

logger = logging.getLogger(__name__)


class ScanResultService:
    """Sync service for storing scan results from Celery tasks into the DB.

    Parameters
    ----------
    db_url : str or None
        Database URL.  Defaults to ``settings.DATABASE_URL`` with the
        ``+asyncpg`` driver suffix replaced by plain ``postgresql`` so
        that the sync engine can connect.
    """

    def __init__(self, db_url: str | None = None) -> None:
        if db_url is None:
            settings = get_settings()
            # Replace the async driver suffix with the sync equivalent.
            db_url = settings.DATABASE_URL.replace(
                "postgresql+asyncpg", "postgresql",
            ).replace(
                "postgresql+psycopg", "postgresql",
            )
        self._engine = create_engine(db_url, pool_pre_ping=True)
        self._session_factory: sessionmaker[Session] = sessionmaker(
            bind=self._engine,
        )

    def store_port_result(
        self,
        scan_job_id: str,
        ip_address_id: str,
        port: int,
        state: str,
        service_name: str | None = None,
        banner: str | None = None,
        risk_level: str | None = None,
        risk_score: float | None = None,
    ) -> PortResult:
        """Insert a ``port_result`` row.

        Parameters
        ----------
        scan_job_id : str
            UUID of the parent ``ScanJob``.
        ip_address_id : str
            UUID of the scanned ``IPAddress``.
        port : int
            Port number.
        state : str
            Port state (e.g. ``"open"``, ``"closed"``).
        service_name : str or None
            Detected service name.
        banner : str or None
            Service banner text.
        risk_level : str or None
            Risk classification level.
        risk_score : float or None
            Numerical risk score.

        Returns
        -------
        PortResult
            The newly created ORM instance.
        """
        session = self._session_factory()
        try:
            result = PortResult(
                scan_job_id=scan_job_id,
                ip_address_id=ip_address_id,
                port=port,
                state=state,
                service_name=service_name,
                banner=banner,
                risk_level=risk_level,
                risk_score=risk_score,
            )
            session.add(result)
            session.commit()
            session.refresh(result)
            return result
        except Exception:
            session.rollback()
            logger.exception(
                "Failed to store port result for job %s, ip %s, port %d",
                scan_job_id, ip_address_id, port,
            )
            raise
        finally:
            session.close()

    def store_http_analysis(
        self,
        scan_job_id: str,
        ip_address_id: str,
        port: int,
        url: str,
        status_code: int | None = None,
        is_static: bool | None = None,
        has_login: bool | None = None,
        has_rate_limit: bool | None = None,
        response_headers: dict[str, Any] | None = None,
        technologies: list[str] | None = None,
        certificates: dict[str, Any] | None = None,
        security_headers: dict[str, Any] | None = None,
        security_headers_score: int | None = None,
        tls_version: str | None = None,
        title: str | None = None,
        static_evidence: list[str] | None = None,
        login_evidence: list[str] | None = None,
        rate_limit_details: dict[str, Any] | None = None,
    ) -> HttpAnalysis:
        """Insert an ``http_analysis`` row.

        Parameters
        ----------
        scan_job_id : str
            UUID of the parent ``ScanJob``.
        ip_address_id : str
            UUID of the scanned ``IPAddress``.
        port : int
            Port number.
        url : str
            Full URL that was analysed.
        status_code : int or None
            HTTP response status code.
        is_static : bool or None
            Whether the response appears to be static content.
        has_login : bool or None
            Whether a login form was detected.
        has_rate_limit : bool or None
            Whether rate-limit headers were found.
        response_headers : dict or None
            Response headers as a dictionary.
        technologies : list[str] or None
            Detected technology stack.
        certificates : dict or None
            TLS certificate metadata.
        security_headers : dict or None
            Present security headers and their values.
        security_headers_score : int or None
            Security header compliance score (0-10).
        tls_version : str or None
            Negotiated TLS protocol version.
        title : str or None
            HTML title tag content.
        static_evidence : list[str] or None
            Probe response evidence for static classification.
        login_evidence : list[str] or None
            Signals that triggered login-page detection.
        rate_limit_details : dict or None
            Burst probe results including status codes and timings.

        Returns
        -------
        HttpAnalysis
            The newly created ORM instance.
        """
        session = self._session_factory()
        try:
            analysis = HttpAnalysis(
                scan_job_id=scan_job_id,
                ip_address_id=ip_address_id,
                port=port,
                url=url,
                status_code=status_code,
                is_static=is_static,
                has_login=has_login,
                has_rate_limit=has_rate_limit,
                response_headers=response_headers or {},
                technologies=technologies or [],
                certificates=certificates or {},
                security_headers=security_headers or {},
                security_headers_score=security_headers_score,
                tls_version=tls_version,
                title=title,
                static_evidence=static_evidence or [],
                login_evidence=login_evidence or [],
                rate_limit_details=rate_limit_details or {},
            )
            session.add(analysis)
            session.commit()
            session.refresh(analysis)
            return analysis
        except Exception:
            session.rollback()
            logger.exception(
                "Failed to store HTTP analysis for job %s, ip %s, port %d",
                scan_job_id, ip_address_id, port,
            )
            raise
        finally:
            session.close()

    def store_scan_event(
        self,
        scan_job_id: str,
        event_type: str,
        message: str,
        data: dict[str, Any] | None = None,
        progress: float | None = None,
    ) -> ScanEvent:
        """Append a ``scan_event`` row for the given scan job.

        Used by Celery tasks to persist the append-only event log that
        mirrors the Redis pub/sub progress stream.

        Parameters
        ----------
        scan_job_id : str
            UUID of the parent ``ScanJob``.
        event_type : str
            Event label — one of ``"started"``, ``"progress"``,
            ``"host_scanned"``, ``"completed"``, ``"failed"``,
            ``"cancelled"``.
        message : str
            Human-readable event message.
        data : dict or None
            Arbitrary event payload, stored in the ``metadata`` JSONB column.
        progress : float or None
            Progress percentage at the time of this event.

        Returns
        -------
        ScanEvent
            The newly created ORM instance.
        """
        session = self._session_factory()
        try:
            event = ScanEvent(
                scan_job_id=scan_job_id,
                event_type=event_type,
                message=message,
                metadata_=data or {},
                progress=progress,
            )
            session.add(event)
            session.commit()
            session.refresh(event)
            return event
        except Exception:
            session.rollback()
            logger.exception(
                "Failed to store scan event for job %s (%s)",
                scan_job_id, event_type,
            )
            raise
        finally:
            session.close()

    def update_scan_job_progress(
        self,
        scan_job_id: str,
        progress: float,
        status: str | None = None,
        ports_found: int | None = None,
        findings_critical: int | None = None,
        findings_high: int | None = None,
        findings_medium: int | None = None,
        findings_low: int | None = None,
        error_message: str | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        ips_scanned: int | None = None,
    ) -> None:
        """Update a ``scan_job`` progress, status, and findings counters.

        Parameters
        ----------
        scan_job_id : str
            UUID of the ``ScanJob`` to update.
        progress : float
            Progress percentage (0–100).
        status : str or None
            New status (e.g. ``"running"``, ``"completed"``, ``"failed"``).
        ports_found : int or None
            Total ports found so far.
        findings_critical : int or None
            Total critical findings so far.
        findings_high : int or None
            Total high findings so far.
        findings_medium : int or None
            Total medium findings so far.
        findings_low : int or None
            Total low findings so far.
        error_message : str or None
            Error message (if status is ``"failed"``).
        started_at : datetime or None
            When provided, sets ``job.started_at`` (recorded at scan start).
        completed_at : datetime or None
            When provided, sets ``job.completed_at`` and, if ``started_at``
            is already set on the job, computes ``job.duration_seconds``.
        ips_scanned : int or None
            When provided, **increments** ``job.ips_scanned`` by this amount
            (use ``1`` per successfully scanned host).
        """
        session = self._session_factory()
        try:
            job = session.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
            if job is None:
                logger.warning("ScanJob %s not found; cannot update progress", scan_job_id)
                return

            job.progress = progress
            if status is not None:
                job.status = status
            if ports_found is not None:
                job.ports_found = ports_found
            if findings_critical is not None:
                job.findings_critical = findings_critical
            if findings_high is not None:
                job.findings_high = findings_high
            if findings_medium is not None:
                job.findings_medium = findings_medium
            if findings_low is not None:
                job.findings_low = findings_low
            if error_message is not None:
                job.error_message = error_message
            if started_at is not None:
                job.started_at = started_at
            if completed_at is not None:
                job.completed_at = completed_at
                if job.started_at is not None:
                    job.duration_seconds = int(
                        (completed_at - job.started_at).total_seconds()
                    )
            if ips_scanned is not None:
                job.ips_scanned = (job.ips_scanned or 0) + ips_scanned

            session.commit()
        except Exception:
            session.rollback()
            logger.exception(
                "Failed to update progress for scan job %s", scan_job_id,
            )
            raise
        finally:
            session.close()

    def get_ip_address_id(self, ip_address: str) -> str | None:
        """Look up the UUID of an IP address by its string value.

        Parameters
        ----------
        ip_address : str
            The IP address string (e.g. ``"10.0.0.1"``).

        Returns
        -------
        str or None
            The UUID as a string, or ``None`` if no matching record
            exists.
        """
        session = self._session_factory()
        try:
            record = (
                session.query(IPAddress)
                .filter(IPAddress.ip_address == ip_address)
                .first()
            )
            if record is None:
                return None
            return str(record.id)
        except Exception:
            logger.exception(
                "Failed to look up IP address %s", ip_address,
            )
            return None
        finally:
            session.close()

    def close(self) -> None:
        """Dispose of the sync engine, releasing all connections."""
        self._engine.dispose()
