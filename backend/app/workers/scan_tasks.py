"""Celery task definitions for scan execution.

Each task publishes progress updates via Redis for the WebSocket / SSE
consumers, integrates with the scanner engine modules, and persists
results to the database using ``ScanResultService``.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from app.workers.celery_app import celery_app

if TYPE_CHECKING:
    # Type-only imports — scanner classes are imported lazily at runtime
    # inside ``run_port_scan`` to avoid blocking Celery worker startup.
    from app.scanner.banner_grabber import BannerGrabber
    from app.scanner.http_analyzer import HttpAnalyzer
    from app.scanner.port_scanner import PortScanner

logger = logging.getLogger(__name__)


# ── Helpers ─────────────────────────────────────────────────────────

# Maps the internal scan ``status`` label to the WebSocket message
# ``type`` expected by the frontend (see ``frontend/src/types/websocket.ts``).
# Values: scan_progress | scan_complete | scan_error | scan_cancelled.
_WS_TYPE_BY_STATUS: dict[str, str] = {
    "running": "scan_progress",
    "complete": "scan_complete",
    "completed": "scan_complete",
    "error": "scan_error",
    "failed": "scan_error",
    "cancelled": "scan_cancelled",
}


def publish_progress(
    task_id: str,
    scan_job_id: str,
    progress: float,
    status: str,
    message: str = "",
    data: dict[str, Any] | None = None,
) -> None:
    """Publish a progress update to Redis for SSE / WS consumers.

    Emits a JSON message shaped to match the frontend ``WsMessage``
    contract::

        {"type": "scan_progress", "scan_job_id": "...",
         "timestamp": "<iso-8601>", "payload": {progress, status, ...}}

    The ``type`` field is derived from *status* via
    ``_WS_TYPE_BY_STATUS`` so callers keep passing the internal status
    label.  Writes the payload to Redis with a 10-minute expiry and
    publishes it on the channel ``scan:progress:{scan_job_id}``.

    Parameters
    ----------
    task_id : str
        The Celery task UUID.
    scan_job_id : str
        The ``ScanJob`` database UUID.
    progress : float
        Progress percentage (0-100).
    status : str
        Current status label (e.g. ``"running"``, ``"complete"``).
    message : str
        Human-readable status message.
    data : dict or None
        Optional additional payload data.
    """
    import redis as sync_redis

    r = sync_redis.from_url(celery_app.conf.result_backend)
    try:
        payload: dict[str, Any] = {
            "task_id": task_id,
            "progress": round(progress, 2),
            "status": status,
            "message": message,
            "data": data or {},
        }
        body = {
            "type": _WS_TYPE_BY_STATUS.get(status, "scan_progress"),
            "scan_job_id": scan_job_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "payload": payload,
        }
        channel = f"scan:progress:{scan_job_id}"
        encoded = json.dumps(body)
        r.setex(channel, 600, encoded)
        r.publish(channel, encoded)
    except Exception as exc:
        logger.warning("Failed to publish progress for %s: %s", scan_job_id, exc)
    finally:
        r.close()


def _get_sync_service() -> Any:
    """Lazy-import and return a ``ScanResultService`` instance.

    Keeps the import out of module level so Celery worker startup
    is not blocked by database engine creation.
    """
    from app.services.scan_result_service import ScanResultService

    return ScanResultService()


def _lookup_ip_id(service: Any, host: str) -> str | None:
    """Resolve an IP address string to a database UUID.

    Returns ``None`` if the IP is not found in ``ip_addresses``.
    """
    return service.get_ip_address_id(host)  # type: ignore[no-any-return]


def _store_event(
    service: Any,
    scan_job_id: str,
    event_type: str,
    message: str,
    data: dict[str, Any] | None = None,
    progress: float | None = None,
) -> None:
    """Persist a ``ScanEvent`` row, swallowing non-fatal persistence errors.

    Event logging is best-effort telemetry: a failure here must never
    abort the scan, so exceptions are logged and discarded.
    """
    try:
        service.store_scan_event(
            scan_job_id, event_type, message,
            data=data, progress=progress,
        )
    except Exception as exc:
        logger.warning(
            "Failed to store scan event (%s) for %s: %s",
            event_type, scan_job_id, exc,
        )


def is_sftp_on_ssh_port(port: int, banner: str | None) -> bool:
    """Return ``True`` when port 22's banner advertises SFTP capability.

    SSH and SFTP share port 22.  A banner containing ``"sftp"`` (case
    insensitive) indicates the service also accepts file-transfer
    sessions, so the caller should report the service as ``"SSH/SFTP"``.

    Parameters
    ----------
    port : int
        Port number to check.
    banner : str or None
        Service banner grabbed from the open port.  ``None`` or an
        empty string means no banner was retrieved.

    Returns
    -------
    bool
        ``True`` iff *port* is 22 and *banner* contains ``"sftp"``.
    """
    if port != 22:
        return False
    if banner is None:
        return False
    return "sftp" in banner.lower()


# ── Async batch helpers ──────────────────────────────────────────────


async def _scan_one_host(
    scanner: PortScanner,
    grabber: BannerGrabber,
    analyzer: HttpAnalyzer,
    host: str,
    ports: list[int],
    do_banner_grab: bool,
    do_http: bool,
    web_ports: tuple[int, ...],
) -> dict[str, Any]:
    """Scan a single host end-to-end: port scan → banner grab → HTTP analysis.

    Pure async I/O — performs **no** database access so it never blocks
    the shared event loop.  Returns a structured result dict ready for
    sync persistence by the caller.

    Parameters
    ----------
    scanner, grabber, analyzer
        Scanner engine instances (already constructed by the task).
    host : str
        IP address or hostname to scan.
    ports : list[int]
        Port numbers to probe.
    do_banner_grab : bool
        Whether to attempt banner grabbing on open ports.
    do_http : bool
        Whether to run HTTP analysis on web ports.
    web_ports : tuple[int, ...]
        Ports that trigger HTTP analysis when *do_http* is true.

    Returns
    -------
    dict
        ``{"host": str, "open_ports": list[int], "port_entries": list[dict]}``
        where each port entry is
        ``{"port": int, "banner": str | None, "http_result": Any | None}``.
    """
    open_ports = await scanner.scan_host(host, ports)

    port_entries: list[dict[str, Any]] = []
    for port in open_ports:
        # ── Banner grab ────────────────────────────────────────────
        banner: str | None = None
        if do_banner_grab:
            try:
                banner = await grabber.grab_banner(host, port)
            except Exception as exc:
                logger.debug("Banner grab failed for %s:%d — %s", host, port, exc)

        # ── HTTP analysis (web ports only) ─────────────────────────
        http_result: Any = None
        if do_http and port in web_ports:
            try:
                http_result = await analyzer.analyze(host, port)
            except Exception as exc:
                logger.debug("HTTP analysis failed for %s:%d — %s", host, port, exc)

        port_entries.append(
            {"port": port, "banner": banner, "http_result": http_result},
        )

    return {"host": host, "open_ports": open_ports, "port_entries": port_entries}


async def _scan_all_hosts(
    scanner: PortScanner,
    grabber: BannerGrabber,
    analyzer: HttpAnalyzer,
    targets: list[tuple[str, list[int]]],
    do_banner_grab: bool,
    do_http: bool,
    web_ports: tuple[int, ...],
) -> list[Any]:
    """Scan all hosts concurrently within a single event loop.

    Dispatches every host scan as a coroutine gathered via
    ``asyncio.gather`` so the event loop is created **once** rather than
    per host.  The ``PortScanner`` internal semaphore already caps
    concurrent socket connections, so batching hosts does not overwhelm
    the network.

    Returns
    -------
    list
        Results aligned with *targets*.  Each element is either the
        host result dict from :func:`_scan_one_host` or an
        ``Exception`` (surfaced via ``return_exceptions=True``) so the
        caller can degrade gracefully per host.
    """
    tasks = [
        _scan_one_host(
            scanner, grabber, analyzer, host, ports,
            do_banner_grab, do_http, web_ports,
        )
        for host, ports in targets
    ]
    return list(await asyncio.gather(*tasks, return_exceptions=True))


# ── Port-scan task ──────────────────────────────────────────────────


@celery_app.task(  # type: ignore[untyped-decorator]
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    acks_late=True,
    reject_on_worker_lost=True,
    track_started=True,
    queue="scans",
)
def run_port_scan(  # type: ignore[no-untyped-def]
    self,
    scan_job_id: str,
    targets: list[dict[str, Any]],
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run a TCP port scan on the given targets and persist results.

    Parameters
    ----------
    scan_job_id : str
        UUID of the ``ScanJob`` record.
    targets : list[dict]
        List of ``{"host": str, "ports": list[int]}`` dicts.
    config : dict or None
        Optional configuration overrides.  Supports the ``"profile"``
        key for named scan profiles.

    Returns
    -------
    dict
        Summary of scan execution with result counters.
    """
    # ── Parse config at the boundary ────────────────────────────────
    config = config or {}
    profile_name = config.get("profile", "standard")

    # Guard: validate profile name early.
    from app.schemas.scan_profiles import get_profile

    try:
        profile = get_profile(profile_name)
    except ValueError as exc:
        logger.error("Invalid profile '%s' for job %s: %s", profile_name, scan_job_id, exc)
        svc = _get_sync_service()
        try:
            svc.update_scan_job_progress(
                scan_job_id, 0, status="failed", error_message=str(exc),
            )
            _store_event(
                svc, scan_job_id, "failed",
                f"Invalid scan profile '{profile_name}': {exc}",
            )
        finally:
            svc.close()
        return {"scan_job_id": scan_job_id, "status": "failed", "error": str(exc)}

    timeout = config.get("timeout", profile.timeout)
    concurrency = config.get("concurrency", profile.concurrency)
    do_banner_grab = config.get("banner_grab", profile.banner_grab)
    do_http = config.get("http_analysis", profile.http_analysis)

    # Guard: empty targets list.
    total_targets = len(targets)
    if total_targets == 0:
        publish_progress(
            self.request.id, scan_job_id, 100, "complete",
            "No targets provided; nothing to scan.",
        )
        now = datetime.now(UTC)
        svc = _get_sync_service()
        try:
            svc.update_scan_job_progress(
                scan_job_id, 100, status="completed", ports_found=0,
                findings_critical=0, findings_high=0,
                findings_medium=0, findings_low=0,
                started_at=now, completed_at=now,
            )
            _store_event(
                svc, scan_job_id, "started",
                "Scan started (no targets).",
                data={"total_targets": 0},
            )
            _store_event(
                svc, scan_job_id, "completed",
                "No targets provided; nothing to scan.",
                progress=100.0,
            )
        finally:
            svc.close()
        return {
            "scan_job_id": scan_job_id,
            "status": "completed",
            "ports_found": 0,
            "findings_critical": 0,
            "findings_high": 0,
            "findings_medium": 0,
            "findings_low": 0,
            "results": [],
        }

    # ── Imports (lazy — avoid blocking worker startup) ─────────────
    from app.scanner.banner_grabber import BannerGrabber
    from app.scanner.http_analyzer import HttpAnalyzer
    from app.scanner.port_scanner import PortScanner
    from app.scanner.risk_classifier import RiskClassifier

    scanner = PortScanner(concurrency=concurrency, timeout=timeout)
    grabber = BannerGrabber(timeout=timeout)
    classifier = RiskClassifier()
    analyzer = HttpAnalyzer()
    svc = _get_sync_service()

    all_open_ports: list[dict[str, Any]] = []
    running_ports_found = 0
    running_critical = 0
    running_high = 0
    running_medium = 0
    running_low = 0

    # Web ports that trigger HTTP analysis when enabled.
    web_ports: tuple[int, ...] = (80, 443, 8080, 8443)

    try:
        # ── Mark scan as started (DB status + append-only event) ────
        started_at = datetime.now(UTC)
        try:
            svc.update_scan_job_progress(
                scan_job_id, progress=0.0, status="running",
                started_at=started_at,
            )
        except Exception as exc:
            logger.warning("Failed to set started_at for %s: %s", scan_job_id, exc)
        _store_event(
            svc, scan_job_id, "started",
            f"Scan started for {total_targets} target(s).",
            data={"total_targets": total_targets},
        )
        publish_progress(
            self.request.id, scan_job_id, 0, "running",
            f"Scan started for {total_targets} target(s).",
        )

        # ── Phase 1: filter valid targets & resolve IP IDs (sync) ──
        # Each entry keeps its original index so progress stays accurate.
        scan_queue: list[tuple[int, str, list[int], str]] = []
        for idx, target in enumerate(targets):
            host = target.get("host", "")
            ports = target.get("ports", []) or profile.ports

            # Guard: skip invalid targets.
            if not host or not ports:
                logger.warning("Skipping invalid target: %s", target)
                continue

            ip_address_id = _lookup_ip_id(svc, host)
            if ip_address_id is None:
                logger.warning(
                    "IP address %s not found in database; skipping", host,
                )
                skip_progress = (idx + 1) / total_targets * 100
                publish_progress(
                    self.request.id, scan_job_id,
                    skip_progress, "running",
                    f"IP {host} not found in DB — skipped",
                )
                _store_event(
                    svc, scan_job_id, "progress",
                    f"IP {host} not found in DB — skipped",
                    data={"host": host, "skipped": True},
                    progress=skip_progress,
                )
                continue

            scan_queue.append((idx, host, ports, ip_address_id))

        # ── Phase 2: run ALL async I/O in a single event loop ──────
        # Port scans, banner grabs, and HTTP analyses for every host are
        # dispatched concurrently via ``asyncio.gather`` so the event
        # loop is created **once** instead of per host (or per port).
        # The PortScanner's internal semaphore already caps concurrent
        # connections, so batching hosts does not overwhelm the network.
        scan_results: list[Any] = []
        if scan_queue:
            scan_results = asyncio.run(
                _scan_all_hosts(
                    scanner, grabber, analyzer,
                    [(host, ports) for _, host, ports, _ in scan_queue],
                    do_banner_grab, do_http, web_ports,
                ),
            )

        # ── Phase 3: process results (sync persistence + progress) ─
        for (idx, host, _ports, ip_address_id), result in zip(
            scan_queue, scan_results, strict=True,
        ):
            # Graceful degradation — a failed host does not abort the batch.
            if isinstance(result, Exception):
                logger.exception("Port scan failed for %s: %s", host, result)
                fail_progress = (idx + 1) / total_targets * 100
                publish_progress(
                    self.request.id, scan_job_id,
                    fail_progress, "running",
                    f"Port scan failed for {host}: {result}",
                )
                _store_event(
                    svc, scan_job_id, "progress",
                    f"Port scan failed for {host}: {result}",
                    data={"host": host, "error": str(result)},
                    progress=fail_progress,
                )
                continue

            open_ports: list[int] = result["open_ports"]
            port_entries: list[dict[str, Any]] = result["port_entries"]

            host_port_infos: list[dict[str, Any]] = []
            for entry in port_entries:
                port: int = entry["port"]
                banner: str | None = entry["banner"]
                http_result: Any = entry["http_result"]

                # ── Risk classification ─────────────────────────────
                service_name = scanner.get_service_name(port)

                # Disambiguate SSH vs SFTP on port 22 using the banner.
                # SSH and SFTP share port 22; a banner advertising "sftp"
                # indicates the service also accepts file-transfer sessions.
                sftp_detected = is_sftp_on_ssh_port(port, banner)
                if sftp_detected:
                    service_name = "SSH/SFTP"

                risk = classifier.classify_port(port)
                risk_level = risk["severity"]
                risk_score = risk["final_score"]

                # Track findings. Severity is lowercase (see
                # RiskClassifier) to match the stored ``risk_level``.
                if risk_level == "critical":
                    running_critical += 1
                elif risk_level == "high":
                    running_high += 1
                elif risk_level == "medium":
                    running_medium += 1
                elif risk_level == "low":
                    running_low += 1

                # ── Persist port result ─────────────────────────────
                try:
                    svc.store_port_result(
                        scan_job_id=scan_job_id,
                        ip_address_id=ip_address_id,
                        port=port,
                        state="open",
                        service_name=service_name,
                        banner=banner,
                        risk_level=risk_level,
                        risk_score=risk_score,
                    )
                except Exception as exc:
                    logger.exception(
                        "Failed to persist port result %s:%d — %s", host, port, exc,
                    )
                    # Continue — persistence failure should not stop
                    # other ports from being recorded.

                port_info: dict[str, Any] = {
                    "host": host,
                    "port": port,
                    "service": service_name,
                    "banner": banner,
                    "risk_level": risk_level,
                    "risk_score": risk_score,
                }
                # Annotate SFTP capability detected from the banner.
                if sftp_detected:
                    port_info["metadata"] = {"sftp_capability": True}

                # ── Persist HTTP analysis (web ports only) ───────────
                if http_result is not None:
                    port_info["http_analysis"] = http_result
                    try:
                        svc.store_http_analysis(
                            scan_job_id=scan_job_id,
                            ip_address_id=ip_address_id,
                            port=port,
                            url=http_result.url,
                            status_code=http_result.status_code,
                            is_static=http_result.is_static,
                            has_login=http_result.has_login,
                            has_rate_limit=http_result.has_rate_limit,
                            response_headers=http_result.response_headers,
                            technologies=http_result.technologies,
                            certificates=http_result.certificates,
                            security_headers=http_result.security_headers,
                            security_headers_score=http_result.security_headers_score,
                            tls_version=http_result.tls_version,
                            title=http_result.title,
                            static_evidence=http_result.static_evidence,
                            login_evidence=http_result.login_evidence,
                            rate_limit_details=http_result.rate_limit_details,
                        )
                    except Exception as exc:
                        logger.debug(
                            "HTTP analysis failed for %s:%d — %s", host, port, exc,
                        )

                host_port_infos.append(port_info)

            all_open_ports.extend(host_port_infos)
            running_ports_found = len(all_open_ports)

            # ── Update progress after each host ─────────────────────
            progress_pct = (idx + 1) / total_targets * 100
            try:
                svc.update_scan_job_progress(
                    scan_job_id,
                    progress=progress_pct,
                    status="running",
                    ports_found=running_ports_found,
                    findings_critical=running_critical,
                    findings_high=running_high,
                    findings_medium=running_medium,
                    findings_low=running_low,
                    ips_scanned=1,
                )
            except Exception as exc:
                logger.warning("Failed to update progress for %s: %s", scan_job_id, exc)

            _store_event(
                svc, scan_job_id, "host_scanned",
                f"Scanned {host} — found {len(open_ports)} open port(s)",
                data={
                    "host": host,
                    "open_ports": len(open_ports),
                    "ports_found_this_host": len(open_ports),
                },
                progress=progress_pct,
            )

            publish_progress(
                self.request.id, scan_job_id, progress_pct, "running",
                f"Scanned {host} — found {len(open_ports)} open port(s)",
                {"current_host": host, "ports_found_this_host": len(open_ports)},
            )

        # ── Mark scan as completed ──────────────────────────────────
        completed_at = datetime.now(UTC)
        try:
            svc.update_scan_job_progress(
                scan_job_id,
                progress=100.0,
                status="completed",
                ports_found=running_ports_found,
                findings_critical=running_critical,
                findings_high=running_high,
                findings_medium=running_medium,
                findings_low=running_low,
                completed_at=completed_at,
            )
        except Exception as exc:
            logger.warning("Failed to mark scan %s as completed: %s", scan_job_id, exc)

        _store_event(
            svc, scan_job_id, "completed",
            f"Scan complete. Found {running_ports_found} open port(s).",
            data={
                "ports_found": running_ports_found,
                "findings_critical": running_critical,
                "findings_high": running_high,
                "findings_medium": running_medium,
                "findings_low": running_low,
            },
            progress=100.0,
        )

        publish_progress(
            self.request.id, scan_job_id, 100, "complete",
            f"Scan complete. Found {running_ports_found} open port(s).",
        )

        return {
            "scan_job_id": scan_job_id,
            "status": "completed",
            "ports_found": running_ports_found,
            "findings_critical": running_critical,
            "findings_high": running_high,
            "findings_medium": running_medium,
            "findings_low": running_low,
            "results": all_open_ports,
        }

    except Exception as exc:
        logger.exception("Fatal error in port scan job %s: %s", scan_job_id, exc)
        try:
            svc.update_scan_job_progress(
                scan_job_id, 0, status="failed", error_message=str(exc),
            )
        except Exception:
            logger.exception("Failed to update scan job %s to failed", scan_job_id)
        _store_event(svc, scan_job_id, "failed", f"Scan failed: {exc}")

        publish_progress(
            self.request.id, scan_job_id, 0, "error",
            f"Scan failed: {exc}",
        )

        return {
            "scan_job_id": scan_job_id,
            "status": "failed",
            "error": str(exc),
        }

    finally:
        svc.close()


# ── HTTP-analysis task ──────────────────────────────────────────────


@celery_app.task(  # type: ignore[untyped-decorator]
    bind=True,
    max_retries=2,
    acks_late=True,
    track_started=True,
    queue="scans",
)
def run_http_analysis(  # type: ignore[no-untyped-def]
    self,
    scan_job_id: str,
    targets: list[dict[str, Any]],
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run HTTP analysis on targets with open HTTP/HTTPS ports.

    Analyses each target with ``HttpAnalyzer`` and persists every
    result as an ``HttpAnalysis`` row.

    Parameters
    ----------
    scan_job_id : str
        UUID of the ``ScanJob`` record.
    targets : list[dict]
        List of dicts containing at minimum ``host`` and ``port`` keys.
    config : dict or None
        Optional configuration overrides.

    Returns
    -------
    dict
        Analysis results per target.
    """
    _ = config
    total_targets = len(targets)

    # Guard: empty targets.
    if total_targets == 0:
        publish_progress(
            self.request.id, scan_job_id, 100, "complete",
            "No HTTP targets provided.",
        )
        svc = _get_sync_service()
        try:
            svc.update_scan_job_progress(
                scan_job_id, 100, status="completed",
            )
        finally:
            svc.close()
        return {
            "scan_job_id": scan_job_id,
            "status": "completed",
            "results": [],
        }

    from app.scanner.http_analyzer import HttpAnalyzer

    analyzer = HttpAnalyzer()
    svc = _get_sync_service()
    results: list[dict[str, Any]] = []

    try:
        for idx, target in enumerate(targets):
            host = target.get("host", "")
            port = target.get("port", 80)

            if not host:
                logger.warning("Skipping target with empty host: %s", target)
                continue

            ip_address_id = _lookup_ip_id(svc, host)
            if ip_address_id is None:
                logger.warning("IP %s not found in DB; skipping HTTP analysis", host)
                results.append({"host": host, "port": port, "error": "IP not found"})
                continue

            try:
                http_result = asyncio.run(analyzer.analyze(host, port))

                # Persist analysis result.
                try:
                    svc.store_http_analysis(
                        scan_job_id=scan_job_id,
                        ip_address_id=ip_address_id,
                        port=port,
                        url=http_result.url,
                        status_code=http_result.status_code,
                        is_static=http_result.is_static,
                        has_login=http_result.has_login,
                        has_rate_limit=http_result.has_rate_limit,
                        response_headers=http_result.response_headers,
                        technologies=http_result.technologies,
                        certificates=http_result.certificates,
                        security_headers=http_result.security_headers,
                        security_headers_score=http_result.security_headers_score,
                        tls_version=http_result.tls_version,
                        title=http_result.title,
                        static_evidence=http_result.static_evidence,
                        login_evidence=http_result.login_evidence,
                        rate_limit_details=http_result.rate_limit_details,
                    )
                except Exception as exc:
                    logger.exception(
                        "Failed to persist HTTP analysis for %s:%d — %s",
                        host, port, exc,
                    )

                results.append({"host": host, "port": port, "result": http_result})
            except Exception as exc:
                logger.exception("HTTP analysis failed for %s:%d — %s", host, port, exc)
                results.append({"host": host, "port": port, "error": str(exc)})

            # Update progress.
            progress_pct = (idx + 1) / total_targets * 100
            try:
                svc.update_scan_job_progress(
                    scan_job_id, progress=progress_pct, status="running",
                )
            except Exception as exc:
                logger.warning(
                    "Failed to update progress for %s: %s", scan_job_id, exc,
                )

            publish_progress(
                self.request.id, scan_job_id, progress_pct, "running",
                f"Analysed HTTP on {host}:{port}",
            )

        # Mark as completed.
        try:
            svc.update_scan_job_progress(
                scan_job_id, progress=100.0, status="completed",
            )
        except Exception as exc:
            logger.warning(
                "Failed to complete HTTP analysis for %s: %s", scan_job_id, exc,
            )

        publish_progress(
            self.request.id, scan_job_id, 100, "complete",
            f"HTTP analysis complete. {len(results)} target(s) analysed.",
        )

    except Exception as exc:
        logger.exception(
            "Fatal error in HTTP analysis job %s: %s", scan_job_id, exc,
        )
        try:
            svc.update_scan_job_progress(
                scan_job_id, 0, status="failed", error_message=str(exc),
            )
        except Exception:
            logger.exception("Failed to mark HTTP analysis %s as failed", scan_job_id)

        publish_progress(
            self.request.id, scan_job_id, 0, "error",
            f"HTTP analysis failed: {exc}",
        )

    finally:
        svc.close()

    return {
        "scan_job_id": scan_job_id,
        "status": "completed",
        "results": results,
    }
