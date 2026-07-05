"""Celery scan task unit tests.

Exercises ``run_port_scan``, ``_scan_one_host``, ``_scan_all_hosts``,
and ``publish_progress`` with mocked scanner engine, DB service, and
Redis.  No real network I/O, database, or Redis connections are made.

Calling ``run_port_scan``:
    The task is declared with ``bind=True``, so we call it via
    ``run_port_scan.apply(args=...)`` which executes eagerly and passes
    the task instance as ``self`` (including ``self.request.id``).
    These tests are **sync** because ``run_port_scan`` calls
    ``asyncio.run()`` internally, which cannot be nested inside a
    running event loop.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from app.workers.scan_tasks import (
    _scan_all_hosts,
    _scan_one_host,
    is_sftp_on_ssh_port,
    publish_progress,
    run_port_scan,
)

# ── Test doubles ──────────────────────────────────────────────────


def _mock_scan_result_service(ip_id: str = "ip-uuid-123") -> MagicMock:
    """Build a mock ScanResultService with all methods the task calls."""
    svc = MagicMock()
    svc.get_ip_address_id.return_value = ip_id
    svc.update_scan_job_progress.return_value = None
    svc.store_port_result.return_value = MagicMock()
    svc.store_http_analysis.return_value = MagicMock()
    svc.store_scan_event.return_value = MagicMock()
    svc.close.return_value = None
    return svc


def _mock_http_result() -> MagicMock:
    """Build a mock HttpAnalysisResult with all attributes the task reads."""
    return MagicMock(
        url="http://10.0.0.1:80",
        status_code=200,
        is_static=False,
        has_login=False,
        has_rate_limit=False,
        response_headers={},
        technologies=[],
        certificates={},
        security_headers={},
        security_headers_score=5,
        tls_version=None,
        title="Test Page",
        static_evidence=[],
        login_evidence=[],
        rate_limit_details={},
    )


# ── publish_progress ──────────────────────────────────────────────


def test_publish_progress_emits_ws_message_shape() -> None:
    """publish_progress writes a JSON body with type, scan_job_id, timestamp, payload."""
    fake_redis = MagicMock()
    with patch("redis.from_url", return_value=fake_redis):
        publish_progress(
            task_id="task-1",
            scan_job_id="scan-1",
            progress=50.0,
            status="running",
            message="Scanning host",
            data={"host": "10.0.0.1"},
        )

    # setex should have been called with the channel, a TTL, and a JSON body.
    fake_redis.setex.assert_called_once()
    _channel, ttl, encoded = fake_redis.setex.call_args.args
    assert ttl == 600
    body = json.loads(encoded)
    assert body["type"] == "scan_progress"
    assert body["scan_job_id"] == "scan-1"
    assert "timestamp" in body
    payload = body["payload"]
    assert payload["task_id"] == "task-1"
    assert payload["progress"] == 50.0
    assert payload["status"] == "running"
    assert payload["message"] == "Scanning host"
    assert payload["data"] == {"host": "10.0.0.1"}

    # The same body should be published on the same channel.
    fake_redis.publish.assert_called_once()
    pub_channel, pub_encoded = fake_redis.publish.call_args.args
    assert pub_channel == _channel
    assert pub_encoded == encoded


def test_publish_progress_maps_complete_status_to_ws_type() -> None:
    """The 'complete' status maps to the 'scan_complete' WS type."""
    fake_redis = MagicMock()
    with patch("redis.from_url", return_value=fake_redis):
        publish_progress("task-1", "scan-1", 100, "complete", "Done")

    body = json.loads(fake_redis.setex.call_args.args[2])
    assert body["type"] == "scan_complete"


def test_publish_progress_swallows_redis_errors() -> None:
    """publish_progress never raises on Redis write failures — they are logged."""
    fake_redis = MagicMock()
    fake_redis.setex.side_effect = Exception("Redis write error")
    with patch("redis.from_url", return_value=fake_redis):
        # Should not raise despite the setex error.
        publish_progress("task-1", "scan-1", 50, "running", "ok")


# ── _scan_one_host ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_one_host_returns_open_ports_and_entries() -> None:
    """_scan_one_host scans ports, grabs banners, and runs HTTP analysis on web ports."""
    async def _fake_scan_host(_host, _ports):
        return [22, 80]

    async def _fake_grab_banner(_host, _port):
        return f"banner-{_port}"

    async def _fake_analyze(_host, _port):
        return _mock_http_result()

    scanner = MagicMock()
    scanner.scan_host = _fake_scan_host
    grabber = MagicMock()
    grabber.grab_banner = _fake_grab_banner
    analyzer = MagicMock()
    analyzer.analyze = _fake_analyze

    result = await _scan_one_host(
        scanner, grabber, analyzer,
        host="10.0.0.1",
        ports=[22, 80, 443],
        do_banner_grab=True,
        do_http=True,
        web_ports=(80, 443, 8080, 8443),
    )

    assert result["host"] == "10.0.0.1"
    assert result["open_ports"] == [22, 80]
    assert len(result["port_entries"]) == 2
    # Port 80 is a web port → HTTP analysis should be attached.
    port_80_entry = next(e for e in result["port_entries"] if e["port"] == 80)
    assert port_80_entry["http_result"] is not None
    # Port 22 is not a web port → no HTTP analysis.
    port_22_entry = next(e for e in result["port_entries"] if e["port"] == 22)
    assert port_22_entry["http_result"] is None


@pytest.mark.asyncio
async def test_scan_one_host_skips_banner_when_disabled() -> None:
    """When do_banner_grab is False, no banner is grabbed."""
    async def _fake_scan_host(_host, _ports):
        return [22]

    scanner = MagicMock()
    scanner.scan_host = _fake_scan_host
    grabber = MagicMock()
    grabber.grab_banner = MagicMock(side_effect=AssertionError("should not be called"))
    analyzer = MagicMock()

    result = await _scan_one_host(
        scanner, grabber, analyzer,
        host="10.0.0.1", ports=[22],
        do_banner_grab=False, do_http=False,
        web_ports=(80, 443),
    )

    assert result["open_ports"] == [22]
    assert result["port_entries"][0]["banner"] is None


# ── _scan_all_hosts ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_all_hosts_returns_results_for_each_host() -> None:
    """_scan_all_hosts returns one result per host, preserving order."""
    async def _fake_scan_host(_host, _ports):
        return [80]

    async def _no_banner(_h, _p):
        return None

    async def _no_http(_h, _p):
        return None

    scanner = MagicMock()
    scanner.scan_host = _fake_scan_host
    grabber = MagicMock()
    grabber.grab_banner = _no_banner
    analyzer = MagicMock()
    analyzer.analyze = _no_http

    targets = [("10.0.0.1", [80]), ("10.0.0.2", [80])]
    results = await _scan_all_hosts(
        scanner, grabber, analyzer, targets,
        do_banner_grab=False, do_http=False,
        web_ports=(80,),
    )

    assert len(results) == 2
    assert results[0]["host"] == "10.0.0.1"
    assert results[1]["host"] == "10.0.0.2"


@pytest.mark.asyncio
async def test_scan_all_hosts_surfaces_exceptions_via_return_exceptions() -> None:
    """A failing host scan surfaces as an Exception, not a crash."""
    async def _fake_scan_host(host, _ports):
        if host == "10.0.0.2":
            raise OSError("connection refused")
        return [80]

    scanner = MagicMock()
    scanner.scan_host = _fake_scan_host
    grabber = MagicMock()
    analyzer = MagicMock()

    results = await _scan_all_hosts(
        scanner, grabber, analyzer,
        [("10.0.0.1", [80]), ("10.0.0.2", [80])],
        do_banner_grab=False, do_http=False,
        web_ports=(80,),
    )

    assert len(results) == 2
    assert isinstance(results[0], dict)
    assert isinstance(results[1], Exception)


# ── is_sftp_on_ssh_port ───────────────────────────────────────────


def test_is_sftp_on_ssh_port_detects_sftp_banner() -> None:
    """Port 22 with 'sftp' in the banner returns True."""
    assert is_sftp_on_ssh_port(22, "SSH-2.0-sftp-server") is True


def test_is_sftp_on_ssh_port_rejects_non_22_ports() -> None:
    """Non-22 ports always return False regardless of banner."""
    assert is_sftp_on_ssh_port(80, "sftp") is False


# ── run_port_scan (sync tests) ────────────────────────────────────


def test_run_port_scan_empty_targets_returns_completed() -> None:
    """An empty targets list completes immediately with zero findings."""
    mock_svc = _mock_scan_result_service()
    with patch("app.workers.scan_tasks._get_sync_service", return_value=mock_svc), \
         patch("app.workers.scan_tasks.publish_progress") as mock_pub:
        result = run_port_scan.apply(
            args=("scan-job-1", [], {"profile": "standard"}),
        ).result

    assert result["status"] == "completed"
    assert result["ports_found"] == 0
    # publish_progress should have been called at least once (for completion).
    assert mock_pub.called


def test_run_port_scan_invalid_profile_returns_failed() -> None:
    """An invalid profile name causes the task to return a failed status."""
    mock_svc = _mock_scan_result_service()
    with patch("app.workers.scan_tasks._get_sync_service", return_value=mock_svc), \
         patch("app.workers.scan_tasks.publish_progress"):
        result = run_port_scan.apply(
            args=(
                "scan-job-1",
                [{"host": "10.0.0.1", "ports": [80]}],
                {"profile": "nonexistent-profile"},
            ),
        ).result

    assert result["status"] == "failed"
    assert "nonexistent-profile" in result["error"]
    # The service should have been told to mark the job as failed.
    mock_svc.update_scan_job_progress.assert_called()
    mock_svc.close.assert_called()


def test_run_port_scan_basic_flow_persists_results() -> None:
    """A single-host scan with open ports persists port results and completes."""
    mock_svc = _mock_scan_result_service()

    # Mock scanner classes so the lazy imports inside the task get mocks.
    mock_scanner_inst = MagicMock()
    mock_scanner_inst.get_service_name.return_value = "SSH"

    async def _scan_host(_h, _p):
        return [22, 80]

    mock_scanner_inst.scan_host = _scan_host

    async def _grab(_h, _p):
        return "SSH-2.0-OpenSSH"

    mock_grabber_inst = MagicMock()
    mock_grabber_inst.grab_banner = _grab

    async def _analyze(_h, _p):
        return _mock_http_result()

    mock_analyzer_inst = MagicMock()
    mock_analyzer_inst.analyze = _analyze

    mock_classifier = MagicMock()
    mock_classifier.classify_port.return_value = {
        "severity": "high",
        "final_score": 7.5,
    }

    with patch("app.workers.scan_tasks._get_sync_service", return_value=mock_svc), \
         patch("app.workers.scan_tasks.publish_progress"), \
         patch("app.scanner.port_scanner.PortScanner", return_value=mock_scanner_inst), \
         patch("app.scanner.banner_grabber.BannerGrabber", return_value=mock_grabber_inst), \
         patch("app.scanner.http_analyzer.HttpAnalyzer", return_value=mock_analyzer_inst), \
         patch("app.scanner.risk_classifier.RiskClassifier", return_value=mock_classifier):
        result = run_port_scan.apply(
            args=(
                "scan-job-1",
                [{"host": "10.0.0.1", "ports": [22, 80]}],
                {"profile": "standard", "banner_grab": True, "http_analysis": True},
            ),
        ).result

    assert result["status"] == "completed"
    assert result["ports_found"] == 2
    assert result["findings_high"] == 2  # Both ports classified as HIGH
    # The service should have been asked to persist port results.
    assert mock_svc.store_port_result.call_count == 2
    # HTTP analysis should be stored for port 80 (a web port).
    mock_svc.store_http_analysis.assert_called_once()
    mock_svc.close.assert_called()


def test_run_port_scan_skips_hosts_not_in_db() -> None:
    """A host not found in the DB (get_ip_address_id returns None) is skipped."""
    mock_svc = _mock_scan_result_service()
    mock_svc.get_ip_address_id.return_value = None  # IP not in DB

    with patch("app.workers.scan_tasks._get_sync_service", return_value=mock_svc), \
         patch("app.workers.scan_tasks.publish_progress"):
        result = run_port_scan.apply(
            args=(
                "scan-job-1",
                [{"host": "10.0.0.99", "ports": [80]}],
                {"profile": "standard"},
            ),
        ).result

    # The scan completes with zero ports (the host was skipped).
    assert result["status"] == "completed"
    assert result["ports_found"] == 0
    # No port results should have been stored.
    mock_svc.store_port_result.assert_not_called()
