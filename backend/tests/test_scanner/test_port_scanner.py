"""Unit tests for the async TCP port scanner.

Exercises the public ``PortScanner`` API: ``scan_host``, ``get_service_name``,
``get_admin_ports``, and constructor validation.  Network I/O is mocked so the
tests are deterministic and fast — no real sockets are opened.
"""

import asyncio
from collections.abc import AsyncGenerator, Awaitable, Callable
from unittest.mock import patch

import pytest
import pytest_asyncio

from app.scanner.port_scanner import PortScanner

# ── Fixture override ──────────────────────────────────────────────
# Port scanner tests are pure unit tests and need no database.  The root
# conftest defines an autouse ``setup_database`` fixture that builds every
# table under SQLite (which chokes on JSONB columns), so override it here
# with a no-op to keep these tests isolated and green.


@pytest_asyncio.fixture(autouse=True)
async def setup_database() -> AsyncGenerator[None, None]:
    """No-op override of the root conftest DB fixture for scanner unit tests."""
    yield


# ── Test doubles ──────────────────────────────────────────────────


class _FakeWriter:
    """Minimal ``asyncio.StreamWriter`` stub for open-connection mocks."""

    def close(self) -> None:
        """No-op close."""

    async def wait_closed(self) -> None:
        """No-op wait_closed."""


def _open_connection_for(
    open_ports: set[int],
) -> Callable[[str, int], Awaitable[tuple[None, _FakeWriter]]]:
    """Return an async fake for ``asyncio.open_connection``.

    Ports in *open_ports* resolve to a successful connection; every other
    port raises ``ConnectionRefusedError``.
    """

    async def _fake_open_connection(_host: str, port: int) -> tuple[None, _FakeWriter]:
        if port in open_ports:
            return (None, _FakeWriter())
        raise ConnectionRefusedError

    return _fake_open_connection


# ── scan_host ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_host_returns_sorted_open_ports() -> None:
    """scan_host returns only the open ports, sorted ascending."""
    scanner = PortScanner(concurrency=10, timeout=1.0)
    open_ports = {443, 22, 80}

    with patch("asyncio.open_connection", side_effect=_open_connection_for(open_ports)):
        result = await scanner.scan_host("127.0.0.1", [9090, 8080, 443, 80, 22])

    assert result == [22, 80, 443]


@pytest.mark.asyncio
async def test_scan_host_empty_port_list_returns_empty_without_scanning() -> None:
    """scan_host with an empty port list returns [] and never opens a connection."""
    scanner = PortScanner(timeout=1.0)

    with patch("asyncio.open_connection") as mock_open:
        result = await scanner.scan_host("127.0.0.1", [])

    assert result == []
    mock_open.assert_not_called()


@pytest.mark.asyncio
async def test_scan_host_all_closed_returns_empty() -> None:
    """scan_host returns an empty list when every port refuses the connection."""
    scanner = PortScanner(concurrency=10, timeout=1.0)

    with patch("asyncio.open_connection", side_effect=_open_connection_for(set())):
        result = await scanner.scan_host("127.0.0.1", [22, 80, 443])

    assert result == []


# ── _scan_port ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_port_returns_port_when_open() -> None:
    """_scan_port returns the port number when the connection succeeds."""
    scanner = PortScanner(concurrency=10, timeout=1.0)

    with patch("asyncio.open_connection", side_effect=_open_connection_for({80})):
        result = await scanner._scan_port("127.0.0.1", 80)

    assert result == 80


@pytest.mark.asyncio
async def test_scan_port_returns_none_when_closed() -> None:
    """_scan_port returns None when the connection is refused."""
    scanner = PortScanner(concurrency=10, timeout=1.0)

    with patch("asyncio.open_connection", side_effect=_open_connection_for(set())):
        result = await scanner._scan_port("127.0.0.1", 81)

    assert result is None


# ── Concurrency ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_host_never_exceeds_concurrency_limit() -> None:
    """scan_host never runs more in-flight connections than configured."""
    in_flight = 0
    max_in_flight = 0

    async def _tracking_open_connection(_host: str, _port: int) -> tuple[None, _FakeWriter]:
        nonlocal in_flight, max_in_flight
        in_flight += 1
        max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.05)  # hold the connection so overlaps are observable
        in_flight -= 1
        raise ConnectionRefusedError

    scanner = PortScanner(concurrency=2, timeout=2.0)

    with patch("asyncio.open_connection", side_effect=_tracking_open_connection):
        await scanner.scan_host("127.0.0.1", list(range(1, 21)))

    assert max_in_flight <= 2


# ── Timeout ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_host_timeout_treats_slow_ports_as_closed() -> None:
    """Ports whose connection exceeds the timeout are omitted from results."""

    async def _slow_open_connection(_host: str, _port: int) -> tuple[None, _FakeWriter]:
        await asyncio.sleep(1.0)  # longer than the scanner timeout
        return (None, _FakeWriter())

    scanner = PortScanner(concurrency=10, timeout=0.1)

    with patch("asyncio.open_connection", side_effect=_slow_open_connection):
        result = await scanner.scan_host("127.0.0.1", [80, 443])

    assert result == []


@pytest.mark.asyncio
async def test_scan_port_returns_none_on_timeout() -> None:
    """_scan_port returns None when the connection exceeds the timeout."""

    async def _slow_open_connection(_host: str, _port: int) -> tuple[None, _FakeWriter]:
        await asyncio.sleep(1.0)
        return (None, _FakeWriter())

    scanner = PortScanner(concurrency=10, timeout=0.1)

    with patch("asyncio.open_connection", side_effect=_slow_open_connection):
        result = await scanner._scan_port("127.0.0.1", 80)

    assert result is None


# ── get_service_name ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("port", "expected"),
    [
        (22, "SSH"),
        (80, "HTTP"),
        (443, "HTTPS"),
        (491, "GoGlobal"),
        (1494, "Citrix-ICA"),
        (2598, "Citrix-CGP"),
        (3200, "SAP-Dispatcher"),
        (3300, "SAP-Dispatcher"),
        (3601, "SAP-Message-Server"),
        (3901, "SAP-Message-Server-HTTP"),
    ],
)
def test_get_service_name_known_ports(port: int, expected: str) -> None:
    """get_service_name maps well-known ports to their service names."""
    scanner = PortScanner()
    assert scanner.get_service_name(port) == expected


def test_get_service_name_unknown_port_returns_unknown() -> None:
    """get_service_name returns 'unknown' for ports outside the well-known map."""
    scanner = PortScanner()
    assert scanner.get_service_name(12345) == "unknown"


# ── get_admin_ports ───────────────────────────────────────────────


def test_get_admin_ports_returns_independent_copy() -> None:
    """get_admin_ports returns a copy; mutating it does not affect the internal map."""
    scanner = PortScanner()
    ports = scanner.get_admin_ports()
    ports[9999] = "injected"
    assert 9999 not in scanner.get_admin_ports()


# ── Constructor validation ────────────────────────────────────────


def test_scanner_rejects_zero_concurrency() -> None:
    """concurrency < 1 raises a descriptive ValueError."""
    with pytest.raises(ValueError, match="concurrency must be >= 1"):
        PortScanner(concurrency=0)


def test_scanner_rejects_negative_concurrency() -> None:
    """Negative concurrency raises a descriptive ValueError."""
    with pytest.raises(ValueError, match="concurrency must be >= 1"):
        PortScanner(concurrency=-5)


def test_scanner_rejects_zero_timeout() -> None:
    """timeout <= 0 raises a descriptive ValueError."""
    with pytest.raises(ValueError, match="timeout must be > 0"):
        PortScanner(timeout=0)


def test_scanner_rejects_negative_timeout() -> None:
    """Negative timeout raises a descriptive ValueError."""
    with pytest.raises(ValueError, match="timeout must be > 0"):
        PortScanner(timeout=-1.0)
