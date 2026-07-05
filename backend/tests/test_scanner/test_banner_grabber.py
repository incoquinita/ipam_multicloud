"""Unit tests for the TCP banner grabber.

Exercises ``BannerGrabber.grab_banner`` with a mocked
``asyncio.open_connection`` so no real sockets are opened.

Covered scenarios:
- HTTP port (80): ``HEAD`` probe → banner text returned
- Non-HTTP port (22): raw ``\\r\\n\\r\\n`` probe → banner text returned
- Connection refused → ``None``
- Connection timeout → ``None``
- Constructor validation: non-positive timeout raises ``ValueError``
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import patch

import pytest

from app.scanner.banner_grabber import BannerGrabber

# Pure unit tests — the shared ``tests/test_scanner/conftest.py`` already
# neutralises the root ``setup_database`` fixture, so no DB is touched.


# ── Test doubles ──────────────────────────────────────────────────


class _FakeReader:
    """Minimal ``asyncio.StreamReader`` stub returning a canned payload."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    async def read(self, n: int = -1) -> bytes:  # noqa: ARG002
        """Return the canned payload (ignores ``n``)."""
        return self._payload


class _FakeWriter:
    """Minimal ``asyncio.StreamWriter`` stub recording the bytes sent."""

    def __init__(self) -> None:
        self.written: bytearray = bytearray()

    def write(self, data: bytes) -> None:
        """Record the outgoing probe bytes."""
        self.written += data

    async def drain(self) -> None:
        """No-op drain."""

    def close(self) -> None:
        """No-op close."""

    async def wait_closed(self) -> None:
        """No-op wait_closed."""


def _open_connection_returning(payload: bytes) -> Any:
    """Build an async fake for ``asyncio.open_connection`` returning *payload*."""

    async def _fake_open_connection(
        _host: str, _port: int,
    ) -> tuple[_FakeReader, _FakeWriter]:
        return _FakeReader(payload), _FakeWriter()

    return _fake_open_connection


# ── HTTP-port banner (HEAD probe) ─────────────────────────────────


@pytest.mark.asyncio
async def test_grab_banner_http_port_sends_head_and_returns_response() -> None:
    """Port 80 triggers a ``HEAD`` request and returns the decoded banner."""
    grabber = BannerGrabber(timeout=1.0)
    banner_text = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
    fake = _open_connection_returning(banner_text.encode())

    with patch("asyncio.open_connection", side_effect=fake) as mock_open:
        banner = await grabber.grab_banner("10.0.0.1", 80)

    assert banner == banner_text.strip()
    mock_open.assert_awaited_once_with("10.0.0.1", 80)


@pytest.mark.asyncio
async def test_grab_banner_https_port_sends_head() -> None:
    """Port 443 is in ``HTTP_PORTS`` and also triggers a ``HEAD`` probe."""
    grabber = BannerGrabber(timeout=1.0)
    banner_text = "HTTP/1.1 200 OK\r\nServer: apache\r\n\r\n"
    fake = _open_connection_returning(banner_text.encode())

    with patch("asyncio.open_connection", side_effect=fake):
        banner = await grabber.grab_banner("10.0.0.1", 443)

    assert banner is not None
    assert "apache" in banner


# ── Non-HTTP-port banner (raw probe) ──────────────────────────────


@pytest.mark.asyncio
async def test_grab_banner_non_http_port_sends_raw_probe() -> None:
    """A non-HTTP port (22) sends ``\\r\\n\\r\\n`` and returns the raw banner."""
    grabber = BannerGrabber(timeout=1.0)
    banner_text = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
    fake = _open_connection_returning(banner_text.encode())

    with patch("asyncio.open_connection", side_effect=fake):
        banner = await grabber.grab_banner("10.0.0.1", 22)

    assert banner == banner_text.strip()
    assert "SSH" in banner


@pytest.mark.asyncio
async def test_grab_banner_returns_none_when_response_is_empty() -> None:
    """An empty banner payload resolves to ``None``."""
    grabber = BannerGrabber(timeout=1.0)
    fake = _open_connection_returning(b"")

    with patch("asyncio.open_connection", side_effect=fake):
        banner = await grabber.grab_banner("10.0.0.1", 22)

    assert banner is None


# ── Failure modes ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_grab_banner_returns_none_on_connection_refused() -> None:
    """``ConnectionRefusedError`` is swallowed → ``None``."""
    grabber = BannerGrabber(timeout=1.0)

    async def _refused(_host: str, _port: int) -> tuple[Any, Any]:
        raise ConnectionRefusedError

    with patch("asyncio.open_connection", side_effect=_refused):
        banner = await grabber.grab_banner("10.0.0.1", 22)

    assert banner is None


@pytest.mark.asyncio
async def test_grab_banner_returns_none_on_timeout() -> None:
    """A connection ``TimeoutError`` resolves to ``None``."""
    grabber = BannerGrabber(timeout=0.01)

    async def _slow(_host: str, _port: int) -> tuple[Any, Any]:
        await asyncio.sleep(1.0)  # Exceeds the 0.01s timeout.
        raise AssertionError("should not reach")

    with patch("asyncio.open_connection", side_effect=_slow):
        banner = await grabber.grab_banner("10.0.0.1", 22)

    assert banner is None


@pytest.mark.asyncio
async def test_grab_banner_returns_none_on_os_error() -> None:
    """Generic ``OSError`` (e.g. network unreachable) resolves to ``None``."""
    grabber = BannerGrabber(timeout=1.0)

    async def _oserror(_host: str, _port: int) -> tuple[Any, Any]:
        raise OSError("network unreachable")

    with patch("asyncio.open_connection", side_effect=_oserror):
        banner = await grabber.grab_banner("10.0.0.1", 22)

    assert banner is None


# ── Constructor validation ────────────────────────────────────────


def test_grabber_rejects_zero_timeout() -> None:
    """``timeout <= 0`` raises a descriptive ``ValueError``."""
    with pytest.raises(ValueError, match="timeout must be positive"):
        BannerGrabber(timeout=0)


def test_grabber_rejects_negative_timeout() -> None:
    """Negative timeout raises a descriptive ``ValueError``."""
    with pytest.raises(ValueError, match="timeout must be positive"):
        BannerGrabber(timeout=-1.0)
