"""Tests for the SSH/SFTP disambiguation logic in ``scan_tasks``.

SSH and SFTP both listen on port 22.  The disambiguation rule: if the
grabbed banner contains the substring ``"sftp"`` (case-insensitive),
the service is reported as ``"SSH/SFTP"``; otherwise it stays ``"SSH"``.

These tests exercise the pure helper ``is_sftp_on_ssh_port`` and the
service-name derivation that builds on it, so no Celery task or
database wiring is required.
"""

from __future__ import annotations

import pytest

from app.scanner.port_scanner import PortScanner
from app.workers.scan_tasks import is_sftp_on_ssh_port

# Pure unit tests — the shared ``tests/test_scanner/conftest.py`` already
# neutralises the root ``setup_database`` fixture, so no DB is touched.


# ── is_sftp_on_ssh_port predicate ─────────────────────────────────


@pytest.mark.parametrize(
    ("port", "banner", "expected"),
    [
        # Port 22 with an SFTP-advertising banner → True.
        (22, "SSH-2.0-OpenSSH_8.9 sftp-server", True),
        # Case-insensitive: uppercase "SFTP" still matches.
        (22, "SSH-2.0-SFTP-subsystem", True),
        # Port 22 with only SSH in the banner → False.
        (22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", False),
        # Port 22 with no banner (None) → False.
        (22, None, False),
        # Port 22 with an empty banner → False.
        (22, "", False),
        # Non-SSH port with "sftp" in banner → False (port guard).
        (2222, "sftp-server", False),
        # Non-SSH port with no banner → False.
        (80, None, False),
    ],
)
def test_is_sftp_on_ssh_port(port: int, banner: str | None, expected: bool) -> None:
    """The predicate returns ``True`` only for port 22 + ``sftp`` banner."""
    assert is_sftp_on_ssh_port(port, banner) is expected


# ── Service-name derivation ───────────────────────────────────────


def _resolve_service_name(port: int, banner: str | None) -> str:
    """Mirror the service-name derivation used in ``run_port_scan``.

    This replicates the two-line snippet in the Celery task so the test
    stays focused on the disambiguation contract without spinning up a
    full task instance.
    """
    scanner = PortScanner()
    service_name = scanner.get_service_name(port)
    if is_sftp_on_ssh_port(port, banner):
        return "SSH/SFTP"
    return service_name


@pytest.mark.parametrize(
    ("banner", "expected_service"),
    [
        ("SSH-2.0-OpenSSH_8.9 sftp-server", "SSH/SFTP"),
        ("SSH-2.0-SFTP-subsystem", "SSH/SFTP"),
        ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "SSH"),
        (None, "SSH"),
        ("", "SSH"),
    ],
)
def test_sftp_disambiguation_on_port_22(banner: str | None, expected_service: str) -> None:
    """Port 22 service name reflects SFTP capability based on the banner.

    - banner with ``"sftp"`` → ``"SSH/SFTP"``
    - banner with only ``"ssh"`` → ``"SSH"``
    - ``None`` banner → ``"SSH"``
    - empty banner → ``"SSH"``
    """
    assert _resolve_service_name(22, banner) == expected_service


def test_sftp_disambiguation_does_not_affect_other_ports() -> None:
    """A non-22 port with ``sftp`` in the banner keeps its own service name."""
    assert _resolve_service_name(2222, "sftp-server") == "unknown"
    assert _resolve_service_name(80, "sftp") == "HTTP"
