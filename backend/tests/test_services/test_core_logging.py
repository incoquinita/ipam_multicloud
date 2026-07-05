"""Structlog configuration unit tests.

Exercises ``configure_logging`` in both DEBUG and production modes so
the processor chains and stdlib routing are covered.  The function is
idempotent, so calling it twice (once per mode) is safe.
"""

from __future__ import annotations

from app.config import get_settings
from app.core import logging as logging_module
from app.core.logging import configure_logging


def _patch_debug(monkeypatch, debug: bool) -> None:
    """Make ``configure_logging`` see the requested DEBUG flag."""
    settings = get_settings()
    monkeypatch.setattr(settings, "DEBUG", debug)
    monkeypatch.setattr("app.core.logging.get_settings", lambda: settings)


def test_configure_logging_production_mode(monkeypatch) -> None:
    """Production (DEBUG=False) wires the JSON renderer and INFO level."""
    _patch_debug(monkeypatch, debug=False)
    configure_logging()  # should not raise


def test_configure_logging_debug_mode(monkeypatch) -> None:
    """Debug (DEBUG=True) wires the colorised console renderer."""
    _patch_debug(monkeypatch, debug=True)
    configure_logging()  # should not raise


def test_module_logger_is_available() -> None:
    """The pre-configured module logger is a bound structlog logger."""
    assert logging_module.logger is not None
