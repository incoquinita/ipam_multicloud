"""Structured logging configuration using structlog.

Parses ``settings.DEBUG`` at import time to choose between pretty
development output and production JSON.  Call :func:`configure_logging`
once at application startup.
"""

import logging
import sys

import structlog

from app.config import get_settings


def configure_logging() -> None:
    """Configure structlog and standard-library loggers.

    In DEBUG mode timestamps are human-readable and the console output
    is colorised.  In production every log line is a JSON object
    consumable by log aggregators.
    """
    settings = get_settings()
    log_level = logging.DEBUG if settings.DEBUG else logging.INFO

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso" if settings.DEBUG else "iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.CallsiteParameterAdder(
            [
                structlog.processors.CallsiteParameter.FUNC_NAME,
                structlog.processors.CallsiteParameter.LINENO,
            ],
        ),
    ]

    if settings.DEBUG:
        processors: list[structlog.types.Processor] = [
            *shared_processors,
            structlog.dev.ConsoleRenderer(
                colors=True,
                force_colors=True,
            ),
        ]
    else:
        processors = [
            *shared_processors,
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Route standard-library logs through structlog.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )


# Pre-configured logger for import convenience.
logger = structlog.get_logger("ipam_scanner")
