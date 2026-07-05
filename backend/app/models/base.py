"""Declarative base and model registry.

Importing this module ensures all model classes are registered with
SQLAlchemy's metadata so Alembic can autogenerate migrations.
"""

import app.models.cloud_credential  # noqa: F401

# Import every model to register it with the metadata.
# isort:skip
import app.models.cloud_provider  # noqa: F401
import app.models.http_analysis  # noqa: F401
import app.models.ip_address  # noqa: F401
import app.models.port_result  # noqa: F401
import app.models.scan_event  # noqa: F401
import app.models.scan_job  # noqa: F401
import app.models.scan_target  # noqa: F401
import app.models.user  # noqa: F401
from app.core.database import Base

__all__ = ["Base"]
