"""Model registry — re-exports all ORM models for convenient imports.

Usage::

    from app.models import CloudProvider, ScanTarget, Base
"""

from app.models.base import Base
from app.models.cloud_credential import CloudCredential
from app.models.cloud_provider import CloudProvider
from app.models.http_analysis import HttpAnalysis
from app.models.ip_address import IPAddress
from app.models.port_result import PortResult
from app.models.scan_event import ScanEvent
from app.models.scan_job import ScanJob
from app.models.scan_target import ScanTarget
from app.models.user import User

__all__ = [
    "Base",
    "CloudProvider",
    "CloudCredential",
    "ScanTarget",
    "IPAddress",
    "ScanJob",
    "PortResult",
    "HttpAnalysis",
    "ScanEvent",
    "User",
]
