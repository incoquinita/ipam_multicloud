"""Pydantic schema package — exports all API request/response models.

Importing from ``app.schemas`` gives access to every schema defined in
submodules so that endpoints and services can import cleanly:
``from app.schemas import CredentialCreate, ScanResultsResponse``.
"""

from app.schemas.analytics import (
    CloudProviderStatus,
    CloudStatusResponse,
    DashboardStats,
    PortDistribution,
    PortDistributionItem,
    RiskSummary,
    ScanTimeline,
    ScanTimelineItem,
)
from app.schemas.credentials import (
    CredentialBase,
    CredentialCreate,
    CredentialListResponse,
    CredentialResponse,
)
from app.schemas.ip_address import IPAddressListResponse, IPAddressResponse
from app.schemas.port_result import PortResultFilter, PortResultListResponse
from app.schemas.scan_result import (
    HttpAnalysisResponse,
    PortResultResponse,
    ScanResultsResponse,
    ScanResultsSummary,
)

__all__ = [
    # credentials
    "CredentialBase",
    "CredentialCreate",
    "CredentialResponse",
    "CredentialListResponse",
    # scan results
    "PortResultResponse",
    "HttpAnalysisResponse",
    "ScanResultsResponse",
    "ScanResultsSummary",
    # analytics
    "DashboardStats",
    "PortDistributionItem",
    "PortDistribution",
    "RiskSummary",
    "ScanTimelineItem",
    "ScanTimeline",
    "CloudProviderStatus",
    "CloudStatusResponse",
    # ip addresses
    "IPAddressResponse",
    "IPAddressListResponse",
    # port results
    "PortResultListResponse",
    "PortResultFilter",
]
