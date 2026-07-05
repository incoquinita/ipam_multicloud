"""Shared Pydantic models: enums, pagination, and common response wrappers.

All HTTP-facing schemas import from here for consistent pagination and
enum representation.
"""

from enum import StrEnum
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

# ── Enums ────────────────────────────────────────────────────────

class ScanType(StrEnum):
    """Scan type — mirrors the named scan profiles.

    Values align with ``app.schemas.scan_profiles.SCAN_PROFILES`` so the
    frontend ``scan_type`` enum and the backend profile names share one
    vocabulary: ``quick | standard | thorough | custom``.
    """

    QUICK = "quick"
    STANDARD = "standard"
    THOROUGH = "thorough"
    CUSTOM = "custom"


class ScanStatus(StrEnum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PortState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"


class CloudProviderType(StrEnum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    OCI = "oci"


class TargetType(StrEnum):
    CIDR = "cidr"
    IP_LIST = "ip_list"
    CLOUD_PROVIDER = "cloud_provider"
    HOSTNAME = "hostname"


# ── Pagination ───────────────────────────────────────────────────

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated list response.

    The JSON field names ``size`` and ``pages`` match the frontend
    contract.  The Python attribute names ``page_size`` and
    ``total_pages`` remain available when constructing the model thanks
    to ``populate_by_name`` — existing endpoint code that passes
    ``page_size=...`` / ``total_pages=...`` keeps working unchanged.
    """

    model_config = ConfigDict(populate_by_name=True)

    items: list[T]
    total: int
    page: int
    page_size: int = Field(alias="size")
    total_pages: int = Field(alias="pages")


class PaginationParams(BaseModel):
    """Query parameters for pagination."""

    page: int = 1
    page_size: int = 50
