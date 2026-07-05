"""Pydantic schemas for port result listing and filtering.

``PortResultListResponse`` wraps paginated ``PortResultResponse`` items
(imported from ``scan_result``), and ``PortResultFilter`` defines the
query parameters accepted by the port-results listing endpoint.
"""

from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.scan_result import PortResultResponse


class PortResultListResponse(BaseModel):
    """Paginated list of port results."""

    items: list[PortResultResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class PortResultFilter(BaseModel):
    """Query parameters for filtering port results."""

    port: int | None = Field(None, description="Filter by port number")
    risk_level: str | None = Field(
        None, description="Filter by risk level (critical, high, medium, low, info)",
    )
    scan_job_id: UUID | None = Field(None, description="Filter by scan job ID")
    state: str | None = Field(
        None, description="Filter by port state (open, closed, filtered, unfiltered)",
    )
