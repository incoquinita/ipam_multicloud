"""Pydantic schemas for HTTP/HTTPS analysis results."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel


class HttpAnalysisResponse(BaseModel):
    """Single HTTP analysis result."""

    id: UUID
    scan_job_id: UUID
    ip_address_id: UUID
    port: int
    url: str
    status_code: int | None = None
    is_static: bool | None = None
    has_login: bool | None = None
    has_rate_limit: bool | None = None
    response_headers: dict[str, Any] | None = None
    technologies: list[str] | None = None
    certificates: dict[str, Any] | None = None
    security_headers: dict[str, Any] | None = None
    security_headers_score: int | None = None
    tls_version: str | None = None
    title: str | None = None
    static_evidence: list[str] | None = None
    login_evidence: list[str] | None = None
    rate_limit_details: dict[str, Any] | None = None
    analyzed_at: datetime

    model_config = {"from_attributes": True}
