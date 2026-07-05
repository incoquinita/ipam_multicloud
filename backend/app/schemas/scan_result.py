"""Pydantic schemas for scan results — port results, HTTP analyses, and summary.

These schemas form the response contract for the scan results endpoint
(Phase 3.x). They map from the ``PortResult`` and ``HttpAnalysis`` ORM
models via ``from_attributes``.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.schemas.scan_job import ScanStatusResponse


class PortResultResponse(BaseModel):
    """Single port scan result."""

    id: UUID
    scan_job_id: UUID
    ip_address_id: UUID | None = None
    port: int
    protocol: str
    state: str
    service_name: str | None = None
    service_product: str | None = None
    service_version: str | None = None
    banner: str | None = None
    risk_level: str | None = None
    risk_score: float | None = None
    cve_ids: list[str] | None = None
    scanned_at: datetime

    model_config = ConfigDict(from_attributes=True)


class HttpAnalysisResponse(BaseModel):
    """Single HTTP/HTTPS analysis result."""

    id: UUID
    scan_job_id: UUID
    ip_address_id: UUID | None = None
    port: int
    url: str | None = None
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

    model_config = ConfigDict(from_attributes=True)


class ScanResultsSummary(BaseModel):
    """Aggregate counts for a scan's results."""

    total_ports: int
    open_ports: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    http_analyzed: int
    static_sites: int
    login_sites: int
    rate_limited_sites: int


class ScanResultsResponse(BaseModel):
    """Full scan results bundle — status, port results, HTTP analyses, summary."""

    scan_job: ScanStatusResponse
    port_results: list[PortResultResponse]
    http_analyses: list[HttpAnalysisResponse]
    summary: ScanResultsSummary

    model_config = ConfigDict(from_attributes=True)
