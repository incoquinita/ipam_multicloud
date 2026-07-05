"""HttpAnalysisResponse schema unit tests.

The response schema was previously uncovered because the scan-results
bundle serialises HTTP analyses inline. These tests validate it directly
via ``model_validate`` so the ``from_attributes`` config is exercised.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from app.models.http_analysis import HttpAnalysis
from app.schemas.http_analysis import HttpAnalysisResponse


def _make_analysis() -> HttpAnalysis:
    """Build an HttpAnalysis ORM instance with representative fields."""
    return HttpAnalysis(
        id=uuid4(),
        scan_job_id=uuid4(),
        ip_address_id=uuid4(),
        port=80,
        url="http://10.0.0.1:80",
        status_code=200,
        is_static=False,
        has_login=True,
        has_rate_limit=False,
        response_headers={"server": "nginx"},
        technologies=["nginx", "php"],
        security_headers_score=8,
        tls_version="TLSv1.3",
        title="Welcome",
        analyzed_at=datetime.now(timezone.utc),
    )


def test_http_analysis_response_validates_from_orm() -> None:
    """HttpAnalysisResponse.model_validate maps every ORM field."""
    analysis = _make_analysis()
    response = HttpAnalysisResponse.model_validate(analysis)

    assert response.port == 80
    assert response.url == "http://10.0.0.1:80"
    assert response.status_code == 200
    assert response.has_login is True
    assert response.technologies == ["nginx", "php"]
    assert response.tls_version == "TLSv1.3"
    assert response.title == "Welcome"


def test_http_analysis_response_defaults_optional_fields() -> None:
    """Optional fields default to None when the ORM leaves them unset."""
    analysis = HttpAnalysis(
        id=uuid4(),
        scan_job_id=uuid4(),
        ip_address_id=uuid4(),
        port=443,
        url="https://10.0.0.1",
        analyzed_at=datetime.now(timezone.utc),
    )
    response = HttpAnalysisResponse.model_validate(analysis)

    assert response.status_code is None
    assert response.is_static is None
    assert response.has_login is None
    assert response.technologies is None
    assert response.security_headers_score is None
