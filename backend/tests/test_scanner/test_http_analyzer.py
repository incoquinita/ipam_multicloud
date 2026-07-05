"""Unit tests for the HTTP/HTTPS service analyzer.

Exercises ``HttpAnalyzer`` detection methods in isolation by mocking
``httpx.AsyncClient``.  No real network connections are made.

Covered methods:
- ``_check_is_static`` — static vs. dynamic site classification
- ``_check_has_login`` — login-page signal detection
- ``_probe_rate_limit`` — rate-limit header / status / latency detection
- ``_analyze_security_headers`` — header presence scoring (0–10)
- ``_detect_technologies`` — server / powered-by / cookie fingerprinting
- ``_extract_title`` — ``<title>`` tag extraction
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import AsyncMock

import httpx
import pytest

from app.scanner.http_analyzer import HttpAnalyzer

# ── Fixture override ──────────────────────────────────────────────
# Pure unit tests — the shared ``tests/test_scanner/conftest.py`` already
# neutralises the root ``setup_database`` fixture, so no DB is touched.


# ── Helpers ───────────────────────────────────────────────────────


def build_response(
    status_code: int = 200,
    *,
    headers: dict[str, str] | None = None,
    text: str = "",
    url: str = "http://test/",
    elapsed_seconds: float = 0.0,
) -> httpx.Response:
    """Construct a fully-populated ``httpx.Response`` for test mocks.

    Sets ``elapsed`` directly (the attribute is normally populated by
    the transport layer after a real request) so ``_probe_rate_limit``
    can read ``response.elapsed.total_seconds()``.
    """
    response = httpx.Response(
        status_code,
        headers=headers or {},
        text=text,
        request=httpx.Request("GET", url),
    )
    response._elapsed = timedelta(seconds=elapsed_seconds)  # noqa: SLF001
    return response


def mock_client(responses: list[httpx.Response]) -> AsyncMock:
    """Return an ``AsyncMock`` simulating ``httpx.AsyncClient.get``.

    ``responses`` are consumed in order across successive ``.get()``
    calls.  This mirrors how the analyzer issues sequential probes.
    """
    client = AsyncMock()
    client.get = AsyncMock(side_effect=responses)
    return client


# ── _check_is_static ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_check_is_static_returns_true_when_all_signals_4xx() -> None:
    """A site that 4xx on every dynamic endpoint probe is classified static."""
    analyzer = HttpAnalyzer()
    # One 4xx response per signal path — the analyzer probes each path.
    responses = [build_response(404, url=f"http://test{path}") for path in analyzer.SIGNALS]
    client = mock_client(responses)

    is_static, evidence = await analyzer._check_is_static(client, "test", 80, "http")

    assert is_static is True
    assert len(evidence) == len(analyzer.SIGNALS)
    assert all(entry.endswith(":404") for entry in evidence)


@pytest.mark.asyncio
async def test_check_is_static_returns_false_when_api_endpoint_responds_200() -> None:
    """A 200 on ``/api/`` proves the site is dynamic (not static)."""
    analyzer = HttpAnalyzer()
    responses: list[httpx.Response] = []
    for path in analyzer.SIGNALS:
        status = 200 if path == "/api/" else 404
        responses.append(build_response(status, url=f"http://test{path}"))
    client = mock_client(responses)

    is_static, evidence = await analyzer._check_is_static(client, "test", 80, "http")

    assert is_static is False
    assert "/api/:200" in evidence


@pytest.mark.asyncio
async def test_check_is_static_treats_request_errors_as_static_evidence() -> None:
    """Connection errors on every probe are recorded as ``:error`` and yield static."""
    analyzer = HttpAnalyzer()
    client = AsyncMock()
    client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))

    is_static, evidence = await analyzer._check_is_static(client, "test", 80, "http")

    assert is_static is True
    assert all(entry.endswith(":error") for entry in evidence)


# ── _check_has_login ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_check_has_login_detects_password_input_field() -> None:
    """HTML with a ``type="password"`` input triggers login detection."""
    analyzer = HttpAnalyzer()
    response = build_response(
        200,
        text='<form><input type="password" name="pw"></form>',
        url="http://test/",
    )

    has_login, evidence = await analyzer._check_has_login(response)

    assert has_login is True
    assert "password_input_field_found" in evidence


@pytest.mark.asyncio
async def test_check_has_login_returns_false_when_no_signals_present() -> None:
    """A plain page with no auth signals returns ``has_login=False``."""
    analyzer = HttpAnalyzer()
    response = build_response(
        200,
        text="<html><body><h1>Welcome</h1></body></html>",
        url="http://test/about",
    )

    has_login, evidence = await analyzer._check_has_login(response)

    assert has_login is False
    assert evidence == []


@pytest.mark.asyncio
async def test_check_has_login_flags_401_status_as_auth_required() -> None:
    """An HTTP 401 response is evidence of an auth-gated resource."""
    analyzer = HttpAnalyzer()
    response = build_response(401, text="Unauthorized", url="http://test/secret")

    has_login, evidence = await analyzer._check_has_login(response)

    assert has_login is True
    assert any("auth_required_status:401" in e for e in evidence)


@pytest.mark.asyncio
async def test_check_has_login_detects_auth_url_path() -> None:
    """A URL path starting with ``/login`` is treated as an auth path."""
    analyzer = HttpAnalyzer()
    response = build_response(200, text="", url="http://test/login")

    has_login, evidence = await analyzer._check_has_login(response)

    assert has_login is True
    assert "auth_url_path_detected" in evidence


# ── _probe_rate_limit ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_probe_rate_limit_detects_http_429() -> None:
    """A 429 response sets ``rate_limited=True`` with type ``http_429``."""
    analyzer = HttpAnalyzer()
    responses = [build_response(429, url="http://test/") for _ in range(analyzer.BURST_COUNT)]
    client = mock_client(responses)

    result = await analyzer._probe_rate_limit(client, "http://test/")

    assert result["rate_limited"] is True
    assert result["rate_limit_type"] == "http_429"
    assert 429 in result["status_codes"]


@pytest.mark.asyncio
async def test_probe_rate_limit_captures_x_ratelimit_headers() -> None:
    """Rate-limit headers (``X-Rate-Limit-*``, ``Retry-After``) are collected.

    The detector matches the substring ``"rate-limit"`` (hyphenated) on
    the lowercased header name, so ``X-Rate-Limit-Remaining`` and
    ``Retry-After`` are captured into ``headers_found``.
    """
    analyzer = HttpAnalyzer()
    responses = [
        build_response(
            200,
            headers={
                "X-Rate-Limit-Limit": "100",
                "X-Rate-Limit-Remaining": "0",
                "Retry-After": "60",
            },
            url="http://test/",
        )
        for _ in range(analyzer.BURST_COUNT)
    ]
    client = mock_client(responses)

    result = await analyzer._probe_rate_limit(client, "http://test/")

    assert "x-rate-limit-limit" in result["headers_found"]
    assert "x-rate-limit-remaining" in result["headers_found"]
    assert result["headers_found"]["x-rate-limit-remaining"] == "0"
    assert result["headers_found"]["retry_after"] == "60"


@pytest.mark.asyncio
async def test_probe_rate_limit_returns_clean_when_no_signals() -> None:
    """Plain 200 responses with no rate-limit headers report no limiting."""
    analyzer = HttpAnalyzer()
    responses = [
        build_response(200, text="<html>ok</html>", url="http://test/")
        for _ in range(analyzer.BURST_COUNT)
    ]
    client = mock_client(responses)

    result = await analyzer._probe_rate_limit(client, "http://test/")

    assert result["rate_limited"] is False
    assert result["headers_found"] == {}
    assert len(result["status_codes"]) == analyzer.BURST_COUNT


# ── _analyze_security_headers ─────────────────────────────────────


def test_analyze_security_headers_scores_zero_when_none_present() -> None:
    """No security headers → score 0."""
    analyzer = HttpAnalyzer()
    result = analyzer._analyze_security_headers({"content-type": "text/html"})

    assert result["score"] == 0
    assert result["headers"] == {}


def test_analyze_security_headers_scores_max_when_all_present() -> None:
    """Every tracked security header present → score 10."""
    analyzer = HttpAnalyzer()
    headers = dict.fromkeys(analyzer.SECURITY_HEADERS, "value")
    result = analyzer._analyze_security_headers(headers)

    assert result["score"] == 10
    assert len(result["headers"]) == len(analyzer.SECURITY_HEADERS)


def test_analyze_security_headers_weights_csp_above_xfo() -> None:
    """CSP (weight 3) alone scores higher than XFO (weight 1) alone."""
    analyzer = HttpAnalyzer()
    max_score = sum(info["weight"] for info in analyzer.SECURITY_HEADERS.values())

    csp_only = analyzer._analyze_security_headers({"content-security-policy": "default-src 'self'"})
    xfo_only = analyzer._analyze_security_headers({"x-frame-options": "DENY"})

    assert csp_only["score"] > xfo_only["score"]
    # Sanity-check the normalised math: round(3 / max * 10) > round(1 / max * 10).
    assert csp_only["score"] == round(3 / max_score * 10)
    assert xfo_only["score"] == round(1 / max_score * 10)


# ── _detect_technologies ──────────────────────────────────────────


def test_detect_technologies_identifies_nginx_server_header() -> None:
    """A ``Server: nginx`` header is surfaced as ``Server:nginx`` and ``nginx``."""
    analyzer = HttpAnalyzer()
    response = build_response(200, headers={"Server": "nginx/1.25"}, url="http://test/")

    detected = analyzer._detect_technologies(response)

    assert "Server:nginx/1.25" in detected
    assert "nginx" in detected


def test_detect_technologies_identifies_express_session_cookie() -> None:
    """A ``connect.sid`` cookie is fingerprinted as an Express session."""
    analyzer = HttpAnalyzer()
    response = build_response(
        200,
        headers={"Set-Cookie": "connect.sid=s%3Aabc; Path=/"},
        url="http://test/",
    )

    detected = analyzer._detect_technologies(response)

    assert "ExpressSession" in detected


def test_detect_technologies_returns_empty_for_generic_headers() -> None:
    """Headers with no fingerprint match return only the raw ``Server`` tag."""
    analyzer = HttpAnalyzer()
    response = build_response(
        200,
        headers={"Server": "custom-ware"},
        url="http://test/",
    )

    detected = analyzer._detect_technologies(response)

    assert detected == ["Server:custom-ware"]


# ── _extract_title ────────────────────────────────────────────────


def test_extract_title_returns_tag_content() -> None:
    """The ``<title>`` text is returned trimmed."""
    html = "<html><head><title>  Dashboard  </title></head>"
    assert HttpAnalyzer._extract_title(html) == "Dashboard"


def test_extract_title_returns_none_when_no_title_tag() -> None:
    """Missing ``<title>`` → ``None``."""
    assert HttpAnalyzer._extract_title("<html><body>no title</body></html>") is None


def test_extract_title_truncates_excessively_long_titles() -> None:
    """Titles longer than 512 characters are truncated."""
    long_title = "A" * 600
    html = f"<title>{long_title}</title>"
    result = HttpAnalyzer._extract_title(html)
    assert result is not None
    assert len(result) == 512


# ── Constructor / behaviour ───────────────────────────────────────


def test_http_analyzer_exposes_signal_and_header_constants() -> None:
    """The analyzer ships non-empty detection constants for callers to inspect."""
    analyzer = HttpAnalyzer()
    assert analyzer.SIGNALS  # non-empty
    assert analyzer.SECURITY_HEADERS  # non-empty
    assert analyzer.BURST_COUNT > 0
