"""HTTP/HTTPS service analyzer.

Performs non-invasive HTTP requests to an open port and analyses
response headers, status codes, TLS certificates, technology
fingerprints, login forms, rate-limiting, and security headers.
"""

from __future__ import annotations

import asyncio
import re
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx


@dataclass
class HttpAnalysisResult:
    """Result of analysing an HTTP service on a single port."""

    url: str
    status_code: int | None = None
    is_static: bool | None = None
    static_evidence: list[str] = field(default_factory=list)
    has_login: bool | None = None
    login_evidence: list[str] = field(default_factory=list)
    has_rate_limit: bool | None = None
    rate_limit_details: dict[str, Any] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    security_headers: dict[str, str] = field(default_factory=dict)
    security_headers_score: int = 0
    technologies: list[str] = field(default_factory=list)
    certificates: dict[str, Any] = field(default_factory=dict)
    tls_version: str | None = None
    title: str | None = None


class HttpAnalyzer:
    """Non-invasive HTTP service analyser.

    Parameters
    ----------
    timeout : float
        Request timeout in seconds (default 10.0).
    follow_redirects : bool
        Whether to follow redirects (default False — security).
    """

    # ── Static-site detection signal paths ─────────────────────────
    SIGNALS: list[str] = [
        "/api/",
        "/api/v1/",
        "/graphql",
        "/wp-admin",
        "/admin",
        "/login",
        "/wp-login.php",
        "/administrator",
        "/.env",
        "/_debug/",
        "/api/health",
        "/rest/",
        "/v1/",
        "/api/users",
        "/wp-json/",
        "/sitemap.xml",
    ]

    # ── Security headers tracked for scoring ───────────────────────
    SECURITY_HEADERS: dict[str, dict[str, Any]] = {
        "content-security-policy": {"name": "CSP", "weight": 3},
        "strict-transport-security": {"name": "HSTS", "weight": 2},
        "x-frame-options": {"name": "XFO", "weight": 1},
        "x-content-type-options": {"name": "XCTO", "weight": 1},
        "referrer-policy": {"name": "Referrer-Policy", "weight": 1},
        "permissions-policy": {"name": "Permissions-Policy", "weight": 1},
        "x-xss-protection": {"name": "X-XSS", "weight": 1},
    }

    # ── Technology fingerprint patterns ────────────────────────────
    TECH_PATTERNS: dict[str, list[tuple[str, str | None]]] = {
        "nginx": [("server", "nginx")],
        "Apache": [("server", "apache")],
        "IIS": [("server", "iis"), ("server", "microsoft-iis")],
        "Cloudflare": [("server", "cloudflare")],
        "Node.js/Express": [("x-powered-by", "express")],
        "Python/Django": [("server", "wsgi"), ("x-powered-by", "django")],
        "Python/Flask": [("server", "werkzeug")],
        "Python/FastAPI": [("server", "uvicorn"), ("server", "starlette")],
        "Ruby/Rails": [("server", "phusion"), ("x-powered-by", "rails")],
        "Java/Tomcat": [("server", "tomcat"), ("server", "coyote")],
        "Java/Spring": [("x-application-context", None)],
        "PHP": [("x-powered-by", "php"), ("server", "php")],
        "WordPress": [("x-powered-by", "wordpress")],
        "Next.js": [("x-powered-by", "next.js")],
        "React": [("x-powered-by", "react")],
        "Vue.js": [("x-powered-by", "vue")],
    }

    BURST_COUNT: int = 10

    def __init__(self, timeout: float = 10.0, follow_redirects: bool = False) -> None:
        self._timeout = timeout
        self._follow_redirects = follow_redirects

    # ── Public API ─────────────────────────────────────────────────

    async def analyze(self, host: str, port: int) -> HttpAnalysisResult:
        """Analyse an HTTP(S) service at ``host:port``.

        Tries HTTPS first, falls back to HTTP.  Returns an
        ``HttpAnalysisResult`` with available metadata.
        """
        schemes = ["https", "http"]
        for scheme in schemes:
            url = f"{scheme}://{host}:{port}"
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout,
                    follow_redirects=self._follow_redirects,
                    verify=False,  # Accept self-signed certs for discovery.
                ) as client:
                    response = await client.get(url)

                    # ── Fire concurrent detection probes ───────────
                    coros: list[Any] = [
                        self._check_is_static(client, host, port, scheme),
                        self._check_has_login(response),
                        self._probe_rate_limit(client, url),
                    ]
                    if scheme == "https":
                        coros.append(self._extract_tls_info(host, port))

                    results = await asyncio.gather(*coros)

                    # ── Unpack results ─────────────────────────────
                    is_static, static_evidence = results[0]
                    has_login, login_evidence = results[1]
                    rate_limit_details = results[2]

                    if scheme == "https":
                        cert_info, tls_version = results[3]
                    else:
                        cert_info, tls_version = {}, None

                    # ── Synchronous detection ──────────────────────
                    technologies = self._detect_technologies(response)
                    sec_headers = self._analyze_security_headers(
                        dict(response.headers),
                    )
                    title = self._extract_title(response.text)

                return HttpAnalysisResult(
                    url=url,
                    status_code=response.status_code,
                    response_headers=dict(response.headers),
                    is_static=is_static,
                    static_evidence=static_evidence,
                    has_login=has_login,
                    login_evidence=login_evidence,
                    has_rate_limit=rate_limit_details.get("rate_limited", False),
                    rate_limit_details=rate_limit_details,
                    security_headers=sec_headers["headers"],
                    security_headers_score=sec_headers["score"],
                    technologies=technologies,
                    certificates=cert_info,
                    tls_version=tls_version,
                    title=title,
                )
            except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
                continue

        # Neither HTTP nor HTTPS succeeded.
        return HttpAnalysisResult(url=f"{host}:{port}")

    # ── Static-site detection ──────────────────────────────────────

    async def _check_is_static(
        self,
        client: httpx.AsyncClient,
        host: str,
        port: int,
        scheme: str,
    ) -> tuple[bool, list[str]]:
        """Multi-signal static site detection.

        Probes for dynamic endpoint patterns.  A truly static/empty
        web server will 404/4xx on all of them.

        Returns (is_static, evidence_list).
        """
        evidence: list[str] = []
        all_four_xx_or_error = True

        for path in self.SIGNALS:
            probe_url = f"{scheme}://{host}:{port}{path}"
            try:
                resp = await client.get(probe_url, follow_redirects=False)
                if resp.status_code < 400:
                    all_four_xx_or_error = False
                    evidence.append(f"{path}:{resp.status_code}")
                else:
                    evidence.append(f"{path}:{resp.status_code}")
            except Exception:  # noqa: BLE001
                evidence.append(f"{path}:error")

        return all_four_xx_or_error, evidence

    # ── Login-page detection ───────────────────────────────────────

    async def _check_has_login(
        self,
        response: httpx.Response,
    ) -> tuple[bool, list[str]]:
        """Multi-signal login page detection.

        Signals:
        1. Password input field in HTML
        2. Form action pointing to */login
        3. CAPTCHA widgets (reCAPTCHA, Turnstile, hCaptcha)
        4. Login-related keywords in body text
        5. HTTP 401/403 status codes
        6. Auth-related path segments in URL
        """
        evidence: list[str] = []
        body = response.text.lower()

        # Signal 1: Password field in form.
        if 'type="password"' in body or "type='password'" in body:
            evidence.append("password_input_field_found")

        # Signal 2: Login form action.
        if re.search(r'<form[^>]*action=["\']/[^"\']*login', body, re.IGNORECASE):
            evidence.append("login_form_action_detected")

        # Signal 3: CAPTCHA widgets.
        captcha_keywords = ["recaptcha", "turnstile", "hcaptcha", "g-recaptcha"]
        if any(kw in body for kw in captcha_keywords):
            evidence.append("captcha_detected")

        # Signal 4: Login-related keywords.
        login_keywords = {"password", "sign in", "login", "username", "email address"}
        found_keywords = [kw for kw in login_keywords if kw in body]
        if found_keywords:
            evidence.append(f"login_keywords:{','.join(found_keywords[:3])}")

        # Signal 5: HTTP status code indicates auth required.
        if response.status_code in (401, 403):
            evidence.append(f"auth_required_status:{response.status_code}")

        # Signal 6: Auth-related URL path.
        path = str(response.url.path).lower()
        auth_paths = ("/login", "/signin", "/auth", "/signup", "/register")
        if any(path.startswith(p) for p in auth_paths):
            evidence.append("auth_url_path_detected")

        return bool(evidence), evidence

    # ── Rate-limit detection ───────────────────────────────────────

    async def _probe_rate_limit(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> dict[str, Any]:
        """Multi-request burst probe to detect rate limiting.

        Sends BURST_COUNT requests in rapid succession, then analyses:
        1. Status code changes (200 -> 429 = rate limited)
        2. Response time degradation (latency increase = silent throttling)
        3. Retry-After headers
        4. X-RateLimit-* headers
        5. Body markers (\"rate limit\", \"too many requests\")
        """
        results: dict[str, Any] = {
            "rate_limited": False,
            "status_codes": [],
            "response_times": [],
            "headers_found": {},
        }

        for _ in range(self.BURST_COUNT):
            try:
                resp = await client.get(url)
                results["status_codes"].append(resp.status_code)
                results["response_times"].append(resp.elapsed.total_seconds())

                if resp.status_code == 429:
                    results["rate_limited"] = True
                    results["rate_limit_type"] = "http_429"

                # Check for rate-limit-related headers.
                for header_name, header_value in resp.headers.items():
                    hl = header_name.lower()
                    if "retry-after" in hl:
                        results["headers_found"]["retry_after"] = header_value
                    if "rate-limit" in hl:
                        results["headers_found"][header_name] = header_value

                # Body markers for soft rate-limiting.
                if resp.status_code == 200:
                    body_lower = resp.text.lower()
                    rate_limit_phrases = [
                        "rate limit",
                        "too many requests",
                        "slow down",
                        "try again later",
                    ]
                    for phrase in rate_limit_phrases:
                        if phrase in body_lower:
                            results["rate_limited"] = True
                            results["rate_limit_type"] = "body_marker"
                            results["rate_limit_marker"] = phrase
                            break

            except Exception:  # noqa: BLE001
                break

        # Detect silent rate limiting via latency degradation.
        rts = results["response_times"]
        if len(rts) >= 4:
            mid = len(rts) // 2
            avg_first = sum(rts[:mid]) / mid
            avg_last = sum(rts[mid:]) / (len(rts) - mid)
            if avg_last > avg_first * 3 and avg_first > 0.1:
                results["rate_limited"] = True
                results["rate_limit_type"] = "latency_degradation"

        return results

    # ── Security header analysis ───────────────────────────────────

    def _analyze_security_headers(
        self,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """Analyse which security headers are present and score them 0-10."""
        found: dict[str, str] = {}
        score = 0
        max_score = sum(info["weight"] for info in self.SECURITY_HEADERS.values())

        for h_name, h_info in self.SECURITY_HEADERS.items():
            for resp_h_name, resp_h_value in headers.items():
                if resp_h_name.lower() == h_name:
                    found[h_info["name"]] = resp_h_value
                    score += h_info["weight"]
                    break

        normalized = round((score / max_score) * 10) if max_score > 0 else 0
        return {"headers": found, "score": normalized}

    # ── Technology fingerprinting ──────────────────────────────────

    def _detect_technologies(self, response: httpx.Response) -> list[str]:
        """Detect technologies from response headers, cookies, and HTML."""
        detected: set[str] = set()
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        # Server header.
        server = headers_lower.get("server", "")
        if server:
            detected.add(f"Server:{server}")

        # x-powered-by header.
        powered_by = headers_lower.get("x-powered-by", "")
        if powered_by:
            detected.add(f"PoweredBy:{powered_by}")

        # Set-Cookie analysis.
        set_cookie = headers_lower.get("set-cookie", "")
        if "session" in set_cookie.lower():
            detected.add("SessionCookie")
        if "connect.sid" in set_cookie:
            detected.add("ExpressSession")

        # Technology pattern matching.
        for tech_name, patterns in self.TECH_PATTERNS.items():
            for header_name, expected_value in patterns:
                val = headers_lower.get(header_name, "")
                if expected_value is None:
                    if val:
                        detected.add(tech_name)
                        break
                elif expected_value.lower() in val.lower():
                    detected.add(tech_name)
                    break

        return sorted(detected)

    # ── TLS certificate extraction ─────────────────────────────────

    async def _extract_tls_info(
        self,
        host: str,
        port: int,
    ) -> tuple[dict[str, Any], str | None]:
        """Extract TLS certificate and version info via raw SSL connection.

        Creates a raw SSL connection to capture the peer certificate
        and negotiated TLS version.
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context),
                timeout=self._timeout,
            )
            _ = reader  # Not needed for cert extraction.

            transport = writer.transport
            ssl_object = transport.get_extra_info("ssl_object")

            cert_info: dict[str, Any] = {}
            tls_version: str | None = None

            if ssl_object is not None:
                tls_version = ssl_object.version()
                peer_cert = ssl_object.getpeercert()

                if peer_cert:
                    subject = peer_cert.get("subject", [])
                    if subject:
                        cert_info["subject"] = dict(subject)

                    issuer = peer_cert.get("issuer", [])
                    if issuer:
                        cert_info["issuer"] = dict(issuer)

                    cert_info["notBefore"] = peer_cert.get("notBefore", "")
                    cert_info["notAfter"] = peer_cert.get("notAfter", "")
                    cert_info["serialNumber"] = peer_cert.get("serialNumber", "")

                    san = peer_cert.get("subjectAltName", [])
                    if san:
                        cert_info["subjectAltName"] = [f"{t}:{v}" for t, v in san]

                    not_after = peer_cert.get("notAfter", "")
                    if not_after:
                        try:
                            expiry = datetime.strptime(
                                not_after,
                                "%b %d %H:%M:%S %Y %Z",
                            )
                            days_left = (expiry - datetime.utcnow()).days
                            cert_info["days_until_expiry"] = days_left
                        except ValueError:
                            pass

            writer.close()
            await writer.wait_closed()
            return cert_info, tls_version

        except (TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError) as exc:
            return {"error": str(exc)[:200]}, None

    # ── HTML title extraction ──────────────────────────────────────

    @staticmethod
    def _extract_title(body: str) -> str | None:
        """Extract the ``<title>`` tag content from HTML body."""
        match = re.search(
            r"<title[^>]*>(.*?)</title>",
            body,
            re.IGNORECASE | re.DOTALL,
        )
        if match:
            title = match.group(1).strip()
            return title[:512] if title else None
        return None
