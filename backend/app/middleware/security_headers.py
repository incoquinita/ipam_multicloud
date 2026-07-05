"""ASGI middleware that injects security-related HTTP response headers.

Enforces HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and
Referrer-Policy on every response.  Helps satisfy OWASP ASVS
requirements at the platform layer.
"""

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add hardened security headers to every HTTP response.

    Headers set
    -----------
    - ``Strict-Transport-Security`` (2-year max-age, include subdomains)
    - ``X-Content-Type-Options`` (nosniff)
    - ``X-Frame-Options`` (DENY)
    - ``Referrer-Policy`` (strict-origin-when-cross-origin)
    - ``Content-Security-Policy`` (restrictive default)
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self'"
        )
        return response
