"""ASGI middleware that attaches a unique request ID to every request.

The ID is read from the ``X-Request-ID`` header if present, otherwise
a new UUIDv4 is generated.  The value is injected into structlog's
context vars for traceability across log lines.
"""

from collections.abc import Awaitable, Callable
from uuid import uuid4

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attach a unique request ID and log context per request.

    The ID is returned in the ``X-Request-ID`` response header so
    callers can correlate server-side logs with client requests.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid4()))

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
