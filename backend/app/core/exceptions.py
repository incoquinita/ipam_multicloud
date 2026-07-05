"""Custom exception hierarchy and FastAPI exception handlers.

All HTTP-visible exceptions inherit from ``AppException`` which carries
a structured ``detail`` payload and a machine-readable ``code``.  Every
error response shares the same JSON shape::

    {"detail": "<human-readable message>", "code": "<machine code>"}

Unhandled exceptions are caught by a final 500 handler that never leaks
internals.
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError


class AppException(Exception):  # noqa: N818 - intentional "Exception" suffix
    """Base application exception with structured error payload.

    Parameters
    ----------
    status_code : int
        HTTP status code to return.
    detail : str
        Human-readable error description.
    code : str | None
        Machine-readable error code for client-side logic.
    """

    def __init__(
        self,
        status_code: int = 500,
        detail: str = "Internal server error",
        code: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.detail = detail
        self.code = code
        super().__init__(self.detail)


class NotFoundException(AppException):
    """Raised when a requested resource does not exist."""

    def __init__(self, detail: str = "Resource not found", code: str = "not_found") -> None:
        super().__init__(status_code=404, detail=detail, code=code)


class BadRequestException(AppException):
    """Raised when the request payload is invalid."""

    def __init__(self, detail: str = "Bad request", code: str = "bad_request") -> None:
        super().__init__(status_code=400, detail=detail, code=code)


class ValidationException(AppException):
    """Raised when input fails semantic validation or a constraint is violated."""

    def __init__(self, detail: str = "Validation error", code: str = "validation_error") -> None:
        super().__init__(status_code=422, detail=detail, code=code)


class UnauthorizedException(AppException):
    """Raised when authentication is missing or invalid."""

    def __init__(self, detail: str = "Not authenticated", code: str = "unauthorized") -> None:
        super().__init__(status_code=401, detail=detail, code=code)


class ForbiddenException(AppException):
    """Raised when the authenticated user lacks required permissions."""

    def __init__(self, detail: str = "Forbidden", code: str = "forbidden") -> None:
        super().__init__(status_code=403, detail=detail, code=code)


class ConflictException(AppException):
    """Raised when the request conflicts with the current state."""

    def __init__(self, detail: str = "Conflict", code: str = "conflict") -> None:
        super().__init__(status_code=409, detail=detail, code=code)


class CloudProviderException(AppException):
    """Raised when a cloud provider API call fails or returns an error.

    Maps to HTTP 502 (Bad Gateway) because the failure originates
    upstream — the API could not complete the request because a cloud
    provider was unreachable or returned an error.
    """

    def __init__(
        self, detail: str = "Cloud provider error", code: str = "cloud_provider_error",
    ) -> None:
        super().__init__(status_code=502, detail=detail, code=code)


def _error_payload(detail: str, code: str | None) -> dict[str, object]:
    """Build a consistent error JSON body, always including a code."""
    return {"detail": detail, "code": code or "internal_error"}


async def _app_exception_handler(_request: Request, exc: AppException) -> JSONResponse:
    """Handle known ``AppException`` subclasses with a consistent body."""
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_payload(exc.detail, exc.code),
    )


async def _integrity_error_handler(
    _request: Request, _exc: IntegrityError,
) -> JSONResponse:
    """Map SQLAlchemy integrity violations to 422 with a stable body."""
    return JSONResponse(
        status_code=422,
        content=_error_payload(
            "Database integrity constraint violated", "integrity_error",
        ),
    )


async def _unhandled_exception_handler(
    _request: Request, _exc: Exception,
) -> JSONResponse:
    """Catch-all for unexpected errors — never leaks internals."""
    return JSONResponse(
        status_code=500,
        content=_error_payload("An unexpected error occurred", "internal_error"),
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register all custom exception handlers on a FastAPI instance.

    Must be called during application startup (inside ``create_app``).
    """
    app.add_exception_handler(AppException, _app_exception_handler)  # type: ignore[type-abstract]
    app.add_exception_handler(IntegrityError, _integrity_error_handler)  # type: ignore[type-abstract]
    app.add_exception_handler(Exception, _unhandled_exception_handler)  # type: ignore[type-abstract]
