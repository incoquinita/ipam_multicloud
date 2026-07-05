"""Rate-limiting middleware using slowapi.

Wraps the standard ``Limiter`` as a FastAPI middleware so that every
route is protected by a global default limit.  Per-route limits can be
applied via decorators from :mod:`slowapi`.
"""

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.config import get_settings

settings = get_settings()

rate_limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.GLOBAL_RATE_LIMIT],
    enabled=not settings.DEBUG,
)


def configure_rate_limiter(app: "FastAPI") -> None:  # noqa: F821
    """Register the rate limiter and its error handler on *app*."""
    app.state.limiter = rate_limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
