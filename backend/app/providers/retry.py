"""Retry with exponential backoff and a per-provider circuit breaker.

Uses monotonic time for all time measurements to prevent wall-clock
manipulation from affecting the circuit-breaker state.
"""

import asyncio
import functools
import logging
import time
from collections.abc import Callable
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


# ── Retry with exponential backoff ────────────────────────────────


async def retry_with_backoff(
    func: Callable[..., Any],
    max_retries: int = 3,
    base_delay: float = 1.0,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Execute *func* with up to *max_retries* attempts and exponential backoff.

    Delays between retries: 1 s, 2 s, 4 s (when *base_delay* == 1.0).
    All exceptions are treated as retryable.

    Parameters
    ----------
    func : Callable
        The async function to retry.
    max_retries : int
        Maximum number of retry attempts.
    base_delay : float
        Base delay in seconds (doubled each retry).
    """
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries:
                delay = base_delay * (2**attempt)
                logger.warning(
                    "Retry %d/%d for %s after %.1f s: %s",
                    attempt + 1,
                    max_retries,
                    func.__name__,
                    delay,
                    exc,
                )
                await asyncio.sleep(delay)
    raise last_exc  # type: ignore[misc]


def retryable(max_retries: int = 3, base_delay: float = 1.0) -> Callable[[F], F]:
    """Decorator that wraps an async function with :func:`retry_with_backoff`.

    Usage::

        @retryable(max_retries=3, base_delay=1.0)
        async def fetch_data():
            ...
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # We intentionally pass *args and **kwargs as positional
            # after keyword arguments to forward them to the wrapped func.
            return await retry_with_backoff(
                func, max_retries, base_delay, *args, **kwargs,
            )
        return wrapper  # type: ignore[return-value]
    return decorator


# ── Circuit breaker ──────────────────────────────────────────────


class CircuitBreakerState:
    """Enum-like constants for circuit-breaker states."""
    CLOSED = "closed"          # Normal operation — requests pass through.
    OPEN = "open"              # Failing fast — requests are rejected.
    HALF_OPEN = "half_open"    # Testing — a single probe request is allowed.


class CloudCircuitBreaker:
    """Per-provider circuit breaker.

    Protects the downstream cloud provider API from being hammered when
    it is unhealthy.  Uses ``time.monotonic()`` for all time measurements.

    Parameters
    ----------
    provider_name : str
        Human-readable name used in log messages.
    failure_threshold : int
        Number of consecutive failures before the circuit opens.
    recovery_timeout : float
        Seconds to wait in OPEN state before transitioning to HALF_OPEN.
    """

    def __init__(
        self,
        provider_name: str = "unknown",
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
    ) -> None:
        self.provider_name = provider_name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout

        self._state: str = CircuitBreakerState.CLOSED
        self._failure_count: int = 0
        self._last_failure_time: float = 0.0

    # ── Public API ────────────────────────────────────────────────

    @property
    def state(self) -> str:
        """Return the current circuit-breaker state."""
        return self._state

    def record_success(self) -> None:
        """Record a successful call — resets the failure count.

        If the circuit was HALF_OPEN it transitions back to CLOSED.
        """
        self._failure_count = 0
        if self._state == CircuitBreakerState.HALF_OPEN:
            logger.info("Circuit breaker '%s' closed after successful probe.", self.provider_name)
            self._state = CircuitBreakerState.CLOSED

    def record_failure(self) -> None:
        """Record a failed call.

        Increments the failure counter.  If threshold is reached the
        circuit transitions to OPEN.
        """
        self._failure_count += 1
        self._last_failure_time = time.monotonic()

        if self._failure_count >= self.failure_threshold:
            logger.warning(
                "Circuit breaker '%s' OPEN after %d consecutive failures.",
                self.provider_name,
                self._failure_count,
            )
            self._state = CircuitBreakerState.OPEN

    def is_open(self) -> bool:
        """Check whether the circuit is currently open (failing fast).

        If the recovery timeout has elapsed while OPEN, automatically
        transitions to HALF_OPEN and returns ``False`` so the next
        call is allowed through as a probe.
        """
        if self._state != CircuitBreakerState.OPEN:
            return False

        elapsed = time.monotonic() - self._last_failure_time
        if elapsed >= self.recovery_timeout:
            logger.info(
                "Circuit breaker '%s' HALF_OPEN after %.1f s recovery.",
                self.provider_name,
                elapsed,
            )
            self._state = CircuitBreakerState.HALF_OPEN
            return False

        return True

    def attempt_reset(self) -> bool:
        """Manually attempt to reset the circuit breaker.

        This is useful after credentials have been refreshed or an
        external dependency has been restored.  Returns ``True`` if the
        circuit was actually reset.
        """
        was_open = self._state != CircuitBreakerState.CLOSED
        self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0
        if was_open:
            logger.info("Circuit breaker '%s' manually reset to CLOSED.", self.provider_name)
        return was_open

    def __repr__(self) -> str:
        return (
            f"<CloudCircuitBreaker '{self.provider_name}' "
            f"state={self._state} failures={self._failure_count}>"
        )
