"""Discovery API endpoint — dispatches async cloud discovery via Celery.

The endpoint is non-blocking: ``POST /discovery/run`` enqueues a Celery
task and returns the job id immediately.  Clients poll
``GET /discovery/status/{job_id}`` for progress and the final summary.
"""

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter
from pydantic import BaseModel

from app.workers.celery_app import get_task_status
from app.workers.discovery_tasks import run_cloud_discovery

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/discovery", tags=["Discovery"])


# ── Request / response schemas ──────────────────────────────────────


class DiscoveryRunRequest(BaseModel):
    """Request body for dispatching a discovery run."""

    provider_id: UUID


class DiscoveryRunResponse(BaseModel):
    """Response returned immediately after dispatching a discovery run."""

    job_id: str
    status: str


class DiscoveryResultSummary(BaseModel):
    """Summary of a completed discovery run (returned by the Celery task)."""

    ips_discovered: int = 0
    security_rules_found: int = 0
    load_balancers_found: int = 0
    errors: list[str] = []


class DiscoveryStatusResponse(BaseModel):
    """Status of a dispatched discovery job.

    ``status`` is the raw Celery state: ``PENDING``, ``STARTED``,
    ``SUCCESS``, or ``FAILURE``.  ``result`` is populated only when the
    task succeeds; ``error`` is populated only when it fails.
    """

    job_id: str
    status: str
    ready: bool
    successful: bool | None = None
    result: DiscoveryResultSummary | None = None
    error: str | None = None


class LegacyDiscoveryStatusResponse(BaseModel):
    """Deprecated response for the legacy ``GET /discovery/status`` endpoint.

    Retained for backward compatibility — always returns ``has_run=False``
    since the in-memory result store was removed when discovery moved to
    Celery.  Use :class:`DiscoveryStatusResponse` via
    ``GET /discovery/status/{job_id}`` instead.
    """

    has_run: bool
    result: dict[str, Any] | None = None
    message: str | None = None


# ── Endpoints ───────────────────────────────────────────────────────


@router.post("/run", response_model=DiscoveryRunResponse)
async def run_discovery(
    data: DiscoveryRunRequest,
) -> DiscoveryRunResponse:
    """Dispatch a cloud discovery job for the given provider.

    Returns immediately with the Celery task id; the actual discovery
    runs asynchronously in a Celery worker on the ``discovery`` queue.
    Poll ``GET /discovery/status/{job_id}`` for progress.
    """
    task = run_cloud_discovery.delay(str(data.provider_id))
    return DiscoveryRunResponse(
        job_id=task.id,
        status="pending",
    )


@router.get("/status/{job_id}", response_model=DiscoveryStatusResponse)
async def get_discovery_status(
    job_id: str,
) -> DiscoveryStatusResponse:
    """Return the status of a dispatched discovery job.

    Reads the Celery ``AsyncResult`` for *job_id* and surfaces the
    current state plus the discovery summary once the task succeeds.
    """
    info = get_task_status(job_id)
    result: DiscoveryResultSummary | None = None
    error: str | None = None

    if info["ready"]:
        if info["successful"]:
            raw_result = info["result"]
            if isinstance(raw_result, dict):
                result = DiscoveryResultSummary(
                    ips_discovered=int(raw_result.get("ips_discovered", 0)),
                    security_rules_found=int(
                        raw_result.get("security_rules_found", 0),
                    ),
                    load_balancers_found=int(
                        raw_result.get("load_balancers_found", 0),
                    ),
                    errors=list(raw_result.get("errors", []) or []),
                )
        else:
            raw_result = info["result"]
            error = str(raw_result) if raw_result is not None else "Task failed"

    return DiscoveryStatusResponse(
        job_id=job_id,
        status=info["status"],
        ready=info["ready"],
        successful=info["successful"],
        result=result,
        error=error,
    )


@router.get(
    "/status",
    response_model=LegacyDiscoveryStatusResponse,
    deprecated=True,
)
async def get_discovery_status_legacy() -> LegacyDiscoveryStatusResponse:
    """Deprecated — use ``GET /discovery/status/{job_id}`` instead.

    The in-memory last-result store was removed when discovery moved to
    Celery.  This endpoint always returns ``has_run=False`` and is
    retained only for backward-compatible clients.
    """
    return LegacyDiscoveryStatusResponse(
        has_run=False,
        result=None,
        message=(
            "Deprecated — dispatch via POST /discovery/run and poll "
            "GET /discovery/status/{job_id}"
        ),
    )
