"""Celery application configuration.

Central Celery instance used by all task modules.  Configuration is
loaded from environment variables via the settings singleton.

Queue topology
--------------
- ``default``: generic / fallback tasks
- ``scans`` (routing key ``scan.#``): scan execution tasks
- ``cleanup`` (routing key ``cleanup.#``): periodic maintenance tasks
- ``discovery`` (routing key ``discovery.#``): cloud discovery tasks

Time limits (soft / hard)
-------------------------
- 600 s / 900 s — enforced at the worker level.
- Tasks that exceed the hard limit are killed; results are lost.
"""

from typing import Any

from celery import Celery

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "ipam_scanner",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    result_expires=3600,
    worker_max_tasks_per_child=1000,
    task_soft_time_limit=600,
    task_time_limit=900,
    task_default_queue="default",
    task_queues={
        "default": {},
        "scans": {"routing_key": "scan.#"},
        "cleanup": {"routing_key": "cleanup.#"},
        "discovery": {"routing_key": "discovery.#"},
    },
    task_default_exchange="tasks",
    task_default_exchange_type="topic",
    task_default_routing_key="scan.default",
    # Explicit task module imports — ``autodiscover_tasks`` looks for a
    # module named ``tasks.py`` by default, but our modules follow the
    # ``<name>_tasks.py`` convention.  Listing them here ensures the
    # worker imports (and registers) every task module on startup.
    include=[
        "app.workers.scan_tasks",
        "app.workers.cleanup_tasks",
        "app.workers.discovery_tasks",
    ],
)

# Auto-discover tasks in all registered worker modules.
celery_app.autodiscover_tasks(["app.workers"])


def get_task_status(task_id: str) -> dict[str, Any]:
    """Return the status of a Celery task by its id.

    Parameters
    ----------
    task_id : str
        UUID of the Celery task.

    Returns
    -------
    dict
        Task status summary with keys ``task_id``, ``status``,
        ``ready``, ``successful``, and ``result``.
    """
    from celery.result import AsyncResult

    result = AsyncResult(task_id, app=celery_app)
    return {
        "task_id": task_id,
        "status": result.status,
        "ready": result.ready(),
        "successful": result.successful(),
        "result": result.result if result.ready() else None,
    }
