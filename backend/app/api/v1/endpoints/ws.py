"""WebSocket endpoint for real-time scan progress updates.

Clients connect to ``/api/v1/ws/scan/{scan_job_id}?token=<jwt>`` and
receive JSON-encoded progress messages published via Redis.  The JWT
access token is validated from the ``token`` query parameter because
WebSocket clients cannot send custom HTTP Authorization headers.
"""

import contextlib
import logging
from uuid import UUID

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.config import get_settings
from app.core.security import decode_access_token

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/ws", tags=["WebSocket"])

# WebSocket close code 4401 — application-defined "Unauthorized" (4xxx
# range is available for application use; 401 mirrors HTTP semantics).
_WS_UNAUTHORIZED_CODE = 4401


@router.websocket("/scan/{scan_job_id}")
async def scan_progress_ws(websocket: WebSocket, scan_job_id: UUID) -> None:
    """Stream scan progress updates to a connected, authenticated client.

    Validates the JWT access token from the ``token`` query parameter
    before subscribing.  Invalid or missing tokens close the connection
    with code 4401.  Listens on the Redis pub/sub channel
    ``scan:progress:{scan_job_id}`` and forwards every message.
    """
    token = websocket.query_params.get("token")
    payload = decode_access_token(token) if token else None

    await websocket.accept()

    if payload is None or payload.get("type") != "access":
        await websocket.close(
            code=_WS_UNAUTHORIZED_CODE,
            reason="Invalid or missing token",
        )
        return

    channel = f"scan:progress:{scan_job_id}"

    redis_conn = aioredis.from_url(
        settings.REDIS_URL,
        password=settings.REDIS_PASSWORD or None,
        socket_connect_timeout=5,
    )

    try:
        pubsub = redis_conn.pubsub()
        await pubsub.subscribe(channel)
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            data = message["data"]
            if isinstance(data, bytes):
                data = data.decode("utf-8")
            try:
                await websocket.send_text(data)
            except WebSocketDisconnect:
                break
    except Exception as exc:
        logger.error("WebSocket error for job %s: %s", scan_job_id, exc)
    finally:
        await pubsub.unsubscribe(channel)
        await redis_conn.close()
        with contextlib.suppress(Exception):
            await websocket.close()
