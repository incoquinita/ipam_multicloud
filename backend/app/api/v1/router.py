"""v1 API router — aggregates all endpoint routers under a single prefix.

Import this from ``app.main`` to mount all v1 endpoints at
``/api/v1/``.
"""

from fastapi import APIRouter, Depends

from app.api.deps import get_current_active_user
from app.api.v1.endpoints import (
    analytics,
    auth,
    cloud_providers,
    credentials,
    discovery,
    health,
    ip_addresses,
    port_results,
    scans,
    targets,
    ws,
)

v1_router = APIRouter(prefix="/api/v1")

# Health check (no auth required).
v1_router.include_router(health.router)

# Auth endpoints (register, login, refresh, me) — public + self-authenticated.
v1_router.include_router(auth.router)

# Domain endpoints — all require an authenticated, active user.
v1_router.include_router(
    scans.router, dependencies=[Depends(get_current_active_user)],
)
v1_router.include_router(
    targets.router, dependencies=[Depends(get_current_active_user)],
)
v1_router.include_router(
    cloud_providers.router, dependencies=[Depends(get_current_active_user)],
)
v1_router.include_router(
    credentials.router, dependencies=[Depends(get_current_active_user)],
)
v1_router.include_router(
    discovery.router, dependencies=[Depends(get_current_active_user)],
)
v1_router.include_router(
    analytics.router, dependencies=[Depends(get_current_active_user)],
)
v1_router.include_router(
    ip_addresses.router, dependencies=[Depends(get_current_active_user)],
)
v1_router.include_router(
    port_results.router, dependencies=[Depends(get_current_active_user)],
)

# WebSocket — token validated manually from the ``token`` query parameter
# (WebSocket clients cannot send HTTP Authorization headers).
v1_router.include_router(ws.router)
