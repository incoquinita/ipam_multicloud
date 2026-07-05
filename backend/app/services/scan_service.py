"""Scan orchestration service.

Coordinates scan job lifecycle: creation, queuing via Celery,
progress tracking, and result aggregation.
"""

import ipaddress
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import BadRequestException, NotFoundException
from app.models.http_analysis import HttpAnalysis
from app.models.ip_address import IPAddress
from app.models.port_result import PortResult
from app.models.scan_job import ScanJob
from app.repositories.scan_repository import ScanRepository
from app.repositories.target_repository import TargetRepository
from app.schemas.scan_job import ScanJobCreate
from app.schemas.scan_profiles import get_profile
from app.workers.scan_tasks import run_port_scan

# Default port list used when no profile and no explicit ports are given.
_DEFAULT_PORTS = [22, 80, 443, 3389]

# Maximum number of IPs a single CIDR target may expand to.
# Prevents accidental scans of huge ranges (e.g. /8 → 16M IPs).
_MAX_CIDR_EXPANSION = 256


def _resolve_ports(data: ScanJobCreate) -> list[int]:
    """Resolve the port list from either an explicit ``ports`` field,
    a named profile, or the default port list.

    Parameters
    ----------
    data : ScanJobCreate
        The scan creation payload.

    Returns
    -------
    list[int]
        The resolved list of ports to scan.
    """
    # Explicit port list takes priority.
    if data.ports is not None:
        return data.ports

    # Profile-based port list.
    if data.config and "profile" in data.config:
        profile_name = data.config["profile"]
        # Guard: validate profile name early.
        try:
            profile = get_profile(profile_name)
        except ValueError:
            raise
        # Custom profile uses the explicit ports from the request (if any).
        if profile_name == "custom" and data.ports is not None:
            return data.ports
        if profile.ports:
            return profile.ports

    return list(_DEFAULT_PORTS)


class ScanService:
    """High-level scan orchestration."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.scan_repo = ScanRepository(session)
        self.target_repo = TargetRepository(session)

    @staticmethod
    def _expand_cidr_target(
        target_value: str,
        max_expansion: int = _MAX_CIDR_EXPANSION,
    ) -> list[dict[str, Any]]:
        """Expand a CIDR range or wrap a single IP/hostname as host dicts.

        - Single IPs and hostnames are wrapped as a single-entry list.
        - CIDR notation (e.g. ``"10.0.0.0/24"``) is expanded into one
          host dict per usable IP address.

        Parameters
        ----------
        target_value : str
            A single IP, hostname, or CIDR range.
        max_expansion : int
            Maximum number of IPs a CIDR may expand to.  Raises
            ``ValueError`` if the range would exceed this limit.

        Returns
        -------
        list[dict[str, Any]]
            A list of ``{"host": str}`` dicts, one per target IP.

        Raises
        ------
        ValueError
            If the CIDR range exceeds ``max_expansion`` hosts, or if the
            value cannot be parsed as a valid network.
        """
        # Non-CIDR targets (single IP or hostname) — no expansion needed.
        if "/" not in target_value:
            return [{"host": target_value}]

        # Parse the CIDR into a network (strict=False tolerates host bits set).
        network = ipaddress.ip_network(target_value, strict=False)
        hosts = list(network.hosts())

        # Fail fast: refuse to scan oversized ranges.
        if len(hosts) > max_expansion:
            raise ValueError(
                f"CIDR range '{target_value}' expands to {len(hosts)} hosts, "
                f"exceeding the maximum of {max_expansion}. "
                "Use a more specific CIDR or raise the expansion limit."
            )

        return [{"host": str(ip)} for ip in hosts]

    async def _resolve_cloud_targets(
        self, provider_id: str,
    ) -> list[dict[str, Any]]:
        """Resolve a cloud-provider target into a list of discovered IP host dicts.

        Reads IPs previously written to ``ip_addresses`` by cloud discovery.
        Does **not** trigger a new discovery run — callers must run discovery
        first via :meth:`CloudService.run_discovery`.

        Parameters
        ----------
        provider_id : str
            UUID of the cloud provider to resolve.

        Returns
        -------
        list[dict[str, Any]]
            A list of ``{"host": str}`` dicts, one per discovered IP.

        Raises
        ------
        BadRequestException
            If ``provider_id`` is not a valid UUID, or if the provider has
            no discovered IPs (discovery must be run first).
        """
        # Parse the provider id at the boundary — fail loud on bad input.
        try:
            provider_uuid = UUID(provider_id)
        except (ValueError, AttributeError, TypeError) as exc:
            raise BadRequestException(
                detail=f"Invalid cloud provider id '{provider_id}': {exc}",
            ) from exc

        stmt = select(IPAddress.ip_address).where(
            IPAddress.cloud_provider_id == provider_uuid,
        )
        result = await self.session.execute(stmt)
        discovered_ips = result.scalars().all()

        # Fail fast: no discovered IPs means the user must run discovery first.
        if not discovered_ips:
            raise BadRequestException(
                detail=(
                    f"No discovered IPs found for cloud provider '{provider_id}'. "
                    "Run cloud discovery before scanning a cloud-provider target."
                ),
            )

        return [{"host": ip} for ip in discovered_ips]

    async def _resolve_targets(
        self,
        target_type: str,
        target_value: str,
        max_expansion: int = _MAX_CIDR_EXPANSION,
    ) -> list[dict[str, Any]]:
        """Resolve a scan target into a list of host dicts based on its type.

        Dispatches by ``target_type``:

        - ``"cloud_provider"`` → query discovered IPs from the database via
          :meth:`_resolve_cloud_targets`.
        - Any other type (``cidr``, ``ip_list``, ``hostname``) → expand the
          textual ``target_value`` via :meth:`_expand_cidr_target`.

        Parameters
        ----------
        target_type : str
            The target type (see :class:`ScanTarget`).
        target_value : str
            The target value — a CIDR, IP, hostname, or cloud provider UUID.
        max_expansion : int
            Maximum CIDR expansion (ignored for cloud-provider targets).

        Returns
        -------
        list[dict[str, Any]]
            A list of ``{"host": str}`` dicts, one per target IP.

        Raises
        ------
        BadRequestException
            If a cloud-provider target has no discovered IPs.
        ValueError
            If a CIDR target exceeds ``max_expansion`` hosts.
        """
        if target_type == "cloud_provider":
            return await self._resolve_cloud_targets(target_value)
        return self._expand_cidr_target(target_value, max_expansion)

    async def create_scan(self, data: ScanJobCreate) -> ScanJob:
        """Create a new scan job and dispatch it to the worker queue.

        Raises
        ------
        NotFoundException
            If the referenced target does not exist.
        BadRequestException
            If the target is inactive.
        ValueError
            If an unknown scan profile is specified in the config.
        """
        target = await self.target_repo.get(data.target_id)
        if target is None:
            raise NotFoundException(detail=f"Target '{data.target_id}' not found")
        if not target.is_active:
            raise BadRequestException(detail="Cannot scan an inactive target")

        # Resolve targets once — reused for both the total count and dispatch.
        # Raises BadRequestException (cloud provider w/o discovered IPs) or
        # ValueError (oversized CIDR) before any job row is created.
        targets = await self._resolve_targets(
            target.target_type, target.target_value,
        )

        # Build config dict with profile info.
        config: dict[str, Any] = {}
        if data.config:
            config.update(data.config)

        # Add profile to config if not already set.
        if "profile" not in config and data.ports is None:
            config["profile"] = "standard"

        scan_job = await self.scan_repo.create({
            "target_id": data.target_id,
            "scan_type": data.scan_type.value,
            "config": config,
            "status": "pending",
            "total_ips": len(targets),
        })

        # Dispatch to Celery asynchronously.
        run_port_scan.delay(
            scan_job_id=str(scan_job.id),
            targets=targets,
            config={
                "scan_type": data.scan_type.value,
                "profile": config.get("profile", "standard"),
                "timeout": config.get("timeout"),
                "concurrency": config.get("concurrency"),
                **(data.config or {}),
            },
        )

        return scan_job

    async def get_scan(self, scan_id: UUID) -> ScanJob:
        """Return a scan job or raise."""
        scan = await self.scan_repo.get(scan_id)
        if scan is None:
            raise NotFoundException(detail=f"Scan job '{scan_id}' not found")
        return scan

    async def list_scans(
        self,
        skip: int = 0,
        limit: int = 50,
        status: str | None = None,
    ) -> tuple[list[ScanJob], int]:
        """Return scan jobs and the total matching count.

        Returns
        -------
        tuple[list[ScanJob], int]
            ``(jobs, total)`` where *jobs* is the requested page and
            *total* is the count of all jobs matching the filter — used
            by the endpoint to populate ``PaginatedResponse.total``.
        """
        filters: dict[str, Any] = {}
        if status is not None:
            filters["status"] = status
        jobs = await self.scan_repo.list(skip=skip, limit=limit, filters=filters)
        total = await self.scan_repo.count_scans(status=status)
        return jobs, total

    async def cancel_scan(self, scan_id: UUID) -> ScanJob:
        """Cancel a running or queued scan job."""
        scan = await self.get_scan(scan_id)
        if scan.status not in ("pending", "queued", "running"):
            raise BadRequestException(
                detail=f"Cannot cancel scan in status '{scan.status}'",
            )
        updated = await self.scan_repo.update(scan_id, {"status": "cancelled"})
        if updated is None:
            raise NotFoundException(detail=f"Scan job '{scan_id}' not found")
        return updated

    async def get_dashboard_stats(self) -> dict[str, Any]:
        """Return aggregate dashboard statistics."""
        return await self.scan_repo.get_dashboard_stats()

    # ── Scan results ───────────────────────────────────────────────

    async def get_scan_results(
        self,
        scan_id: UUID,
    ) -> tuple[ScanJob, list[PortResult], list[HttpAnalysis]]:
        """Return the scan job together with all its port and HTTP results.

        Raises ``NotFoundException`` if the scan job does not exist.
        All port results and HTTP analyses are loaded (no pagination)
        so the caller can build a complete results bundle.
        """
        job = await self.get_scan(scan_id)
        port_results = await self.scan_repo.get_port_results(scan_id)
        http_analyses = await self.scan_repo.get_http_analyses(scan_id)
        return job, port_results, http_analyses

    async def get_port_results(
        self,
        scan_id: UUID,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[PortResult], int]:
        """Return a paginated page of port results and the total count.

        Raises ``NotFoundException`` if the scan job does not exist.
        """
        await self.get_scan(scan_id)
        results = await self.scan_repo.get_port_results(scan_id, skip=skip, limit=limit)
        total = await self.scan_repo.count_port_results(scan_id)
        return results, total

    async def get_http_analyses(
        self,
        scan_id: UUID,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[HttpAnalysis], int]:
        """Return a paginated page of HTTP analyses and the total count.

        Raises ``NotFoundException`` if the scan job does not exist.
        """
        await self.get_scan(scan_id)
        results = await self.scan_repo.get_http_analyses(scan_id, skip=skip, limit=limit)
        total = await self.scan_repo.count_http_analyses(scan_id)
        return results, total
