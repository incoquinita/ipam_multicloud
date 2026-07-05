"""Cloud provider management and discovery orchestration service."""

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundException
from app.models.cloud_provider import CloudProvider
from app.models.ip_address import IPAddress
from app.providers.base import CloudProvider as CloudProviderABC
from app.providers.base import DiscoveredIP, ProviderCredential
from app.providers.factory import get_provider
from app.repositories.cloud_repository import CloudRepository
from app.schemas.cloud_provider import CloudProviderCreate, CloudProviderUpdate
from app.services.credential_service import CloudCredentialService

logger = logging.getLogger(__name__)


class CloudService:
    """High-level cloud-provider operations and discovery orchestration."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = CloudRepository(session)
        self.credential_service = CloudCredentialService(session)

    # ── CRUD operations ───────────────────────────────────────────

    async def create_provider(self, data: CloudProviderCreate) -> CloudProvider:
        """Register a new cloud provider."""
        payload = data.model_dump(exclude_unset=True)
        # Flatten regions list to comma-separated string for storage.
        if "regions" in payload and payload["regions"] is not None:
            payload["regions"] = ",".join(payload["regions"])
        # Map metadata key to metadata_ column.
        if "metadata" in payload:
            payload["metadata_"] = payload.pop("metadata")
        return await self.repo.create(payload)

    async def get_provider(self, provider_id: UUID) -> CloudProvider:
        """Return a cloud provider or raise."""
        provider = await self.repo.get(provider_id)
        if provider is None:
            raise NotFoundException(detail=f"Cloud provider '{provider_id}' not found")
        return provider

    async def list_providers(
        self,
        skip: int = 0,
        limit: int = 50,
        active_only: bool = False,
    ) -> list[CloudProvider]:
        """Return cloud providers."""
        if active_only:
            return await self.repo.get_active_providers()
        return await self.repo.list(skip=skip, limit=limit)

    async def update_provider(
        self, provider_id: UUID, data: CloudProviderUpdate,
    ) -> CloudProvider:
        """Update a cloud provider."""
        provider = await self.repo.get(provider_id)
        if provider is None:
            raise NotFoundException(detail=f"Cloud provider '{provider_id}' not found")
        payload = data.model_dump(exclude_unset=True)
        if "regions" in payload and payload["regions"] is not None:
            payload["regions"] = ",".join(payload["regions"])
        if "metadata" in payload:
            payload["metadata_"] = payload.pop("metadata")
        updated = await self.repo.update(provider_id, payload)
        if updated is None:
            raise NotFoundException(detail=f"Cloud provider '{provider_id}' not found")
        return updated

    async def delete_provider(self, provider_id: UUID) -> None:
        """Delete a cloud provider."""
        deleted = await self.repo.delete(provider_id)
        if not deleted:
            raise NotFoundException(detail=f"Cloud provider '{provider_id}' not found")

    # ── Discovery orchestration ───────────────────────────────────

    async def run_discovery(self) -> dict[str, Any]:
        """Run full discovery across all active cloud providers.

        For each active provider:
          1. Decrypts credentials.
          2. Instantiates the provider via the factory.
          3. Calls ``discover_ip_addresses``, ``discover_security_rules``,
             ``discover_load_balancers``.
          4. Deduplicates IPs and stores them in the ``ip_addresses`` table.
          5. Handles partial failures gracefully.

        Returns
        -------
        dict
            Summary containing:
            - ``total_ips``: total number of unique IPs discovered.
            - ``provider_breakdown``: mapping of provider name -> IP count.
            - ``errors``: list of error messages per provider.
        """
        summary: dict[str, Any] = {
            "total_ips": 0,
            "provider_breakdown": {},
            "errors": [],
        }
        all_ips: dict[str, DiscoveredIP] = {}  # keyed by ip_address for dedup.

        # 1. Get all active providers with credentials eagerly loaded.
        providers = await self.repo.get_active_providers()
        if not providers:
            logger.info("No active providers found for discovery.")
            return summary

        for provider in providers:
            provider_name = provider.name or provider.provider_type
            try:
                await self._discover_single_provider(
                    provider, provider_name, all_ips, summary,
                )
            except Exception as exc:
                error_msg = f"{provider_name}: {exc}"
                logger.exception("Discovery failed for '%s'", provider_name)
                summary["errors"].append(error_msg)

        # 3. Persist deduplicated IPs.
        if all_ips:
            await self._store_discovered_ips(list(all_ips.values()), providers)

        summary["total_ips"] = len(all_ips)
        return summary

    async def _discover_single_provider(
        self,
        provider: CloudProvider,
        provider_name: str,
        all_ips: dict[str, DiscoveredIP],
        summary: dict[str, Any],
    ) -> None:
        """Run discovery for a single provider and collect results.

        Parameters
        ----------
        provider : CloudProvider
            The ORM model instance.
        provider_name : str
            Human-readable name for error reporting.
        all_ips : dict
            Shared IP deduplication dict (mutated in place).
        summary : dict
            Shared summary dict (mutated in place).
        """
        # Guard: no credentials.
        if not provider.credentials:
            logger.warning("Provider '%s' has no credentials; skipping.", provider_name)
            summary["errors"].append(f"{provider_name}: no active credentials")
            return

        # 2a. Decrypt credentials.
        provider_credentials: list[ProviderCredential] = []
        for cred in provider.credentials:
            try:
                parsed = self.credential_service.decrypt_credential(cred)
                provider_credentials.append(parsed)
            except Exception as exc:
                logger.warning(
                    "Failed to decrypt credential '%s' for '%s': %s",
                    cred.id, provider_name, exc,
                )
                summary["errors"].append(
                    f"{provider_name}: credential '{cred.credential_name}' "
                    f"decryption failed",
                )

        if not provider_credentials:
            summary["errors"].append(
                f"{provider_name}: no valid credentials after decryption",
            )
            return

        # 2b. For each credential, instantiate and discover.
        for cred in provider_credentials:
            try:
                provider_instance: CloudProviderABC = get_provider(
                    provider.provider_type, cred,
                )
            except Exception as exc:
                error_msg = f"{provider_name}: failed to instantiate provider: {exc}"
                logger.exception(error_msg)
                summary["errors"].append(error_msg)
                continue

            # 2c. Discover IP addresses.
            try:
                ips = await provider_instance.discover_ip_addresses()
                for discovered_ip in ips:
                    all_ips[discovered_ip.ip_address] = discovered_ip
                summary["provider_breakdown"][provider_name] = (
                    summary["provider_breakdown"].get(provider_name, 0) + len(ips)
                )
                logger.info(
                    "Discovered %d IPs from '%s'",
                    len(ips), provider_name,
                )
            except Exception as exc:
                error_msg = f"{provider_name}: IP discovery failed: {exc}"
                logger.exception(error_msg)
                summary["errors"].append(error_msg)

            # 2d. Discover security rules.
            try:
                security_rules = await provider_instance.discover_security_rules()
                logger.info(
                    "Discovered %d security rules from '%s'",
                    len(security_rules), provider_name,
                )
            except Exception as exc:
                logger.warning(
                    "Security rule discovery failed for '%s': %s",
                    provider_name, exc,
                )
                summary["errors"].append(
                    f"{provider_name}: security rule discovery failed: {exc}",
                )

            # 2e. Discover load balancers.
            try:
                lb_endpoints = await provider_instance.discover_load_balancers()
                for lb in lb_endpoints:
                    if lb.ip_address:
                        all_ips[lb.ip_address] = DiscoveredIP(
                            ip_address=lb.ip_address,
                            resource_type="load_balancer",
                            hostname=lb.name,
                            tags={"protocol": lb.protocol or "", "port_range": lb.port_range or ""},
                        )
                logger.info(
                    "Discovered %d load balancer endpoints from '%s'",
                    len(lb_endpoints), provider_name,
                )
            except Exception as exc:
                logger.warning(
                    "Load balancer discovery failed for '%s': %s",
                    provider_name, exc,
                )
                summary["errors"].append(
                    f"{provider_name}: load balancer discovery failed: {exc}",
                )

    async def _store_discovered_ips(
        self,
        ips: list[DiscoveredIP],
        providers: list[CloudProvider],
    ) -> None:
        """Store discovered IPs into the ``ip_addresses`` table.

        Uses upsert-like logic: if an IP with the same ``ip_address``
        already exists, update its ``last_seen_at`` and metadata.
        Otherwise insert a new row.

        Parameters
        ----------
        ips : list[DiscoveredIP]
            Deduplicated discovered IPs.
        providers : list[CloudProvider]
            List of all known providers (for mapping resource types).
        """
        existing = await self._load_existing_ips()

        for dip in ips:
            if dip.ip_address in existing:
                # Update last_seen_at on the existing record.
                existing_ip = existing[dip.ip_address]
                existing_ip.last_seen_at = datetime.now(timezone.utc)  # noqa: UP017  # mypy typeshed lacks datetime.UTC
                # Update optional metadata if missing.
                if not existing_ip.resource_type and dip.resource_type:
                    existing_ip.resource_type = dip.resource_type
                if not existing_ip.region and dip.region:
                    existing_ip.region = dip.region
                if not existing_ip.hostname and dip.hostname:
                    existing_ip.hostname = dip.hostname
            else:
                # Find the matching provider for resource-type mapping.
                provider_id: UUID | None = None
                for prov in providers:
                    if dip.resource_type and dip.resource_type.startswith(f"{prov.provider_type}_"):
                        provider_id = prov.id
                        break

                ip_record = IPAddress(
                    ip_address=dip.ip_address,
                    private_ip=dip.private_ip,
                    resource_id=dip.resource_id,
                    resource_type=dip.resource_type,
                    region=dip.region,
                    hostname=dip.hostname,
                    tags=dip.tags,
                    cloud_provider_id=provider_id,
                )
                self.session.add(ip_record)
                existing[dip.ip_address] = ip_record

        await self.session.flush()

    async def _load_existing_ips(self) -> dict[str, IPAddress]:
        """Load all existing IP addresses into a dict keyed by ``ip_address``."""
        from sqlalchemy import select as sa_select

        stmt = sa_select(IPAddress)
        result = await self.session.execute(stmt)
        return {row.ip_address: row for row in result.scalars().all()}
