"""Azure cloud provider implementation.

Uses the Azure SDK to enumerate network interfaces, public IPs, network
security groups, and load balancers.
"""

import logging

from azure.identity import ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient

from app.providers.base import (
    CloudProvider,
    DiscoveredIP,
    LBEndpoint,
    ProviderCredential,
    SecurityRule,
)

logger = logging.getLogger(__name__)


class AzureProvider(CloudProvider):
    """IP discovery for Microsoft Azure."""

    def __init__(self, credential: ProviderCredential) -> None:
        super().__init__(credential)
        self._credential: ClientSecretCredential | None = None
        self._subscription_id: str = ""

    def _get_credential(self) -> ClientSecretCredential:
        """Create or return a cached Azure credential."""
        if self._credential is None:
            self._credential = ClientSecretCredential(
                tenant_id=self.credential.fields.get("tenant_id", ""),
                client_id=self.credential.fields.get("client_id", ""),
                client_secret=self.credential.fields.get("client_secret", ""),
            )
            self._subscription_id = self.credential.fields.get("subscription_id", "")
        return self._credential

    def _get_network_client(self) -> NetworkManagementClient:
        """Create a network management client."""
        cred = self._get_credential()
        return NetworkManagementClient(cred, self._subscription_id)

    # ── IP discovery ──────────────────────────────────────────────

    async def discover_ip_addresses(self) -> list[DiscoveredIP]:
        """Enumerate Azure public IPs, NICs, and load balancer frontend IPs."""
        discovered: list[DiscoveredIP] = []

        # 1. Public IP addresses.
        public_ips = await self._run_in_executor(self._discover_public_ips)
        discovered.extend(public_ips)

        # 2. Network interfaces (private IPs).
        nics = await self._run_in_executor(self._discover_nic_ips)
        discovered.extend(nics)

        # 3. Load balancer frontend IPs.
        lb_ips = await self._run_in_executor(self._discover_lb_frontend_ips)
        discovered.extend(lb_ips)

        return discovered

    def _discover_public_ips(self) -> list[DiscoveredIP]:
        """Synchronous helper — enumerate public IP addresses."""
        result: list[DiscoveredIP] = []
        network_client = self._get_network_client()
        pips = network_client.public_ip_addresses.list_all()
        for pip in pips:
            ip = pip.ip_address
            if not ip:
                continue
            result.append(DiscoveredIP(
                ip_address=ip,
                resource_id=pip.id,
                resource_type="public_ip",
                region=pip.location,
                tags=dict(pip.tags) if pip.tags else {},
            ))
        return result

    def _discover_nic_ips(self) -> list[DiscoveredIP]:
        """Synchronous helper — enumerate NIC private IPs."""
        result: list[DiscoveredIP] = []
        network_client = self._get_network_client()
        nics = network_client.network_interfaces.list_all()
        for nic in nics:
            for ip_config in nic.ip_configurations or []:
                private_ip = ip_config.private_ip_address
                if private_ip:
                    result.append(DiscoveredIP(
                        ip_address=private_ip,
                        private_ip=private_ip,
                        resource_id=nic.id,
                        resource_type="network_interface",
                        region=nic.location,
                        tags=dict(nic.tags) if nic.tags else {},
                    ))
        return result

    def _discover_lb_frontend_ips(self) -> list[DiscoveredIP]:
        """Synchronous helper — enumerate load balancer frontend IPs."""
        result: list[DiscoveredIP] = []
        network_client = self._get_network_client()
        lbs = network_client.load_balancers.list_all()
        for lb in lbs:
            if not lb.frontend_ip_configurations:
                continue
            for fip in lb.frontend_ip_configurations:
                private_ip = fip.private_ip_address
                public_ip_ref = None
                if fip.public_ip_address:
                    public_ip_ref = fip.public_ip_address.id

                ip = private_ip or ""
                # If we have a public IP reference, fetch its address.
                if public_ip_ref and not ip:
                    try:
                        pip = network_client.public_ip_addresses.get(
                            resource_group_name=self._extract_resource_group(public_ip_ref),
                            public_ip_address_name=self._extract_resource_name(public_ip_ref),
                        )
                        if pip.ip_address:
                            ip = pip.ip_address
                    except Exception:
                        logger.warning(
                            "Failed to resolve public IP for LB frontend '%s'", fip.id,
                        )

                if not ip:
                    continue

                result.append(DiscoveredIP(
                    ip_address=ip,
                    private_ip=private_ip,
                    resource_id=lb.id,
                    resource_type="load_balancer",
                    region=lb.location,
                    tags=dict(lb.tags) if lb.tags else {},
                ))
        return result

    @staticmethod
    def _extract_resource_group(resource_id: str) -> str:
        """Extract the resource group name from an Azure resource ID."""
        parts = resource_id.lower().split("/")
        for i, part in enumerate(parts):
            if part == "resourcegroups" and i + 1 < len(parts):
                return parts[i + 1]
        return ""

    @staticmethod
    def _extract_resource_name(resource_id: str) -> str:
        """Extract the resource name from an Azure resource ID (last segment)."""
        return resource_id.rstrip("/").split("/")[-1]

    # ── Security rules discovery ──────────────────────────────────

    async def discover_security_rules(self) -> list[SecurityRule]:
        """Enumerate network security groups and their rules."""
        rules = await self._run_in_executor(self._discover_nsg_rules)
        return rules

    def _discover_nsg_rules(self) -> list[SecurityRule]:
        """Synchronous helper — list all NSGs and extract rules."""
        result: list[SecurityRule] = []
        network_client = self._get_network_client()
        nsgs = network_client.network_security_groups.list_all()

        for nsg in nsgs:
            nsg_id = nsg.id or ""
            nsg_name = nsg.name or ""

            # Inbound rules.
            for rule in nsg.security_rules or []:
                direction = (rule.direction or "Inbound").lower()
                protocol = (rule.protocol or "*").lower()
                access = (rule.access or "Allow").lower()

                source_cidrs: list[str] = []
                if rule.source_address_prefixes:
                    source_cidrs.extend(rule.source_address_prefixes)
                elif rule.source_address_prefix:
                    source_cidrs.append(rule.source_address_prefix)

                port_range: str | None = None
                if rule.destination_port_ranges:
                    port_range = ",".join(
                        str(p) for p in rule.destination_port_ranges
                    )
                elif rule.destination_port_range:
                    port_range = rule.destination_port_range

                rule_id = (
                    f"{nsg_name}-{rule.name}-{direction}"
                    if rule.name
                    else f"{nsg_id}-{direction}"
                )

                description_parts = [f"access={access}"]
                if rule.priority is not None:
                    description_parts.append(f"priority={rule.priority}")
                description = "; ".join(description_parts)

                result.append(SecurityRule(
                    rule_id=rule_id,
                    protocol=protocol,
                    port_range=port_range,
                    source_cidrs=source_cidrs,
                    direction=direction.replace("inbound", "ingress").replace("outbound", "egress"),
                    description=description,
                ))

        return result

    # ── Load balancer discovery ───────────────────────────────────

    async def discover_load_balancers(self) -> list[LBEndpoint]:
        """Enumerate load balancers and extract frontend endpoints."""
        endpoints = await self._run_in_executor(self._discover_lb_endpoints)
        return endpoints

    def _discover_lb_endpoints(self) -> list[LBEndpoint]:
        """Synchronous helper — list LBs and their frontend / backend configs."""
        result: list[LBEndpoint] = []
        network_client = self._get_network_client()
        lbs = network_client.load_balancers.list_all()

        for lb in lbs:
            lb_name = lb.name or ""
            for fip in lb.frontend_ip_configurations or []:
                ip_address = fip.private_ip_address or ""
                # Try to resolve public IP if available.
                if fip.public_ip_address and fip.public_ip_address.id:
                    try:
                        pip = network_client.public_ip_addresses.get(
                            resource_group_name=self._extract_resource_group(fip.public_ip_address.id),
                            public_ip_address_name=self._extract_resource_name(fip.public_ip_address.id),
                        )
                        if pip.ip_address:
                            ip_address = pip.ip_address
                    except Exception:
                        logger.warning(
                            "Failed to resolve public IP for LB endpoint '%s'", fip.id,
                        )

                if not ip_address:
                    continue

                # Extract rules associated with this frontend.
                port_range = None
                protocol = None
                backend_pool = None
                for rule in lb.load_balancing_rules or []:
                    fip_match = (
                        rule.frontend_ip_configuration
                        and rule.frontend_ip_configuration.id == fip.id
                    )
                    if fip_match:
                        port_range = str(rule.frontend_port) if rule.frontend_port else None
                        protocol = rule.protocol or None
                        if rule.backend_address_pool:
                            backend_pool = self._extract_resource_name(
                                rule.backend_address_pool.id,
                            ) if rule.backend_address_pool.id else None
                        break

                result.append(LBEndpoint(
                    name=lb_name,
                    ip_address=ip_address,
                    port_range=port_range,
                    protocol=protocol,
                    backend_pool=backend_pool,
                ))

        return result

    # ── Health / regions ─────────────────────────────────────────

    async def health_check(self) -> bool:
        """Verify Azure connectivity by listing resource groups."""
        try:
            cred = self._get_credential()
            resource_client = ResourceManagementClient(cred, self._subscription_id)
            await self._run_in_executor(
                lambda: list(resource_client.resource_groups.list(maxresults=1)),
            )
            return True
        except Exception:
            return False

    async def get_regions(self) -> list[str]:
        """Return all available Azure regions."""
        cred = self._get_credential()
        resource_client = ResourceManagementClient(cred, self._subscription_id)
        regions = await self._run_in_executor(
            lambda: list(resource_client.subscriptions.list_locations(self._subscription_id)),
        )
        return [r.name for r in regions]
