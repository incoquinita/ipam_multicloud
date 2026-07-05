"""GCP cloud provider implementation.

Uses the Google Cloud Compute SDK to enumerate VM instances, firewall
rules, forwarding rules (load balancers), and static external IPs.
"""

from typing import Any

from google.cloud import compute_v1

from app.providers.base import (
    CloudProvider,
    DiscoveredIP,
    LBEndpoint,
    ProviderCredential,
    SecurityRule,
)


class GCPProvider(CloudProvider):
    """IP discovery for Google Cloud Platform."""

    def __init__(self, credential: ProviderCredential) -> None:
        super().__init__(credential)
        self._project_id: str = credential.fields.get("project_id", "")

    # ── IP discovery ──────────────────────────────────────────────

    async def discover_ip_addresses(self) -> list[DiscoveredIP]:
        """Enumerate GCP Compute Engine instances and static external IPs."""
        discovered: list[DiscoveredIP] = []

        # 1. Compute instances.
        instances_ips = await self._run_in_executor(self._discover_instance_ips)
        discovered.extend(instances_ips)

        # 2. Static (reserved) external IPs.
        static_ips = await self._run_in_executor(self._discover_static_ips)
        discovered.extend(static_ips)

        return discovered

    def _discover_instance_ips(self) -> list[DiscoveredIP]:
        """Synchronous helper — enumerate instance IPs."""
        result: list[DiscoveredIP] = []
        client = compute_v1.InstancesClient()
        request = compute_v1.AggregatedListInstancesRequest(project=self._project_id)

        for zone, instances_in_zone in client.aggregated_list(request=request):
            if not instances_in_zone.instances:
                continue
            for instance in instances_in_zone.instances:
                region = zone.rsplit("/", 1)[-1] if "/" in zone else zone
                tags_map = dict(instance.labels or {})
                for nic in instance.network_interfaces or []:
                    public_ip = None
                    for access_config in nic.access_configs or []:
                        if access_config.nat_i_p:
                            public_ip = access_config.nat_i_p
                            break
                    private_ip = nic.network_i_p or None
                    ip = public_ip or private_ip or ""
                    if not ip:
                        continue

                    result.append(DiscoveredIP(
                        ip_address=ip,
                        private_ip=private_ip,
                        resource_id=instance.name,
                        resource_type="compute_instance",
                        region=region,
                        hostname=getattr(instance, "hostname", None),
                        tags=tags_map,
                    ))

        return result

    def _discover_static_ips(self) -> list[DiscoveredIP]:
        """Synchronous helper — discover static (reserved) external IPs."""
        result: list[DiscoveredIP] = []
        client = compute_v1.AddressesClient()
        request = compute_v1.AggregatedListAddressesRequest(project=self._project_id)

        for region, addresses_in_region in client.aggregated_list(request=request):
            if not addresses_in_region.addresses:
                continue
            region_name = region.rsplit("/", 1)[-1] if "/" in region else region
            for addr in addresses_in_region.addresses:
                ip_address = addr.address
                if not ip_address:
                    continue
                result.append(DiscoveredIP(
                    ip_address=ip_address,
                    resource_id=addr.name,
                    resource_type="static_external_ip",
                    region=region_name,
                    tags=dict(addr.labels or {}),
                ))

        return result

    # ── Security rules discovery ──────────────────────────────────

    async def discover_security_rules(self) -> list[SecurityRule]:
        """Enumerate GCP firewall rules."""
        rules = await self._run_in_executor(self._discover_firewall_rules)
        return rules

    def _discover_firewall_rules(self) -> list[SecurityRule]:
        """Synchronous helper — list all firewall rules."""
        result: list[SecurityRule] = []
        client = compute_v1.FirewallsClient()
        request = compute_v1.ListFirewallsRequest(project=self._project_id)

        for rule in client.list(request=request):
            direction = (rule.direction or "INGRESS").lower()
            protocol = "any"
            port_range: str | None = None
            source_cidrs: list[str] = []
            dest_cidrs: list[str] = []

            # Source ranges (ingress) or destination ranges (egress).
            if rule.source_ranges:
                source_cidrs.extend(rule.source_ranges)
            if rule.destination_ranges:
                dest_cidrs.extend(rule.destination_ranges)

            # Allowed protocols + ports.
            allowed_ports: list[str] = []
            for allowed in rule.allowed or []:
                ip_protocol = self._extract_ip_protocol(allowed)
                if ip_protocol and ip_protocol != "all" and protocol == "any":
                    protocol = ip_protocol
                ports = self._extract_ports(allowed)
                if ports:
                    allowed_ports.extend(ports)

            # Denied protocols + ports.
            denied_ports: list[str] = []
            for denied in rule.denied or []:
                ip_protocol = self._extract_ip_protocol(denied)
                if ip_protocol and ip_protocol != "all" and protocol == "any":
                    protocol = ip_protocol
                ports = self._extract_ports(denied)
                if ports:
                    denied_ports.extend(ports)

            if allowed_ports:
                port_range = ",".join(allowed_ports)
            elif denied_ports:
                port_range = ",".join(denied_ports)

            rule_id = rule.name or ""

            description_parts: list[str] = []
            if rule.description:
                description_parts.append(rule.description)
            if rule.disabled:
                description_parts.append("disabled")
            if rule.priority is not None:
                description_parts.append(f"priority={rule.priority}")
            if rule.target_tags:
                description_parts.append(f"target_tags={','.join(rule.target_tags)}")
            description = "; ".join(description_parts) if description_parts else None

            result.append(SecurityRule(
                rule_id=rule_id,
                protocol=protocol,
                port_range=port_range,
                source_cidrs=dest_cidrs if direction == "egress" else source_cidrs,
                direction=direction,
                description=description,
            ))

        return result

    @staticmethod
    def _extract_ip_protocol(obj: Any) -> str | None:
        """Extract the IP protocol from a firewall allowed/denied entry."""
        raw: Any = (
            obj.get("IPProtocol")
            if isinstance(obj, dict)
            else getattr(obj, "IpProtocol", None)
        )
        return str(raw) if raw is not None else None

    @staticmethod
    def _extract_ports(obj: Any) -> list[str]:
        """Extract the ports list from a firewall allowed/denied entry."""
        if isinstance(obj, dict):
            return obj.get("ports") or []
        ports = getattr(obj, "ports", None)
        return ports or []

    # ── Load balancer discovery ───────────────────────────────────

    async def discover_load_balancers(self) -> list[LBEndpoint]:
        """Enumerate GCP forwarding rules (regional and global)."""
        endpoints: list[LBEndpoint] = []

        # Regional forwarding rules.
        regional = await self._run_in_executor(self._discover_regional_forwarding_rules)
        endpoints.extend(regional)

        # Global forwarding rules.
        global_rules = await self._run_in_executor(self._discover_global_forwarding_rules)
        endpoints.extend(global_rules)

        return endpoints

    @staticmethod
    def _forwarding_rule_ip(rule: Any) -> str:
        """Extract IP address from a forwarding rule."""
        return getattr(rule, "IPAddress", "")

    @staticmethod
    def _forwarding_rule_protocol(rule: Any) -> str | None:
        """Extract protocol from a forwarding rule."""
        ip_protocol = getattr(rule, "IPProtocol", "")
        return ip_protocol.upper() if ip_protocol else None

    def _discover_regional_forwarding_rules(self) -> list[LBEndpoint]:
        """Synchronous helper — list regional forwarding rules."""
        result: list[LBEndpoint] = []
        client = compute_v1.ForwardingRulesClient()
        request = compute_v1.AggregatedListForwardingRulesRequest(project=self._project_id)

        for _region, rules_in_region in client.aggregated_list(request=request):
            if not rules_in_region.forwarding_rules:
                continue
            for rule in rules_in_region.forwarding_rules:
                ip_address = self._forwarding_rule_ip(rule)
                port_range = self._gcp_ports_str(rule)
                protocol = self._forwarding_rule_protocol(rule)
                if not ip_address:
                    continue
                result.append(LBEndpoint(
                    name=rule.name or "",
                    ip_address=ip_address,
                    port_range=port_range,
                    protocol=protocol,
                    backend_pool=getattr(rule, "target", None),
                ))

        return result

    def _discover_global_forwarding_rules(self) -> list[LBEndpoint]:
        """Synchronous helper — list global forwarding rules."""
        result: list[LBEndpoint] = []
        client = compute_v1.GlobalForwardingRulesClient()
        request = compute_v1.ListGlobalForwardingRulesRequest(project=self._project_id)

        for rule in client.list(request=request):
            ip_address = self._forwarding_rule_ip(rule)
            port_range = self._gcp_ports_str(rule)
            protocol = self._forwarding_rule_protocol(rule)
            if not ip_address:
                continue
            result.append(LBEndpoint(
                name=rule.name or "",
                ip_address=ip_address,
                port_range=port_range,
                protocol=protocol,
                backend_pool=getattr(rule, "target", None),
            ))

        return result

    @staticmethod
    def _gcp_ports_str(rule: Any) -> str | None:
        """Extract port range string from a GCP forwarding rule."""
        if getattr(rule, "all_ports", False):
            return None
        port_range: str | None = getattr(rule, "port_range", None)
        if port_range:
            return port_range
        ports: list[str] | list[Any] = getattr(rule, "ports", None) or []
        if ports:
            return ",".join(str(p) for p in ports)
        return None

    # ── Health / regions ─────────────────────────────────────────

    async def health_check(self) -> bool:
        """Verify GCP connectivity by listing zones."""
        try:
            client = compute_v1.ZonesClient()
            request = compute_v1.ListZonesRequest(project=self._project_id)
            await self._run_in_executor(lambda: list(client.list(request=request)))
            return True
        except Exception:
            return False

    async def get_regions(self) -> list[str]:
        """Return all available GCP regions."""
        client = compute_v1.RegionsClient()
        request = compute_v1.ListRegionsRequest(project=self._project_id)
        regions = await self._run_in_executor(lambda: list(client.list(request=request)))
        return [r.name for r in regions]
