"""OCI (Oracle Cloud Infrastructure) provider implementation.

Uses the OCI Python SDK to enumerate compute instances, VNICs, security
lists, network security groups, load balancers, and public IPs.
"""

from typing import Any

import oci
from oci.config import validate_config

from app.providers.base import (
    CloudProvider,
    DiscoveredIP,
    LBEndpoint,
    ProviderCredential,
    SecurityRule,
)


class OCIProvider(CloudProvider):
    """IP discovery for Oracle Cloud Infrastructure."""

    def __init__(self, credential: ProviderCredential) -> None:
        super().__init__(credential)
        self._config: dict[str, Any] | None = None

    def _get_config(self) -> dict[str, Any]:
        """Build an OCI SDK config dict from stored credential fields."""
        if self._config is None:
            self._config = {
                "user": self.credential.fields.get("user_ocid", ""),
                "key_file": self.credential.fields.get("key_file_path", ""),
                "fingerprint": self.credential.fields.get("fingerprint", ""),
                "tenancy": self.credential.fields.get("tenancy_ocid", ""),
                "region": self.credential.fields.get("region", "us-ashburn-1"),
            }
            validate_config(self._config)
        return self._config

    def _get_compartments(self, identity: Any) -> list[Any]:
        """Synchronous helper — list all compartments in the tenancy."""
        config = self._get_config()
        compartments = identity.list_compartments(
            config["tenancy"], compartment_id_in_subtree=True,
        ).data
        return [config["tenancy"]] + [c.id for c in compartments]

    # ── IP discovery ──────────────────────────────────────────────

    async def discover_ip_addresses(self) -> list[DiscoveredIP]:
        """Enumerate OCI compute instances, VNICs, and public IPs."""
        config = self._get_config()
        compute_client = oci.core.ComputeClient(config)
        virtual_network_client = oci.core.VirtualNetworkClient(config)
        identity = oci.identity.IdentityClient(config)

        discovered: list[DiscoveredIP] = []

        # 1. Compute instance VNIC IPs.
        compartments = await self._run_in_executor(self._get_compartments, identity)
        compute_ips = await self._run_in_executor(
            self._discover_compute_ips, compute_client, virtual_network_client, compartments,
        )
        discovered.extend(compute_ips)

        # 2. Reserved and ephemeral public IPs.
        public_ips = await self._run_in_executor(
            self._discover_public_ips, virtual_network_client, compartments,
        )
        discovered.extend(public_ips)

        return discovered

    def _discover_compute_ips(
        self,
        compute_client: Any,
        virtual_network_client: Any,
        compartments: list[str],
    ) -> list[DiscoveredIP]:
        """Synchronous helper — enumerate compute instance VNIC IPs."""
        result: list[DiscoveredIP] = []

        for compartment_id in compartments:
            instances = compute_client.list_instances(
                compartment_id=compartment_id,
            ).data

            for instance in instances:
                vnic_attachments = compute_client.list_vnic_attachments(
                    compartment_id=compartment_id,
                    instance_id=instance.id,
                ).data

                for vnic_attachment in vnic_attachments:
                    vnic = virtual_network_client.get_vnic(
                        vnic_attachment.vnic_id,
                    ).data

                    public_ip = vnic.public_ip
                    private_ip = vnic.private_ip
                    ip = public_ip or private_ip or ""
                    if not ip:
                        continue

                    result.append(DiscoveredIP(
                        ip_address=ip,
                        private_ip=private_ip,
                        resource_id=instance.id,
                        resource_type="compute_instance",
                        region=instance.region or self._config.get("region", ""),  # type: ignore[union-attr]
                        hostname=vnic.hostname_label or None,
                        tags=dict(instance.defined_tags or {}),
                    ))

        return result

    def _discover_public_ips(
        self,
        virtual_network_client: Any,
        compartments: list[str],
    ) -> list[DiscoveredIP]:
        """Synchronous helper — discover reserved and ephemeral public IPs."""
        assert self._config is not None, "_get_config() must be called before _discover_public_ips"
        result: list[DiscoveredIP] = []

        for compartment_id in compartments:
            # Reserved public IPs.
            reserved_ips = virtual_network_client.list_public_ips(
                compartment_id=compartment_id,
                scope="REGION",
                lifetime="RESERVED",
            ).data
            for pip in reserved_ips:
                ip_address = pip.ip_address
                if not ip_address:
                    continue
                result.append(DiscoveredIP(
                    ip_address=ip_address,
                    resource_id=pip.id,
                    resource_type="public_ip_reserved",
                    region=self._config.get("region", ""),
                    tags={},
                ))

            # Ephemeral public IPs.
            ephemeral_ips = virtual_network_client.list_public_ips(
                compartment_id=compartment_id,
                scope="REGION",
                lifetime="EPHEMERAL",
            ).data
            for pip in ephemeral_ips:
                ip_address = pip.ip_address
                if not ip_address:
                    continue
                result.append(DiscoveredIP(
                    ip_address=ip_address,
                    resource_id=pip.id,
                    resource_type="public_ip_ephemeral",
                    region=self._config.get("region", ""),
                    tags={},
                ))

        return result

    # ── Security rules discovery ──────────────────────────────────

    async def discover_security_rules(self) -> list[SecurityRule]:
        """Enumerate security lists and network security groups."""
        config = self._get_config()
        virtual_network_client = oci.core.VirtualNetworkClient(config)
        identity = oci.identity.IdentityClient(config)

        compartments = await self._run_in_executor(self._get_compartments, identity)

        # 1. Security lists.
        sl_rules = await self._run_in_executor(
            self._discover_security_list_rules, virtual_network_client, compartments,
        )
        # 2. Network security groups.
        nsg_rules = await self._run_in_executor(
            self._discover_nsg_rules, virtual_network_client, compartments,
        )

        return sl_rules + nsg_rules

    def _discover_security_list_rules(
        self,
        virtual_network_client: Any,
        compartments: list[str],
    ) -> list[SecurityRule]:
        """Synchronous helper — extract rules from security lists."""
        result: list[SecurityRule] = []

        for compartment_id in compartments:
            security_lists = virtual_network_client.list_security_lists(
                compartment_id=compartment_id,
            ).data

            for sl in security_lists:
                sl_name = sl.display_name or sl.id or ""

                # Ingress rules.
                for rule in sl.ingress_security_rules or []:
                    protocol = self._oci_protocol_name(rule.protocol)
                    source_cidrs: list[str] = []
                    if rule.source:
                        source_cidrs.append(rule.source)

                    port_range = self._oci_format_port_range(rule)
                    rule_id = f"{sl_name}-ingress-{protocol}"

                    result.append(SecurityRule(
                        rule_id=rule_id,
                        protocol=protocol,
                        port_range=port_range,
                        source_cidrs=source_cidrs,
                        direction="ingress",
                        description=sl_name,
                    ))

                # Egress rules.
                for rule in sl.egress_security_rules or []:
                    protocol = self._oci_protocol_name(rule.protocol)
                    dest_cidrs: list[str] = []
                    if rule.destination:
                        dest_cidrs.append(rule.destination)

                    port_range = self._oci_format_port_range(rule)
                    rule_id = f"{sl_name}-egress-{protocol}"

                    result.append(SecurityRule(
                        rule_id=rule_id,
                        protocol=protocol,
                        port_range=port_range,
                        source_cidrs=dest_cidrs,
                        direction="egress",
                        description=sl_name,
                    ))

        return result

    def _discover_nsg_rules(
        self,
        virtual_network_client: Any,
        compartments: list[str],
    ) -> list[SecurityRule]:
        """Synchronous helper — extract rules from network security groups."""
        result: list[SecurityRule] = []

        for compartment_id in compartments:
            nsgs = virtual_network_client.list_network_security_groups(
                compartment_id=compartment_id,
            ).data

            for nsg in nsgs:
                nsg_name = nsg.display_name or nsg.id or ""
                # Get rules for this NSG.
                nsg_rules = virtual_network_client.list_network_security_group_security_rules(
                    network_security_group_id=nsg.id,
                ).data

                for rule in nsg_rules:
                    direction = (rule.direction or "INGRESS").lower()
                    protocol = self._oci_protocol_name(rule.protocol)

                    source_cidrs: list[str] = []
                    if direction == "ingress":
                        if rule.source:
                            source_cidrs.append(rule.source)
                    else:
                        if rule.destination:
                            source_cidrs.append(rule.destination)

                    port_range = None
                    if rule.tcp_options:
                        port_range = self._oci_format_transport_options(rule.tcp_options)
                    elif rule.udp_options:
                        port_range = self._oci_format_transport_options(rule.udp_options)

                    rule_id = f"{nsg_name}-{rule.id or direction}-{protocol}"

                    result.append(SecurityRule(
                        rule_id=rule_id,
                        protocol=protocol,
                        port_range=port_range,
                        source_cidrs=source_cidrs,
                        direction=direction,
                        description=rule.description or nsg_name,
                    ))

        return result

    @staticmethod
    def _oci_protocol_name(protocol: str | int | None) -> str:
        """Map OCI protocol numbers to names."""
        protocol_map: dict[int, str] = {
            1: "icmp",
            6: "tcp",
            17: "udp",
            58: "icmpv6",
        }
        if protocol is None:
            return "any"
        if isinstance(protocol, int):
            return protocol_map.get(protocol, str(protocol))
        return protocol

    @staticmethod
    def _oci_format_port_range(rule: Any) -> str | None:
        """Extract port range from an OCI security list/NSG rule."""
        tcp_options = getattr(rule, "tcp_options", None)
        udp_options = getattr(rule, "udp_options", None)

        options = tcp_options or udp_options
        if options is None:
            return None

        dest = getattr(options, "destination_port_range", None)
        if dest is None:
            return None

        if hasattr(dest, "min") and hasattr(dest, "max"):
            if dest.min == dest.max:
                return str(dest.min)
            return f"{dest.min}-{dest.max}"
        return str(dest)

    @staticmethod
    def _oci_format_transport_options(options: Any) -> str | None:
        """Extract port range from OCI TCP/UDP options."""
        dest = getattr(options, "destination_port_range", None)
        if dest is None:
            return None
        if hasattr(dest, "min") and hasattr(dest, "max"):
            if dest.min == dest.max:
                return str(dest.min)
            return f"{dest.min}-{dest.max}"
        return str(dest)

    # ── Load balancer discovery ───────────────────────────────────

    async def discover_load_balancers(self) -> list[LBEndpoint]:
        """Enumerate OCI load balancers."""
        config = self._get_config()
        identity = oci.identity.IdentityClient(config)
        compartments = await self._run_in_executor(self._get_compartments, identity)

        # OCI LBaaS uses a separate client.
        lb_client = oci.load_balancer.LoadBalancerClient(config)
        endpoints = await self._run_in_executor(
            self._discover_lb_endpoints, lb_client, compartments,
        )
        return endpoints

    def _discover_lb_endpoints(
        self,
        lb_client: Any,
        compartments: list[str],
    ) -> list[LBEndpoint]:
        """Synchronous helper — list LBs and extract public IPs."""
        result: list[LBEndpoint] = []

        for compartment_id in compartments:
            lbs = lb_client.list_load_balancers(
                compartment_id=compartment_id,
            ).data

            for lb in lbs:
                lb_name = lb.display_name or lb.id or ""

                # Extract IP addresses from backend sets / listeners.
                ip_addresses: list[str] = []
                for backend_set in (lb.backend_sets or {}).values():
                    for backend in backend_set.backends or []:
                        ip_address = getattr(backend, "ip_address", None)
                        if ip_address and ip_address not in ip_addresses:
                            ip_addresses.append(ip_address)

                # Extract listeners for ports and protocols.
                listeners = lb.listeners or {}
                for listener_name, listener in listeners.items():
                    protocol = getattr(listener, "protocol", None) or None
                    listener_port = getattr(listener, "port", None)
                    port = str(listener_port) if listener_port else None

                    # If no explicit IPs from backends, try LB-level ip_addresses.
                    listener_ips = list(ip_addresses)
                    if not listener_ips:
                        lb_ips = getattr(lb, "ip_addresses", None)
                        if lb_ips:
                            listener_ips = [lb_ips[0]]

                    if not listener_ips:
                        continue

                    for ip_addr in listener_ips:
                        result.append(LBEndpoint(
                            name=f"{lb_name}/{listener_name}" if listener_name else lb_name,
                            ip_address=ip_addr,
                            port_range=port,
                            protocol=protocol,
                            backend_pool=getattr(
                                listener, "default_backend_set_name", None,
                            ),
                        ))

        return result

    # ── Health / regions ─────────────────────────────────────────

    async def health_check(self) -> bool:
        """Verify OCI connectivity by listing availability domains."""
        try:
            config = self._get_config()
            identity = oci.identity.IdentityClient(config)
            await self._run_in_executor(
                identity.list_availability_domains, config["tenancy"],
            )
            return True
        except Exception:
            return False

    async def get_regions(self) -> list[str]:
        """Return all OCI regions (subscribed)."""
        config = self._get_config()
        identity = oci.identity.IdentityClient(config)
        regions = await self._run_in_executor(
            lambda: identity.list_region_subscriptions(config["tenancy"]).data,
        )
        return [r.region_name for r in regions]
