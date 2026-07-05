"""AWS cloud provider implementation.

Uses ``boto3`` to enumerate EC2 instances, security groups, load
balancers, Elastic IPs, and NAT Gateway IPs.
"""

from typing import Any

import boto3

from app.providers.base import (
    CloudProvider,
    DiscoveredIP,
    LBEndpoint,
    ProviderCredential,
    SecurityRule,
)


class AWSProvider(CloudProvider):
    """IP discovery for Amazon Web Services."""

    def __init__(self, credential: ProviderCredential) -> None:
        super().__init__(credential)
        self._session: boto3.Session | None = None

    # ── Session management ────────────────────────────────────────

    def _get_session(self) -> boto3.Session:
        """Create or return a cached boto3 session."""
        if self._session is None:
            self._session = boto3.Session(
                aws_access_key_id=self.credential.fields.get("access_key_id", ""),
                aws_secret_access_key=self.credential.fields.get("secret_access_key", ""),
                region_name=self.credential.fields.get("region", "us-east-1"),
            )
        return self._session

    # ── IP discovery ──────────────────────────────────────────────

    async def discover_ip_addresses(self) -> list[DiscoveredIP]:
        """Enumerate EC2 instances, Elastic IPs, and NAT Gateway IPs."""
        session = self._get_session()
        ec2 = session.client("ec2")

        discovered: list[DiscoveredIP] = []

        # 1. EC2 instances.
        paginator = ec2.get_paginator("describe_instances")
        ec2_ips = await self._run_in_executor(
            self._discover_ec2_ips, paginator,
        )
        discovered.extend(ec2_ips)

        # 2. Elastic IPs (EIPs).
        eip_ips = await self._run_in_executor(
            self._discover_eips, ec2,
        )
        discovered.extend(eip_ips)

        # 3. NAT Gateway public IPs.
        nat_ips = await self._run_in_executor(
            self._discover_nat_ips, ec2,
        )
        discovered.extend(nat_ips)

        return discovered

    def _discover_ec2_ips(self, paginator: Any) -> list[DiscoveredIP]:
        """Synchronous helper — enumerate EC2 instances."""
        result: list[DiscoveredIP] = []
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    public_ip = instance.get("PublicIpAddress")
                    private_ip = instance.get("PrivateIpAddress")
                    if not public_ip and not private_ip:
                        continue

                    ip = public_ip or private_ip or ""
                    tags_map: dict[str, str] = {
                        t["Key"]: t["Value"]
                        for t in instance.get("Tags", [])
                    }

                    result.append(DiscoveredIP(
                        ip_address=ip,
                        private_ip=private_ip,
                        resource_id=instance["InstanceId"],
                        resource_type="ec2_instance",
                        region=(
                            instance.get("Placement", {})
                            .get("AvailabilityZone", "")
                            .rstrip("abcdef")
                        ),
                        hostname=instance.get("PublicDnsName"),
                        tags=tags_map,
                    ))
        return result

    def _discover_eips(self, ec2: Any) -> list[DiscoveredIP]:
        """Synchronous helper — discover Elastic IPs."""
        result: list[DiscoveredIP] = []
        response = ec2.describe_addresses()
        for addr in response.get("Addresses", []):
            public_ip = addr.get("PublicIp")
            if not public_ip:
                continue
            tags_map: dict[str, str] = {
                t["Key"]: t["Value"]
                for t in addr.get("Tags", [])
            }
            result.append(DiscoveredIP(
                ip_address=public_ip,
                private_ip=addr.get("PrivateIpAddress"),
                resource_id=addr.get("AllocationId"),
                resource_type="elastic_ip",
                region=addr.get("Domain", "standard"),
                tags=tags_map,
            ))
        return result

    def _discover_nat_ips(self, ec2: Any) -> list[DiscoveredIP]:
        """Synchronous helper — discover NAT Gateway public IPs."""
        result: list[DiscoveredIP] = []
        response = ec2.describe_nat_gateways()
        for ngw in response.get("NatGateways", []):
            for addr in ngw.get("NatGatewayAddresses", []):
                public_ip = addr.get("PublicIp")
                if not public_ip:
                    continue
                tags_map: dict[str, str] = {
                    t["Key"]: t["Value"]
                    for t in ngw.get("Tags", [])
                }
                result.append(DiscoveredIP(
                    ip_address=public_ip,
                    private_ip=addr.get("PrivateIp"),
                    resource_id=ngw.get("NatGatewayId"),
                    resource_type="nat_gateway",
                    region=self._get_session().region_name,
                    tags=tags_map,
                ))
        return result

    # ── Security rules discovery ──────────────────────────────────

    async def discover_security_rules(self) -> list[SecurityRule]:
        """Enumerate security groups and extract ingress/egress rules."""
        session = self._get_session()
        ec2 = session.client("ec2")

        security_groups = await self._run_in_executor(self._list_security_groups, ec2)
        return self._parse_security_rules(security_groups)

    def _list_security_groups(self, ec2: Any) -> list[Any]:
        """Synchronous helper — list all security groups."""
        result: list[Any] = []
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            result.extend(page.get("SecurityGroups", []))
        return result

    def _parse_security_rules(self, security_groups: list[Any]) -> list[SecurityRule]:
        """Synchronous helper — parse security group rules into SecurityRule dataclasses."""
        rules: list[SecurityRule] = []

        for sg in security_groups:
            group_id = sg.get("GroupId", "")
            group_name = sg.get("GroupName", "")
            description = sg.get("Description", "")
            rule_id_prefix = group_id or group_name

            # Ingress rules.
            for perm in sg.get("IpPermissions", []):
                protocol = perm.get("IpProtocol", "any")
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")
                port_range = self._format_port_range(from_port, to_port)

                source_cidrs: list[str] = []
                for ip_range in perm.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr:
                        source_cidrs.append(cidr)
                for ipv6_range in perm.get("Ipv6Ranges", []):
                    cidr = ipv6_range.get("CidrIpv6", "")
                    if cidr:
                        source_cidrs.append(cidr)

                rule_id = f"{rule_id_prefix}-ingress-{protocol}-{port_range or 'any'}"
                rules.append(SecurityRule(
                    rule_id=rule_id,
                    protocol=protocol,
                    port_range=port_range,
                    source_cidrs=source_cidrs,
                    direction="ingress",
                    description=description or None,
                ))

            # Egress rules.
            for perm in sg.get("IpPermissionsEgress", []):
                protocol = perm.get("IpProtocol", "any")
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")
                port_range = self._format_port_range(from_port, to_port)

                dest_cidrs: list[str] = []
                for ip_range in perm.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr:
                        dest_cidrs.append(cidr)
                for ipv6_range in perm.get("Ipv6Ranges", []):
                    cidr = ipv6_range.get("CidrIpv6", "")
                    if cidr:
                        dest_cidrs.append(cidr)

                rule_id = f"{rule_id_prefix}-egress-{protocol}-{port_range or 'any'}"
                rules.append(SecurityRule(
                    rule_id=rule_id,
                    protocol=protocol,
                    port_range=port_range,
                    source_cidrs=dest_cidrs,
                    direction="egress",
                    description=description or None,
                ))

        return rules

    @staticmethod
    def _format_port_range(from_port: int | None, to_port: int | None) -> str | None:
        """Format a port range as ``from-to`` or a single port."""
        if from_port is None and to_port is None:
            return None
        if from_port == to_port or to_port is None:
            return str(from_port)
        if from_port is None:
            return str(to_port)
        return f"{from_port}-{to_port}"

    # ── Load balancer discovery ───────────────────────────────────

    async def discover_load_balancers(self) -> list[LBEndpoint]:
        """Enumerate ELBv1, ELBv2 (ALB/NLB) load balancers."""
        session = self._get_session()

        endpoints: list[LBEndpoint] = []

        # ELBv2 (ALB / NLB).
        elbv2 = session.client("elbv2")
        elbv2_lbs = await self._run_in_executor(self._list_elbv2, elbv2)
        endpoints.extend(self._parse_elbv2_endpoints(elbv2_lbs))

        # ELBv1 (Classic).
        elb = session.client("elb")
        elbv1_lbs = await self._run_in_executor(self._list_elbv1, elb)
        endpoints.extend(self._parse_elbv1_endpoints(elbv1_lbs))

        return endpoints

    def _list_elbv2(self, elbv2: Any) -> list[Any]:
        """Synchronous helper — list ELBv2 load balancers."""
        result: list[Any] = []
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            result.extend(page.get("LoadBalancers", []))
        return result

    def _list_elbv1(self, elb: Any) -> list[Any]:
        """Synchronous helper — list ELBv1 (classic) load balancers."""
        result: list[Any] = []
        paginator = elb.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            result.extend(page.get("LoadBalancerDescriptions", []))
        return result

    def _parse_elbv2_endpoints(self, load_balancers: list[Any]) -> list[LBEndpoint]:
        """Parse ELBv2 load balancer endpoints (ALB / NLB)."""
        endpoints: list[LBEndpoint] = []

        for lb in load_balancers:
            name = lb.get("LoadBalancerName", "")
            dns_name = lb.get("DNSName", "")
            scheme = lb.get("Scheme", "")
            lb_type = lb.get("Type", "")
            # Use DNS name as the IP surrogate (NLBs can have Elastic IPs via DNS A records).
            ip_address = dns_name or ""
            port_range = None
            protocol = None

            # Try to extract listener info from the DNS / type.
            if lb_type == "network":
                protocol = "TCP"
            elif lb_type == "application":
                protocol = "HTTP/HTTPS"

            backend_pool = None
            # Extract availability-zone mapping for public IPs in NLB.
            if scheme != "internal" and ip_address:
                endpoints.append(LBEndpoint(
                    name=name,
                    ip_address=ip_address,
                    port_range=port_range,
                    protocol=protocol,
                    backend_pool=backend_pool,
                ))

        return endpoints

    def _parse_elbv1_endpoints(self, load_balancers: list[Any]) -> list[LBEndpoint]:
        """Parse ELBv1 (classic) load balancer endpoints."""
        endpoints: list[LBEndpoint] = []

        for lb in load_balancers:
            name = lb.get("LoadBalancerName", "")
            dns_name = lb.get("DNSName", "")
            ip_address = dns_name or ""
            listener_ports = [
                listener.get("LoadBalancerPort")
                for listener in lb.get("ListenerDescriptions", [])
                if listener.get("LoadBalancerPort")
            ]
            port_range = str(listener_ports[0]) if listener_ports else None

            if ip_address:
                endpoints.append(LBEndpoint(
                    name=name,
                    ip_address=ip_address,
                    port_range=port_range,
                    protocol="HTTP/HTTPS/TCP",
                    backend_pool=None,
                ))

        return endpoints

    # ── Health / regions ─────────────────────────────────────────

    async def health_check(self) -> bool:
        """Verify AWS API access by calling DescribeRegions."""
        try:
            session = self._get_session()
            ec2 = session.client("ec2")
            await self._run_in_executor(ec2.describe_regions)
            return True
        except Exception:
            return False

    async def get_regions(self) -> list[str]:
        """Return all available AWS regions."""
        session = self._get_session()
        ec2 = session.client("ec2", region_name="us-east-1")
        response = await self._run_in_executor(ec2.describe_regions)
        return [r["RegionName"] for r in response.get("Regions", [])]
