"""AWS provider unit tests.

Exercises ``AWSProvider`` discovery methods with mocked boto3 sessions
and clients.  No real AWS API calls are made — every SDK call is
intercepted by ``unittest.mock`` patches.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.providers.aws_provider import AWSProvider
from app.providers.base import ProviderCredential

_CREDENTIAL = ProviderCredential(
    credential_type="access_key",
    fields={
        "access_key_id": "AKIATEST",
        "secret_access_key": "secret",
        "region": "us-east-1",
    },
)


def _mock_paginator(pages: list[dict]) -> MagicMock:
    """Build a mock paginator whose ``paginate()`` yields the given pages."""
    paginator = MagicMock()
    paginator.paginate.return_value = iter(pages)
    return paginator


def _mock_ec2_client(
    reservations: list[dict] | None = None,
    addresses: list[dict] | None = None,
    nat_gateways: list[dict] | None = None,
    security_groups: list[dict] | None = None,
    elbv2_lbs: list[dict] | None = None,
    elb_lbs: list[dict] | None = None,
    regions: list[dict] | None = None,
) -> MagicMock:
    """Build a mock EC2/ELB client with configurable describe responses."""
    client = MagicMock()

    # EC2 paginators.
    ec2_paginator = _mock_paginator(reservations or [])
    elb_paginator = _mock_paginator(elb_lbs or [])
    sg_paginator = _mock_paginator(security_groups or [])

    paginator_map = {
        "describe_instances": ec2_paginator,
        "describe_security_groups": sg_paginator,
        "describe_load_balancers": elb_paginator,  # ELBv2 uses the same name
    }

    def _get_paginator(name: str) -> MagicMock:
        return paginator_map.get(name, _mock_paginator([]))

    client.get_paginator.side_effect = _get_paginator

    # Direct describe calls.
    client.describe_addresses.return_value = {"Addresses": addresses or []}
    client.describe_nat_gateways.return_value = {"NatGateways": nat_gateways or []}
    client.describe_regions.return_value = {"Regions": regions or []}

    return client


def _mock_elbv2_client(lbs: list[dict] | None = None) -> MagicMock:
    """Build a mock ELBv2 client."""
    client = MagicMock()
    paginator = _mock_paginator(lbs or [])
    client.get_paginator.return_value = paginator
    return client


def _mock_elb_client(lbs: list[dict] | None = None) -> MagicMock:
    """Build a mock ELBv1 (classic) client."""
    client = MagicMock()
    paginator = _mock_paginator(lbs or [])
    client.get_paginator.return_value = paginator
    return client


def _mock_boto3_session(ec2_client, elbv2_client=None, elb_client=None) -> MagicMock:
    """Build a mock boto3.Session whose ``client()`` returns the given clients."""
    session = MagicMock()
    client_map = {
        "ec2": ec2_client,
        "elbv2": elbv2_client or _mock_elbv2_client(),
        "elb": elb_client or _mock_elb_client(),
    }
    session.client.side_effect = lambda name, **_kw: client_map.get(name, MagicMock())
    session.region_name = "us-east-1"
    return session


# ── discover_ip_addresses ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_discover_ip_addresses_finds_ec2_instances() -> None:
    """EC2 instances with a PublicIpAddress are discovered."""
    reservations = [{
        "Reservations": [{
            "Instances": [{
                "InstanceId": "i-123",
                "PublicIpAddress": "203.0.113.10",
                "PrivateIpAddress": "10.0.0.1",
                "PublicDnsName": "ec2.example.com",
                "Placement": {"AvailabilityZone": "us-east-1a"},
                "Tags": [{"Key": "Name", "Value": "web-1"}],
            }],
        }],
    }]
    ec2 = _mock_ec2_client(reservations=reservations)

    provider = AWSProvider(_CREDENTIAL)
    with patch("app.providers.aws_provider.boto3.Session", return_value=_mock_boto3_session(ec2)):
        result = await provider.discover_ip_addresses()

    ips = {dip.ip_address for dip in result}
    assert "203.0.113.10" in ips
    ec2_entry = next(dip for dip in result if dip.ip_address == "203.0.113.10")
    assert ec2_entry.resource_type == "ec2_instance"
    assert ec2_entry.resource_id == "i-123"
    assert ec2_entry.private_ip == "10.0.0.1"


@pytest.mark.asyncio
async def test_discover_ip_addresses_finds_elastic_ips() -> None:
    """Elastic IPs (describe_addresses) are discovered."""
    addresses = [{
        "PublicIp": "192.0.2.50",
        "PrivateIpAddress": "10.0.0.50",
        "AllocationId": "eipalloc-123",
        "Tags": [],
    }]
    ec2 = _mock_ec2_client(addresses=addresses)

    provider = AWSProvider(_CREDENTIAL)
    with patch("app.providers.aws_provider.boto3.Session", return_value=_mock_boto3_session(ec2)):
        result = await provider.discover_ip_addresses()

    eip = next(dip for dip in result if dip.ip_address == "192.0.2.50")
    assert eip.resource_type == "elastic_ip"
    assert eip.resource_id == "eipalloc-123"


@pytest.mark.asyncio
async def test_discover_ip_addresses_finds_nat_gateway_ips() -> None:
    """NAT Gateway public IPs are discovered."""
    nat_gateways = [{
        "NatGatewayId": "nat-123",
        "NatGatewayAddresses": [{"PublicIp": "198.51.100.5", "PrivateIp": "10.0.0.5"}],
        "Tags": [],
    }]
    ec2 = _mock_ec2_client(nat_gateways=nat_gateways)

    provider = AWSProvider(_CREDENTIAL)
    with patch("app.providers.aws_provider.boto3.Session", return_value=_mock_boto3_session(ec2)):
        result = await provider.discover_ip_addresses()

    nat = next(dip for dip in result if dip.ip_address == "198.51.100.5")
    assert nat.resource_type == "nat_gateway"
    assert nat.resource_id == "nat-123"


@pytest.mark.asyncio
async def test_discover_ip_addresses_empty_account_returns_empty_list() -> None:
    """An account with no instances, EIPs, or NAT gateways returns []"""
    ec2 = _mock_ec2_client()

    provider = AWSProvider(_CREDENTIAL)
    with patch("app.providers.aws_provider.boto3.Session", return_value=_mock_boto3_session(ec2)):
        result = await provider.discover_ip_addresses()

    assert result == []


# ── discover_security_rules ───────────────────────────────────────


@pytest.mark.asyncio
async def test_discover_security_rules_finds_open_ingress() -> None:
    """Security groups with 0.0.0.0/0 ingress are discovered."""
    security_groups = [{
        "SecurityGroups": [{
            "GroupId": "sg-123",
            "GroupName": "open-web",
            "Description": "Open web SG",
            "IpPermissions": [{
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
            "IpPermissionsEgress": [],
        }],
    }]
    ec2 = _mock_ec2_client(security_groups=security_groups)

    provider = AWSProvider(_CREDENTIAL)
    with patch("app.providers.aws_provider.boto3.Session", return_value=_mock_boto3_session(ec2)):
        rules = await provider.discover_security_rules()

    assert len(rules) == 1
    rule = rules[0]
    assert rule.direction == "ingress"
    assert "0.0.0.0/0" in rule.source_cidrs
    assert rule.port_range == "80"


@pytest.mark.asyncio
async def test_discover_security_rules_includes_egress() -> None:
    """Egress rules are parsed with their destination CIDRs."""
    security_groups = [{
        "SecurityGroups": [{
            "GroupId": "sg-456",
            "GroupName": "egress-all",
            "Description": "",
            "IpPermissions": [],
            "IpPermissionsEgress": [{
                "IpProtocol": "-1",
                "FromPort": None,
                "ToPort": None,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        }],
    }]
    ec2 = _mock_ec2_client(security_groups=security_groups)

    provider = AWSProvider(_CREDENTIAL)
    with patch("app.providers.aws_provider.boto3.Session", return_value=_mock_boto3_session(ec2)):
        rules = await provider.discover_security_rules()

    assert len(rules) == 1
    assert rules[0].direction == "egress"
    assert "0.0.0.0/0" in rules[0].source_cidrs


# ── discover_load_balancers ───────────────────────────────────────


@pytest.mark.asyncio
async def test_discover_load_balancers_finds_elbv2_and_elbv1() -> None:
    """Both ELBv2 (ALB/NLB) and ELBv1 (classic) load balancers are discovered."""
    elbv2_lbs = [{
        "LoadBalancers": [{
            "LoadBalancerName": "my-nlb",
            "DNSName": "nlb.example.com",
            "Scheme": "internet-facing",
            "Type": "network",
        }],
    }]
    elb_lbs = [{
        "LoadBalancerDescriptions": [{
            "LoadBalancerName": "classic-lb",
            "DNSName": "classic.example.com",
            "ListenerDescriptions": [{"LoadBalancerPort": 443}],
        }],
    }]

    ec2 = _mock_ec2_client()
    elbv2 = _mock_elbv2_client(elbv2_lbs)
    elb = _mock_elb_client(elb_lbs)

    provider = AWSProvider(_CREDENTIAL)
    with patch(
        "app.providers.aws_provider.boto3.Session",
        return_value=_mock_boto3_session(ec2, elbv2, elb),
    ):
        endpoints = await provider.discover_load_balancers()

    names = {ep.name for ep in endpoints}
    assert "my-nlb" in names
    assert "classic-lb" in names


# ── health_check ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_check_returns_true_on_successful_api_call() -> None:
    """health_check returns True when describe_regions succeeds."""
    ec2 = _mock_ec2_client(regions=[{"RegionName": "us-east-1"}])

    provider = AWSProvider(_CREDENTIAL)
    with patch("app.providers.aws_provider.boto3.Session", return_value=_mock_boto3_session(ec2)):
        result = await provider.health_check()

    assert result is True


@pytest.mark.asyncio
async def test_health_check_returns_false_on_exception() -> None:
    """health_check returns False when the API call raises."""
    ec2 = _mock_ec2_client()
    ec2.describe_regions.side_effect = Exception("AWS auth failed")

    provider = AWSProvider(_CREDENTIAL)
    with patch("app.providers.aws_provider.boto3.Session", return_value=_mock_boto3_session(ec2)):
        result = await provider.health_check()

    assert result is False
