"""GCP provider unit tests.

Exercises ``GCPProvider`` discovery methods with mocked Google Cloud
Compute SDK clients.  No real GCP API calls are made.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.providers.base import ProviderCredential
from app.providers.gcp_provider import GCPProvider

_CREDENTIAL = ProviderCredential(
    credential_type="service_account",
    fields={"project_id": "test-project-123"},
)


def _mock_access_config(nat_ip: str | None) -> MagicMock:
    """Build a mock GCP access config with a natIP (external IP)."""
    return MagicMock(nat_i_p=nat_ip)


def _mock_network_interface(
    network_ip: str = "10.0.0.1",
    access_configs: list[MagicMock] | None = None,
) -> MagicMock:
    """Build a mock GCP network interface."""
    return MagicMock(network_i_p=network_ip, access_configs=access_configs or [])


def _mock_instance(
    name: str = "instance-1",
    zone: str = "zones/us-central1-a",
    network_interfaces: list[MagicMock] | None = None,
    labels: dict | None = None,
) -> MagicMock:
    """Build a mock GCP Compute Engine instance."""
    return MagicMock(
        name=name,
        network_interfaces=network_interfaces or [],
        labels=labels or {},
        hostname=None,
    )


def _mock_instances_response(
    zone_to_instances: dict[str, list[MagicMock]],
) -> list[tuple[str, MagicMock]]:
    """Build the (zone, response) pairs that ``aggregated_list`` yields.

    The GCP SDK ``aggregated_list`` returns an iterator of
    ``(zone, instances_in_zone)`` tuples.  Each ``instances_in_zone``
    has an ``instances`` attribute (possibly None).
    """
    pairs = []
    for zone, instances in zone_to_instances.items():
        scoped = MagicMock(instances=instances)
        pairs.append((zone, scoped))
    return pairs


def _mock_address(
    address: str = "203.0.113.50",
    name: str = "static-ip-1",
    region: str = "us-central1",
) -> MagicMock:
    """Build a mock GCP static external address."""
    return MagicMock(address=address, name=name, labels={})


def _mock_addresses_response(
    region_to_addresses: dict[str, list[MagicMock]],
) -> list[tuple[str, MagicMock]]:
    """Build the (region, response) pairs for ``AddressesClient.aggregated_list``."""
    pairs = []
    for region, addresses in region_to_addresses.items():
        scoped = MagicMock(addresses=addresses)
        pairs.append((region, scoped))
    return pairs


def _mock_firewall_rule(
    name: str = "allow-http",
    direction: str = "INGRESS",
    source_ranges: list[str] | None = None,
    destination_ranges: list[str] | None = None,
    allowed: list[dict] | None = None,
    denied: list[dict] | None = None,
    description: str | None = None,
    disabled: bool = False,
    priority: int = 1000,
    target_tags: list[str] | None = None,
) -> MagicMock:
    """Build a mock GCP firewall rule.

    ``allowed``/``denied`` are lists of dicts with ``IPProtocol`` and
    ``ports`` keys, matching the GCP SDK's protobuf-like interface.
    """
    return MagicMock(
        name=name,
        direction=direction,
        source_ranges=source_ranges or [],
        destination_ranges=destination_ranges or [],
        allowed=allowed or [],
        denied=denied or [],
        description=description,
        disabled=disabled,
        priority=priority,
        target_tags=target_tags or [],
    )


# ── discover_ip_addresses ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_discover_ip_addresses_finds_instance_nat_ips() -> None:
    """Compute instance NIC external IPs (natIP) are discovered."""
    instance = _mock_instance(
        name="web-1",
        network_interfaces=[
            _mock_network_interface(
                network_ip="10.0.0.1",
                access_configs=[_mock_access_config("203.0.113.10")],
            ),
        ],
    )

    instances_client = MagicMock()
    instances_client.aggregated_list.return_value = iter(
        _mock_instances_response({"zones/us-central1-a": [instance]}),
    )

    addresses_client = MagicMock()
    addresses_client.aggregated_list.return_value = iter([])

    provider = GCPProvider(_CREDENTIAL)
    with patch("app.providers.gcp_provider.compute_v1") as mock_compute:
        mock_compute.InstancesClient.return_value = instances_client
        mock_compute.AggregatedListInstancesRequest.return_value = MagicMock()
        mock_compute.AddressesClient.return_value = addresses_client
        mock_compute.AggregatedListAddressesRequest.return_value = MagicMock()
        result = await provider.discover_ip_addresses()

    ips = {dip.ip_address for dip in result}
    assert "203.0.113.10" in ips
    entry = next(dip for dip in result if dip.ip_address == "203.0.113.10")
    assert entry.resource_type == "compute_instance"
    assert entry.private_ip == "10.0.0.1"


@pytest.mark.asyncio
async def test_discover_ip_addresses_finds_static_external_ips() -> None:
    """Static (reserved) external IPs are discovered."""
    addr1 = _mock_address("192.0.2.10", "ip-1")
    addr2 = _mock_address("192.0.2.11", "ip-2")

    instances_client = MagicMock()
    instances_client.aggregated_list.return_value = iter([])

    addresses_client = MagicMock()
    addresses_client.aggregated_list.return_value = iter(
        _mock_addresses_response({"us-central1": [addr1, addr2]}),
    )

    provider = GCPProvider(_CREDENTIAL)
    with patch("app.providers.gcp_provider.compute_v1") as mock_compute:
        mock_compute.InstancesClient.return_value = instances_client
        mock_compute.AggregatedListInstancesRequest.return_value = MagicMock()
        mock_compute.AddressesClient.return_value = addresses_client
        mock_compute.AggregatedListAddressesRequest.return_value = MagicMock()
        result = await provider.discover_ip_addresses()

    ips = {dip.ip_address for dip in result}
    assert "192.0.2.10" in ips
    assert "192.0.2.11" in ips
    static = next(dip for dip in result if dip.ip_address == "192.0.2.10")
    assert static.resource_type == "static_external_ip"


@pytest.mark.asyncio
async def test_discover_ip_addresses_empty_project_returns_empty_list() -> None:
    """An empty GCP project returns no IPs."""
    instances_client = MagicMock()
    instances_client.aggregated_list.return_value = iter([])

    addresses_client = MagicMock()
    addresses_client.aggregated_list.return_value = iter([])

    provider = GCPProvider(_CREDENTIAL)
    with patch("app.providers.gcp_provider.compute_v1") as mock_compute:
        mock_compute.InstancesClient.return_value = instances_client
        mock_compute.AggregatedListInstancesRequest.return_value = MagicMock()
        mock_compute.AddressesClient.return_value = addresses_client
        mock_compute.AggregatedListAddressesRequest.return_value = MagicMock()
        result = await provider.discover_ip_addresses()

    assert result == []


# ── discover_security_rules ───────────────────────────────────────


@pytest.mark.asyncio
async def test_discover_security_rules_finds_open_firewall_ingress() -> None:
    """Firewall rules with 0.0.0.0/0 source range are discovered."""
    rule = _mock_firewall_rule(
        name="allow-http",
        direction="INGRESS",
        source_ranges=["0.0.0.0/0"],
        allowed=[{"IPProtocol": "tcp", "ports": ["80"]}],
    )

    firewalls_client = MagicMock()
    firewalls_client.list.return_value = iter([rule])

    provider = GCPProvider(_CREDENTIAL)
    with patch("app.providers.gcp_provider.compute_v1") as mock_compute:
        mock_compute.FirewallsClient.return_value = firewalls_client
        mock_compute.ListFirewallsRequest.return_value = MagicMock()
        rules = await provider.discover_security_rules()

    assert len(rules) == 1
    assert rules[0].direction == "ingress"
    assert "0.0.0.0/0" in rules[0].source_cidrs
    assert rules[0].port_range == "80"


@pytest.mark.asyncio
async def test_discover_security_rules_handles_egress_direction() -> None:
    """Egress firewall rules are parsed with destination ranges."""
    rule = _mock_firewall_rule(
        name="allow-egress",
        direction="EGRESS",
        destination_ranges=["10.0.0.0/8"],
        allowed=[{"IPProtocol": "tcp", "ports": ["443"]}],
    )

    firewalls_client = MagicMock()
    firewalls_client.list.return_value = iter([rule])

    provider = GCPProvider(_CREDENTIAL)
    with patch("app.providers.gcp_provider.compute_v1") as mock_compute:
        mock_compute.FirewallsClient.return_value = firewalls_client
        mock_compute.ListFirewallsRequest.return_value = MagicMock()
        rules = await provider.discover_security_rules()

    assert len(rules) == 1
    assert rules[0].direction == "egress"
    assert "10.0.0.0/8" in rules[0].source_cidrs


# ── health_check ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_check_returns_true_on_successful_call() -> None:
    """health_check returns True when listing zones succeeds."""
    zones_client = MagicMock()
    zones_client.list.return_value = iter([MagicMock(name="us-central1-a")])

    provider = GCPProvider(_CREDENTIAL)
    with patch("app.providers.gcp_provider.compute_v1") as mock_compute:
        mock_compute.ZonesClient.return_value = zones_client
        mock_compute.ListZonesRequest.return_value = MagicMock()
        result = await provider.health_check()

    assert result is True


@pytest.mark.asyncio
async def test_health_check_returns_false_on_exception() -> None:
    """health_check returns False when the GCP API raises."""
    zones_client = MagicMock()
    zones_client.list.side_effect = Exception("GCP auth failed")

    provider = GCPProvider(_CREDENTIAL)
    with patch("app.providers.gcp_provider.compute_v1") as mock_compute:
        mock_compute.ZonesClient.return_value = zones_client
        mock_compute.ListZonesRequest.return_value = MagicMock()
        result = await provider.health_check()

    assert result is False
