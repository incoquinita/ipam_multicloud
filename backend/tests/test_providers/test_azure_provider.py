"""Azure provider unit tests.

Exercises ``AzureProvider`` discovery methods with mocked Azure SDK
clients.  No real Azure API calls are made.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.providers.azure_provider import AzureProvider
from app.providers.base import ProviderCredential

_CREDENTIAL = ProviderCredential(
    credential_type="service_principal",
    fields={
        "tenant_id": "tenant-123",
        "client_id": "client-123",
        "client_secret": "secret",
        "subscription_id": "sub-123",
    },
)


def _mock_public_ip(ip_address: str, pip_id: str = "pip-1", location: str = "eastus") -> MagicMock:
    """Build a mock public IP address object."""
    return MagicMock(id=pip_id, ip_address=ip_address, location=location, tags=None)


def _mock_nic(
    private_ip: str, nic_id: str = "nic-1", location: str = "eastus",
) -> MagicMock:
    """Build a mock network interface with one IP configuration."""
    ip_config = MagicMock(private_ip_address=private_ip)
    return MagicMock(id=nic_id, location=location, tags=None, ip_configurations=[ip_config])


def _mock_nsg(
    rules: list[MagicMock], nsg_id: str = "nsg-1", name: str = "open-nsg",
) -> MagicMock:
    """Build a mock network security group with the given rules."""
    return MagicMock(id=nsg_id, name=name, security_rules=rules)


def _mock_security_rule(
    name: str = "rule-1",
    direction: str = "Inbound",
    protocol: str = "Tcp",
    access: str = "Allow",
    source_prefix: str | None = "Internet",
    source_prefixes: list[str] | None = None,
    dest_port_range: str | None = "80",
    dest_port_ranges: list[str] | None = None,
    priority: int = 100,
) -> MagicMock:
    """Build a mock NSG security rule."""
    return MagicMock(
        name=name,
        direction=direction,
        protocol=protocol,
        access=access,
        source_address_prefix=source_prefix,
        source_address_prefixes=source_prefixes,
        destination_port_range=dest_port_range,
        destination_port_ranges=dest_port_ranges,
        priority=priority,
    )


def _mock_network_client(
    public_ips: list[MagicMock] | None = None,
    nics: list[MagicMock] | None = None,
    nsgs: list[MagicMock] | None = None,
    load_balancers: list[MagicMock] | None = None,
) -> MagicMock:
    """Build a mock NetworkManagementClient with configurable list responses."""
    client = MagicMock()

    client.public_ip_addresses.list_all.return_value = iter(public_ips or [])
    client.network_interfaces.list_all.return_value = iter(nics or [])
    client.network_security_groups.list_all.return_value = iter(nsgs or [])
    client.load_balancers.list_all.return_value = iter(load_balancers or [])

    return client


def _mock_resource_client(groups: list | None = None) -> MagicMock:
    """Build a mock ResourceManagementClient for health_check."""
    client = MagicMock()
    client.resource_groups.list.return_value = iter(groups or [])
    return client


# ── discover_ip_addresses ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_discover_ip_addresses_finds_public_ips() -> None:
    """Public IP addresses are discovered from list_all."""
    public_ips = [_mock_public_ip("203.0.113.10"), _mock_public_ip("203.0.113.11", "pip-2")]
    network_client = _mock_network_client(public_ips=public_ips)

    provider = AzureProvider(_CREDENTIAL)
    with patch.object(provider, "_get_network_client", return_value=network_client):
        result = await provider.discover_ip_addresses()

    ips = {dip.ip_address for dip in result}
    assert "203.0.113.10" in ips
    assert "203.0.113.11" in ips
    pub = next(dip for dip in result if dip.ip_address == "203.0.113.10")
    assert pub.resource_type == "public_ip"


@pytest.mark.asyncio
async def test_discover_ip_addresses_finds_nic_private_ips() -> None:
    """NIC private IPs are discovered from network_interfaces.list_all."""
    nics = [_mock_nic("10.0.0.1"), _mock_nic("10.0.0.2", "nic-2")]
    network_client = _mock_network_client(nics=nics)

    provider = AzureProvider(_CREDENTIAL)
    with patch.object(provider, "_get_network_client", return_value=network_client):
        result = await provider.discover_ip_addresses()

    nic_ips = {dip.ip_address for dip in result if dip.resource_type == "network_interface"}
    assert "10.0.0.1" in nic_ips
    assert "10.0.0.2" in nic_ips


@pytest.mark.asyncio
async def test_discover_ip_addresses_empty_subscription_returns_empty_list() -> None:
    """An empty Azure subscription returns no IPs."""
    network_client = _mock_network_client()

    provider = AzureProvider(_CREDENTIAL)
    with patch.object(provider, "_get_network_client", return_value=network_client):
        result = await provider.discover_ip_addresses()

    assert result == []


# ── discover_security_rules ───────────────────────────────────────


@pytest.mark.asyncio
async def test_discover_security_rules_finds_internet_open_ingress() -> None:
    """NSG rules with source_address_prefix='Internet' are discovered."""
    rule = _mock_security_rule(
        name="allow-web",
        direction="Inbound",
        source_prefix="Internet",
        dest_port_range="80",
    )
    nsg = _mock_nsg(rules=[rule])
    network_client = _mock_network_client(nsgs=[nsg])

    provider = AzureProvider(_CREDENTIAL)
    with patch.object(provider, "_get_network_client", return_value=network_client):
        rules = await provider.discover_security_rules()

    assert len(rules) == 1
    assert rules[0].direction == "ingress"
    assert "Internet" in rules[0].source_cidrs
    assert rules[0].port_range == "80"


@pytest.mark.asyncio
async def test_discover_security_rules_handles_multiple_source_prefixes() -> None:
    """Rules with source_address_prefixes (list) are parsed correctly."""
    rule = _mock_security_rule(
        name="allow-multi",
        source_prefix=None,
        source_prefixes=["10.0.0.0/8", "Internet"],
        dest_port_range="443",
    )
    nsg = _mock_nsg(rules=[rule])
    network_client = _mock_network_client(nsgs=[nsg])

    provider = AzureProvider(_CREDENTIAL)
    with patch.object(provider, "_get_network_client", return_value=network_client):
        rules = await provider.discover_security_rules()

    assert len(rules) == 1
    assert "10.0.0.0/8" in rules[0].source_cidrs
    assert "Internet" in rules[0].source_cidrs


# ── health_check ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_check_returns_true_on_successful_call() -> None:
    """health_check returns True when resource_groups.list succeeds."""
    resource_client = _mock_resource_client(groups=[MagicMock()])

    provider = AzureProvider(_CREDENTIAL)
    with patch.object(provider, "_get_credential"), \
         patch(
             "app.providers.azure_provider.ResourceManagementClient",
             return_value=resource_client,
         ):
        result = await provider.health_check()

    assert result is True


@pytest.mark.asyncio
async def test_health_check_returns_false_on_exception() -> None:
    """health_check returns False when the Azure API raises."""
    resource_client = _mock_resource_client()
    resource_client.resource_groups.list.side_effect = Exception("Azure auth failed")

    provider = AzureProvider(_CREDENTIAL)
    with patch.object(provider, "_get_credential"), \
         patch(
             "app.providers.azure_provider.ResourceManagementClient",
             return_value=resource_client,
         ):
        result = await provider.health_check()

    assert result is False
