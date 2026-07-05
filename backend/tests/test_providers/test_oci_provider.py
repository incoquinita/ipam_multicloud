"""OCI (Oracle Cloud) provider unit tests.

Exercises ``OCIProvider`` discovery methods with mocked OCI SDK clients.
No real OCI API calls are made.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.providers.base import ProviderCredential
from app.providers.oci_provider import OCIProvider

_CREDENTIAL = ProviderCredential(
    credential_type="oci_config",
    fields={
        "user_ocid": "ocid1.user.oc1..test",
        "key_file_path": "/tmp/key.pem",
        "fingerprint": "ab:cd:ef",
        "tenancy_ocid": "ocid1.tenancy.oc1..test",
        "region": "us-ashburn-1",
    },
)


def _mock_vnic(public_ip: str | None, private_ip: str | None, vnic_id: str = "vnic-1") -> MagicMock:
    """Build a mock VNIC attachment and VNIC response."""
    vnic = MagicMock(
        public_ip=public_ip,
        private_ip=private_ip,
        hostname_label="host-1",
    )
    attachment = MagicMock(vnic_id=vnic_id)
    return attachment, vnic


def _mock_instance(
    instance_id: str = "ocid1.instance.1",
    region: str = "us-ashburn-1",
    attachments: list[MagicMock] | None = None,
) -> MagicMock:
    """Build a mock compute instance."""
    return MagicMock(id=instance_id, region=region, defined_tags={})


def _mock_public_ip(ip: str, pip_id: str = "ocid1.publicip.1") -> MagicMock:
    """Build a mock public IP resource."""
    return MagicMock(id=pip_id, ip_address=ip)


def _mock_tcp_options(min_val: int, max_val: int) -> MagicMock:
    """Build a mock OCI TCP/UDP options object with destination_port_range.

    The OCI SDK structure is ``tcp_options.destination_port_range.min/max``.
    """
    return MagicMock(destination_port_range=MagicMock(min=min_val, max=max_val))


def _mock_sl_rule(
    source: str = "0.0.0.0/0",
    protocol: str = "6",
    tcp_options: MagicMock | None = None,
) -> MagicMock:
    """Build a mock OCI security list ingress/egress rule."""
    return MagicMock(source=source, protocol=protocol, tcp_options=tcp_options)


def _mock_nsg_rule(
    direction: str = "INGRESS",
    source: str = "0.0.0.0/0",
    protocol: str = "6",
    tcp_options: MagicMock | None = None,
    rule_id: str = "nsg-rule-1",
    description: str | None = None,
) -> MagicMock:
    """Build a mock OCI NSG rule."""
    return MagicMock(
        id=rule_id,
        direction=direction,
        source=source if direction == "INGRESS" else None,
        destination=source if direction != "INGRESS" else None,
        protocol=protocol,
        tcp_options=tcp_options,
        description=description,
    )


def _mock_security_list(
    display_name: str = "sl-1",
    ingress_rules: list[MagicMock] | None = None,
    egress_rules: list[MagicMock] | None = None,
) -> MagicMock:
    """Build a mock OCI security list."""
    return MagicMock(
        id="ocid1.securitylist.1",
        display_name=display_name,
        ingress_security_rules=ingress_rules or [],
        egress_security_rules=egress_rules or [],
    )


def _mock_nsg(
    display_name: str = "nsg-1",
    rules: list[MagicMock] | None = None,
) -> MagicMock:
    """Build a mock OCI network security group."""
    return MagicMock(
        id="ocid1.nsg.1",
        display_name=display_name,
    )


def _mock_identity_client(compartments: list[MagicMock] | None = None) -> MagicMock:
    """Build a mock OCI IdentityClient."""
    client = MagicMock()
    client.list_compartments.return_value.data = compartments or []
    client.list_availability_domains.return_value.data = []
    return client


def _mock_compute_client(
    instances: list[MagicMock] | None = None,
    vnic_attachments: list[MagicMock] | None = None,
) -> MagicMock:
    """Build a mock OCI ComputeClient with per-instance VNIC attachments."""
    client = MagicMock()

    def _list_instances(compartment_id, **kw):
        result = MagicMock()
        result.data = instances or []
        return result

    def _list_vnic_attachments(compartment_id, **kw):
        result = MagicMock()
        result.data = vnic_attachments or []
        return result

    client.list_instances.side_effect = _list_instances
    client.list_vnic_attachments.side_effect = _list_vnic_attachments
    return client


def _mock_virtual_network_client(
    security_lists: list[MagicMock] | None = None,
    nsgs: list[MagicMock] | None = None,
    public_ips_reserved: list[MagicMock] | None = None,
    public_ips_ephemeral: list[MagicMock] | None = None,
    vnic_map: dict[str, MagicMock] | None = None,
) -> MagicMock:
    """Build a mock OCI VirtualNetworkClient."""
    client = MagicMock()

    def _list_security_lists(compartment_id, **kw):
        result = MagicMock()
        result.data = security_lists or []
        return result

    def _list_network_security_groups(compartment_id, **kw):
        result = MagicMock()
        result.data = nsgs or []
        return result

    def _list_nsg_rules(network_security_group_id, **kw):
        result = MagicMock()
        result.data = getattr(_list_nsg_rules, "_rules", [])
        return result

    def _list_public_ips(compartment_id, scope, lifetime, **kw):
        result = MagicMock()
        if lifetime == "RESERVED":
            result.data = public_ips_reserved or []
        else:
            result.data = public_ips_ephemeral or []
        return result

    def _get_vnic(vnic_id, **kw):
        result = MagicMock()
        result.data = (vnic_map or {}).get(vnic_id, MagicMock(public_ip=None, private_ip=None))
        return result

    client.list_security_lists.side_effect = _list_security_lists
    client.list_network_security_groups.side_effect = _list_network_security_groups
    client.list_network_security_group_security_rules.side_effect = _list_nsg_rules
    client.list_public_ips.side_effect = _list_public_ips
    client.get_vnic.side_effect = _get_vnic

    return client


# ── discover_ip_addresses ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_discover_ip_addresses_finds_vnic_public_ips() -> None:
    """Compute instance VNIC public IPs are discovered."""
    vnic_attachment, vnic = _mock_vnic("203.0.113.20", "10.0.0.1")
    instance = _mock_instance(attachments=[vnic_attachment])

    compute_client = _mock_compute_client(
        instances=[instance],
        vnic_attachments=[vnic_attachment],
    )

    vnic_client = _mock_virtual_network_client(
        vnic_map={vnic_attachment.vnic_id: vnic},
    )
    identity_client = _mock_identity_client()

    provider = OCIProvider(_CREDENTIAL)
    with patch("app.providers.oci_provider.oci") as mock_oci, \
         patch("app.providers.oci_provider.validate_config"):
        mock_oci.core.ComputeClient.return_value = compute_client
        mock_oci.core.VirtualNetworkClient.return_value = vnic_client
        mock_oci.identity.IdentityClient.return_value = identity_client
        result = await provider.discover_ip_addresses()

    ips = {dip.ip_address for dip in result}
    assert "203.0.113.20" in ips
    vnic_entry = next(dip for dip in result if dip.ip_address == "203.0.113.20")
    assert vnic_entry.resource_type == "compute_instance"


@pytest.mark.asyncio
async def test_discover_ip_addresses_finds_reserved_public_ips() -> None:
    """Reserved public IPs are discovered."""
    reserved_ips = [_mock_public_ip("192.0.2.10"), _mock_public_ip("192.0.2.11", "pip-2")]

    vnic_client = _mock_virtual_network_client(public_ips_reserved=reserved_ips)
    identity_client = _mock_identity_client()
    compute_client = _mock_compute_client()

    provider = OCIProvider(_CREDENTIAL)
    with patch("app.providers.oci_provider.oci") as mock_oci, \
         patch("app.providers.oci_provider.validate_config"):
        mock_oci.core.ComputeClient.return_value = compute_client
        mock_oci.core.VirtualNetworkClient.return_value = vnic_client
        mock_oci.identity.IdentityClient.return_value = identity_client
        result = await provider.discover_ip_addresses()

    ips = {dip.ip_address for dip in result}
    assert "192.0.2.10" in ips
    assert "192.0.2.11" in ips


# ── discover_security_rules ───────────────────────────────────────


@pytest.mark.asyncio
async def test_discover_security_rules_finds_security_list_ingress() -> None:
    """Security list ingress rules with 0.0.0.0/0 source are discovered."""
    tcp_opts = _mock_tcp_options(80, 80)
    ingress = _mock_sl_rule(source="0.0.0.0/0", protocol="6", tcp_options=tcp_opts)
    sl = _mock_security_list(ingress_rules=[ingress])

    vnic_client = _mock_virtual_network_client(security_lists=[sl])
    identity_client = _mock_identity_client()

    provider = OCIProvider(_CREDENTIAL)
    with patch("app.providers.oci_provider.oci") as mock_oci, \
         patch("app.providers.oci_provider.validate_config"):
        mock_oci.core.VirtualNetworkClient.return_value = vnic_client
        mock_oci.identity.IdentityClient.return_value = identity_client
        rules = await provider.discover_security_rules()

    sl_rules = [r for r in rules if r.direction == "ingress"]
    assert len(sl_rules) >= 1
    assert "0.0.0.0/0" in sl_rules[0].source_cidrs
    assert sl_rules[0].port_range == "80"


@pytest.mark.asyncio
async def test_discover_security_rules_finds_nsg_rules() -> None:
    """NSG rules are discovered alongside security list rules."""
    nsg = _mock_nsg(display_name="web-nsg")
    tcp_opts = _mock_tcp_options(443, 443)
    nsg_rule = _mock_nsg_rule(
        direction="INGRESS",
        source="0.0.0.0/0",
        protocol="6",
        tcp_options=tcp_opts,
        description="Allow HTTPS",
    )

    vnic_client = _mock_virtual_network_client(nsgs=[nsg])
    # Set the rules that the NSG rule listing will return.
    vnic_client.list_network_security_group_security_rules.side_effect = lambda **_kw: MagicMock(
        data=[nsg_rule],
    )
    identity_client = _mock_identity_client()

    provider = OCIProvider(_CREDENTIAL)
    with patch("app.providers.oci_provider.oci") as mock_oci, \
         patch("app.providers.oci_provider.validate_config"):
        mock_oci.core.VirtualNetworkClient.return_value = vnic_client
        mock_oci.identity.IdentityClient.return_value = identity_client
        rules = await provider.discover_security_rules()

    assert len(rules) >= 1
    open_rules = [r for r in rules if "0.0.0.0/0" in r.source_cidrs]
    assert len(open_rules) >= 1


# ── health_check ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_check_returns_true_on_successful_call() -> None:
    """health_check returns True when list_availability_domains succeeds."""
    identity_client = _mock_identity_client()

    provider = OCIProvider(_CREDENTIAL)
    with patch("app.providers.oci_provider.oci") as mock_oci, \
         patch("app.providers.oci_provider.validate_config"):
        mock_oci.identity.IdentityClient.return_value = identity_client
        result = await provider.health_check()

    assert result is True


@pytest.mark.asyncio
async def test_health_check_returns_false_on_exception() -> None:
    """health_check returns False when the OCI API raises."""
    identity_client = _mock_identity_client()
    identity_client.list_availability_domains.side_effect = Exception("OCI auth failed")

    provider = OCIProvider(_CREDENTIAL)
    with patch("app.providers.oci_provider.oci") as mock_oci, \
         patch("app.providers.oci_provider.validate_config"):
        mock_oci.identity.IdentityClient.return_value = identity_client
        result = await provider.health_check()

    assert result is False
