"""Abstract base class for all cloud provider integrations.

Each cloud provider implementation must inherit from ``CloudProvider``
and implement the discovery methods.
"""

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

T = TypeVar("T")


@dataclass
class DiscoveredIP:
    """A single discovered IP address from a cloud provider."""

    ip_address: str
    private_ip: str | None = None
    resource_id: str | None = None
    resource_type: str | None = None
    region: str | None = None
    hostname: str | None = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class SecurityRule:
    """A security group / firewall / NSG rule discovered from a cloud provider."""

    rule_id: str | None = None
    protocol: str = "any"
    port_range: str | None = None
    source_cidrs: list[str] = field(default_factory=list)
    direction: str = "ingress"
    description: str | None = None


@dataclass
class LBEndpoint:
    """A load-balancer endpoint discovered from a cloud provider."""

    name: str = ""
    ip_address: str = ""
    port_range: str | None = None
    protocol: str | None = None
    backend_pool: str | None = None


@dataclass
class ProviderCredential:
    """Parsed credential for authenticating with a cloud provider."""

    credential_type: str
    fields: dict[str, str]


class CloudProvider(ABC):
    """Abstract interface for cloud provider IP discovery."""

    def __init__(self, credential: ProviderCredential) -> None:
        self.credential = credential

    # ── Abstract discovery methods ────────────────────────────────

    @abstractmethod
    async def discover_ip_addresses(self) -> list[DiscoveredIP]:
        """Enumerate all IP addresses accessible to the configured credentials.

        Returns
        -------
        list[DiscoveredIP]
            List of discovered IP addresses and their metadata.
        """
        ...

    @abstractmethod
    async def discover_security_rules(self) -> list[SecurityRule]:
        """Enumerate all security rules (security groups, NSGs, firewalls).

        Returns
        -------
        list[SecurityRule]
            List of discovered security rules.
        """
        ...

    @abstractmethod
    async def discover_load_balancers(self) -> list[LBEndpoint]:
        """Enumerate all load balancers and their endpoints.

        Returns
        -------
        list[LBEndpoint]
            List of discovered load balancer endpoints.
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify that the provider credentials are valid and API is reachable."""
        ...

    @abstractmethod
    async def get_regions(self) -> list[str]:
        """Return the list of available regions for this provider."""
        ...

    # ── Utility helpers ───────────────────────────────────────────

    async def _run_in_executor(self, func: Callable[..., T], *args: Any) -> T:
        """Run a blocking SDK call in the default executor to avoid blocking the event loop.

        Parameters
        ----------
        func : Callable
            The synchronous blocking function to call.
        *args
            Positional arguments forwarded to *func*.

        Returns
        -------
        Any
            The return value of *func*.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, func, *args)
