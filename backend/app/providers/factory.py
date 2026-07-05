"""Provider factory — resolves a provider type to its concrete class.

Parses the provider-type string at the boundary so internal code
receives a trusted ``CloudProvider`` instance.
"""

from __future__ import annotations

from app.providers.aws_provider import AWSProvider
from app.providers.azure_provider import AzureProvider
from app.providers.base import CloudProvider, ProviderCredential
from app.providers.gcp_provider import GCPProvider
from app.providers.oci_provider import OCIProvider

_PROVIDER_REGISTRY: dict[str, type[CloudProvider]] = {
    "aws": AWSProvider,
    "azure": AzureProvider,
    "gcp": GCPProvider,
    "oci": OCIProvider,
}


def get_provider(provider_type: str, credential: ProviderCredential) -> CloudProvider:
    """Return a :class:`CloudProvider` instance matching *provider_type*.

    Parameters
    ----------
    provider_type : str
        One of ``aws``, ``azure``, ``gcp``, or ``oci``.
    credential : ProviderCredential
        Parsed credential data.

    Returns
    -------
    CloudProvider
        An instance of the matching provider class.

    Raises
    ------
    ValueError
        If *provider_type* is not supported.
    """
    provider_cls = _PROVIDER_REGISTRY.get(provider_type)
    if provider_cls is None:
        raise ValueError(
            f"Unsupported cloud provider '{provider_type}'. "
            f"Supported types: {', '.join(_PROVIDER_REGISTRY)}",
        )
    return provider_cls(credential=credential)
