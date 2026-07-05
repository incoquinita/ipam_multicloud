"""Provider factory unit tests."""

import pytest

from app.providers.base import ProviderCredential
from app.providers.factory import get_provider


def test_get_provider_returns_instance_for_known_type() -> None:
    """A supported provider type resolves to a provider instance."""
    cred = ProviderCredential(credential_type="access_key", fields={})
    provider = get_provider("aws", cred)
    assert provider is not None


def test_get_provider_raises_value_error_for_unknown_type() -> None:
    """An unsupported provider type fails fast with a descriptive error."""
    cred = ProviderCredential(credential_type="access_key", fields={})
    with pytest.raises(ValueError, match="Unsupported cloud provider 'digitalocean'"):
        get_provider("digitalocean", cred)
