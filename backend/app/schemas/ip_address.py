"""Pydantic schema for discovered IP addresses.

Maps from the ``IPAddress`` ORM model. The API field names
(``address``, ``provider_type``, ``instance_id``) intentionally differ
from the ORM column names (``ip_address``, ``resource_type``,
``resource_id``); ``AliasChoices`` lets ``from_attributes`` load from
either name. ``is_public`` is intentionally omitted — the ORM exposes
``is_alive`` (liveness), which is semantically distinct from public
reachability and would require its own migration to model.
"""

from datetime import datetime
from uuid import UUID

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class IPAddressResponse(BaseModel):
    """Discovered IP address representation."""

    id: UUID
    address: str = Field(
        ...,
        validation_alias=AliasChoices("address", "ip_address"),
        description="IP address string (IPv4 or IPv6)",
    )
    cloud_provider_id: UUID | None = None
    provider_type: str | None = Field(
        None,
        validation_alias=AliasChoices("provider_type", "resource_type"),
        description="Cloud provider type (aws, azure, gcp, oci)",
    )
    instance_id: str | None = Field(
        None,
        validation_alias=AliasChoices("instance_id", "resource_id"),
        description="Cloud provider resource instance ID",
    )
    region: str | None = None
    discovered_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IPAddressListResponse(BaseModel):
    """Paginated list of discovered IP addresses."""

    items: list[IPAddressResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
