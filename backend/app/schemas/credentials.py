"""Pydantic schemas for cloud credentials — creation and response.

The encrypted secret is never exposed by any response schema; only
``CredentialCreate`` accepts the plaintext credential fields, which the
service layer encrypts before persistence.

Field-name reconciliation with the ``CloudCredential`` ORM model:
the API exposes ``provider_type`` / ``name`` while the ORM columns are
``credential_type`` / ``credential_name``. ``CredentialResponse`` uses
``AliasChoices`` so ``from_attributes`` loads succeed regardless of
which name the source attribute carries.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class CredentialBase(BaseModel):
    """Shared credential fields."""

    provider_type: str = Field(
        ...,
        description=(
            "Credential type (access_key, service_principal, "
            "service_account, api_key, oci_config)"
        ),
    )
    name: str = Field(..., description="Human-readable label for this credential")
    metadata: dict[str, Any] | None = Field(
        None, description="Optional non-secret metadata associated with this credential",
    )


class CredentialCreate(CredentialBase):
    """Payload for storing a new credential.

    ``cloud_provider_id`` identifies the owning provider, and
    ``credentials`` holds the secret values that will be encrypted at
    the application boundary before being written to the database.
    """

    cloud_provider_id: UUID = Field(
        ..., description="UUID of the cloud provider this credential belongs to",
    )
    credentials: dict[str, Any] = Field(
        ..., description="Plaintext credential fields to encrypt and store",
    )


class CredentialResponse(BaseModel):
    """Credential representation returned from endpoints.

    Never includes the encrypted secret blob.  Field aliases reconcile
    the API names (``provider_type``, ``name``) with the ORM columns
    (``credential_type``, ``credential_name``) so ``from_attributes``
    loads from :class:`app.models.cloud_credential.CloudCredential`.
    """

    id: UUID
    provider_type: str = Field(
        ...,
        validation_alias=AliasChoices("provider_type", "credential_type"),
        description=(
            "Credential type (access_key, service_principal, "
            "service_account, api_key, oci_config)"
        ),
    )
    name: str = Field(
        ...,
        validation_alias=AliasChoices("name", "credential_name"),
        description="Human-readable label for this credential",
    )
    created_at: datetime
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class CredentialListResponse(BaseModel):
    """List of credentials with total count."""

    items: list[CredentialResponse]
    total: int
