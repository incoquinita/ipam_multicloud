"""Cloud credential management endpoints.

All endpoints are mounted under ``/api/v1/credentials`` and require an
authenticated, active user (enforced at the router level).

The encrypted secret blob is never exposed by any response — only
``CredentialCreate`` accepts the plaintext credential fields, which the
service layer encrypts before persistence.  ``CredentialResponse`` omits
the ``encrypted_data`` column entirely.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db
from app.schemas.credentials import (
    CredentialCreate,
    CredentialListResponse,
    CredentialResponse,
)
from app.services.credential_service import CloudCredentialService

router = APIRouter(prefix="/credentials", tags=["Credentials"])


@router.post("/", response_model=CredentialResponse, status_code=status.HTTP_201_CREATED)
async def create_credential(
    data: CredentialCreate,
    db: AsyncSession = Depends(get_db),
) -> CredentialResponse:
    """Encrypt and store a new cloud credential.

    The plaintext ``credentials`` dict is encrypted at the service
    boundary and never persisted in cleartext.  The response excludes
    the encrypted blob entirely.
    """
    service = CloudCredentialService(db)
    credential = await service.create_credential(
        cloud_provider_id=data.cloud_provider_id,
        credential_type=data.provider_type,
        credential_name=data.name,
        fields=data.credentials,
    )
    return CredentialResponse.model_validate(credential)


@router.get("/", response_model=CredentialListResponse)
async def list_credentials(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    cloud_provider_id: UUID | None = Query(
        None, description="Filter by owning cloud provider",
    ),
    active_only: bool = Query(False, description="Return only active credentials"),
    db: AsyncSession = Depends(get_db),
) -> CredentialListResponse:
    """Return a paginated list of credentials (masked — no encrypted data)."""
    service = CloudCredentialService(db)
    skip = (page - 1) * page_size
    credentials = await service.list_credentials(
        skip=skip,
        limit=page_size,
        cloud_provider_id=cloud_provider_id,
        active_only=active_only,
    )
    total = await service.count_credentials(
        cloud_provider_id=cloud_provider_id,
        active_only=active_only,
    )
    items = [CredentialResponse.model_validate(c) for c in credentials]
    return CredentialListResponse(items=items, total=total)


@router.get("/{credential_id}", response_model=CredentialResponse)
async def get_credential(
    credential_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> CredentialResponse:
    """Return a single credential by ID (masked — no encrypted data)."""
    service = CloudCredentialService(db)
    credential = await service.get_by_id(credential_id)
    return CredentialResponse.model_validate(credential)


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_credential(
    credential_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Delete a credential by ID.  Returns 204 No Content on success."""
    service = CloudCredentialService(db)
    await service.delete_credential(credential_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
