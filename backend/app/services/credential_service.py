"""Credential management service.

Handles encrypting credential data before storage and decrypting before
use, using Fernet symmetric encryption from the ``cryptography`` package.
"""

import base64
import hashlib
import json
import logging
from typing import Any, cast
from uuid import UUID

from cryptography.fernet import Fernet
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.exceptions import NotFoundException
from app.models.cloud_credential import CloudCredential
from app.models.cloud_provider import CloudProvider
from app.providers.base import ProviderCredential

logger = logging.getLogger(__name__)


class CloudCredentialService:
    """Service for encrypting, storing, and decrypting cloud credentials.

    Uses a Fernet symmetric key derived from the application's
    ``ENCRYPTION_KEY`` setting.  All data is encrypted at the boundary
    before passing to the repository and decrypted at the boundary
    before returning to callers.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        settings = get_settings()
        key = settings.ENCRYPTION_KEY
        # Fernet requires a 32-byte URL-safe base64 key.
        # If the key isn't already in the right format, derive one.
        self._fernet = self._build_fernet(key)

    # ── Initialization helpers ────────────────────────────────────

    @staticmethod
    def _build_fernet(raw_key: str) -> Fernet:
        """Build a Fernet instance from a string key.

        If *raw_key* is already a valid Fernet key (32 URL-safe base64
        bytes) it is used directly.  Otherwise the string is padded /
        hashed to produce a valid key.
        """
        try:
            return Fernet(raw_key.encode() if isinstance(raw_key, str) else raw_key)
        except (ValueError, TypeError):
            # Derive a valid Fernet key by hashing.
            digest = hashlib.sha256(raw_key.encode()).digest()
            key = base64.urlsafe_b64encode(digest)
            return Fernet(key)

    # ── Public API ────────────────────────────────────────────────

    async def encrypt_and_store(
        self,
        cloud_provider_id: UUID,
        credential_type: str,
        credential_name: str,
        fields_dict: dict[str, str],
    ) -> CloudCredential:
        """Encrypt *fields_dict* and persist it as a new ``CloudCredential``.

        Parameters
        ----------
        cloud_provider_id : UUID
            Foreign key to the owning cloud provider.
        credential_type : str
            e.g. ``access_key``, ``service_principal``, ``service_account``.
        credential_name : str
            Human-readable label for this credential.
        fields_dict : dict[str, str]
            Plaintext credential fields to encrypt.

        Returns
        -------
        CloudCredential
            The newly created (and flushed) ORM instance.
        """
        encrypted_blob = self._fernet.encrypt(
            json.dumps(fields_dict).encode("utf-8"),
        ).decode("utf-8")

        credential = CloudCredential(
            cloud_provider_id=cloud_provider_id,
            credential_type=credential_type,
            credential_name=credential_name,
            encrypted_data=encrypted_blob,
            is_active=True,
        )
        self.session.add(credential)
        await self.session.flush()
        await self.session.refresh(credential)
        return credential

    async def decrypt_and_parse(self, credential_id: UUID) -> ProviderCredential:
        """Retrieve and decrypt a credential by its ID.

        Parameters
        ----------
        credential_id : UUID
            The credential record's primary key.

        Returns
        -------
        ProviderCredential
            Parsed credential ready to pass to a ``CloudProvider``.

        Raises
        ------
        NotFoundException
            If the credential does not exist.
        """
        credential = await self.session.get(CloudCredential, credential_id)
        if credential is None:
            raise NotFoundException(detail=f"Credential '{credential_id}' not found")

        return self.decrypt_credential(credential)

    async def get_active_credentials_for_provider(
        self,
        cloud_provider_id: UUID,
    ) -> list[CloudCredential]:
        """Return all active (non-expired) credentials for a provider.

        Results are **still encrypted** — call :meth:`decrypt_and_parse`
        on individual credentials when needed.

        Parameters
        ----------
        cloud_provider_id : UUID
            The cloud provider's primary key.

        Returns
        -------
        list[CloudCredential]
            Active credentials for the provider.
        """
        stmt = (
            select(CloudCredential)
            .where(CloudCredential.cloud_provider_id == cloud_provider_id)
            .where(CloudCredential.is_active.is_(True))
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_decrypted_credentials_for_provider(
        self,
        cloud_provider_id: UUID,
    ) -> list[ProviderCredential]:
        """Return all active credentials for a provider, decrypted.

        This is a convenience method that combines
        :meth:`get_active_credentials_for_provider` with decryption.

        Parameters
        ----------
        cloud_provider_id : UUID
            The cloud provider's primary key.

        Returns
        -------
        list[ProviderCredential]
            Decrypted credentials ready for provider instantiation.
        """
        credentials = await self.get_active_credentials_for_provider(cloud_provider_id)
        result: list[ProviderCredential] = []
        for cred in credentials:
            try:
                result.append(self.decrypt_credential(cred))
            except Exception:
                logger.warning(
                    "Failed to decrypt credential '%s'; skipping", cred.id,
                )
                continue
        return result

    async def get_by_id(self, credential_id: UUID) -> CloudCredential:
        """Return a credential ORM instance by ID (still encrypted).

        Raises ``NotFoundException`` if not found.
        """
        credential = await self.session.get(CloudCredential, credential_id)
        if credential is None:
            raise NotFoundException(detail=f"Credential '{credential_id}' not found")
        return credential

    async def create_credential(
        self,
        cloud_provider_id: UUID,
        credential_type: str,
        credential_name: str,
        fields: dict[str, Any],
    ) -> CloudCredential:
        """Validate the provider exists, then encrypt and store a credential.

        Raises ``NotFoundException`` if the cloud provider does not exist.
        """
        # Fail fast: refuse to encrypt for a non-existent provider.
        provider = await self.session.get(CloudProvider, cloud_provider_id)
        if provider is None:
            raise NotFoundException(
                detail=f"Cloud provider '{cloud_provider_id}' not found",
            )
        return await self.encrypt_and_store(
            cloud_provider_id=cloud_provider_id,
            credential_type=credential_type,
            credential_name=credential_name,
            fields_dict=cast(dict[str, str], fields),
        )

    async def list_credentials(
        self,
        skip: int = 0,
        limit: int = 100,
        cloud_provider_id: UUID | None = None,
        active_only: bool = False,
    ) -> list[CloudCredential]:
        """Return a paginated list of credentials (still encrypted).

        Parameters
        ----------
        skip : int
            Number of records to skip (offset).
        limit : int
            Maximum number of records to return.
        cloud_provider_id : UUID | None
            Optional filter by owning cloud provider.
        active_only : bool
            If ``True``, return only credentials where ``is_active`` is ``True``.
        """
        stmt = (
            select(CloudCredential)
            .order_by(CloudCredential.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        if cloud_provider_id is not None:
            stmt = stmt.where(CloudCredential.cloud_provider_id == cloud_provider_id)
        if active_only:
            stmt = stmt.where(CloudCredential.is_active.is_(True))
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_credentials(
        self,
        cloud_provider_id: UUID | None = None,
        active_only: bool = False,
    ) -> int:
        """Return the total count of credentials, optionally filtered."""
        stmt = select(func.count(CloudCredential.id))
        if cloud_provider_id is not None:
            stmt = stmt.where(CloudCredential.cloud_provider_id == cloud_provider_id)
        if active_only:
            stmt = stmt.where(CloudCredential.is_active.is_(True))
        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def delete_credential(self, credential_id: UUID) -> None:
        """Delete a credential by ID.

        Raises ``NotFoundException`` if the credential does not exist.
        """
        # Fail fast: load and verify existence before deleting.
        credential = await self.get_by_id(credential_id)
        await self.session.delete(credential)
        await self.session.flush()

    # ── Decryption helper ─────────────────────────────────────────

    def decrypt_credential(
        self,
        credential: CloudCredential,
    ) -> ProviderCredential:
        """Decrypt a ``CloudCredential`` ORM instance and return a ``ProviderCredential``.

        Raises
        ------
        ValueError
            If the encrypted data cannot be decrypted or parsed.
        """
        if not credential.encrypted_data:
            raise ValueError(
                f"Credential '{credential.id}' has no encrypted data",
            )

        try:
            plaintext = self._fernet.decrypt(
                credential.encrypted_data.encode("utf-8"),
            )
            fields: dict[str, str] = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise ValueError(
                f"Failed to decrypt credential '{credential.id}': {exc}",
            ) from exc

        if not isinstance(fields, dict):
            raise ValueError(
                f"Decrypted credential '{credential.id}' is not a dict",
            )

        return ProviderCredential(
            credential_type=credential.credential_type,
            fields=fields,
        )
