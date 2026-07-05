"""Celery task definitions for cloud provider discovery.

Dispatches async cloud-provider discovery calls (IP addresses, security
rules, load balancers) inside a Celery worker, persists discovered IPs
to the ``ip_addresses`` table, and publishes progress via Redis pub/sub
for WebSocket / SSE consumers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any
from uuid import UUID

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, selectinload, sessionmaker

from app.config import get_settings
from app.models.cloud_credential import CloudCredential
from app.models.cloud_provider import CloudProvider
from app.models.ip_address import IPAddress
from app.providers.base import (
    CloudProvider as CloudProviderABC,
)
from app.providers.base import DiscoveredIP, LBEndpoint, ProviderCredential, SecurityRule
from app.providers.factory import get_provider
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


# ── Sync session helpers ────────────────────────────────────────────


def _make_sync_session() -> sessionmaker[Session]:
    """Build a sync SQLAlchemy session factory for the worker.

    Mirrors the pattern in ``cleanup_tasks`` and ``scan_result_service``:
    take the async ``DATABASE_URL`` and strip the async driver suffix so
    the sync engine can connect from the Celery worker process.
    """
    settings = get_settings()
    sync_url = (
        settings.DATABASE_URL
        .replace("postgresql+asyncpg", "postgresql")
        .replace("postgresql+psycopg", "postgresql")
    )
    engine = create_engine(sync_url, pool_pre_ping=True)
    return sessionmaker(bind=engine)


# ── Credential decryption ───────────────────────────────────────────


def _build_fernet() -> Any:
    """Build a Fernet instance from the application's encryption key.

    Replicates the logic in ``CloudCredentialService._build_fernet`` so
    this module can decrypt credentials from a sync worker process
    without constructing an async ``CloudCredentialService``.
    """
    import base64
    import hashlib

    from cryptography.fernet import Fernet

    raw_key = get_settings().ENCRYPTION_KEY
    try:
        return Fernet(raw_key.encode() if isinstance(raw_key, str) else raw_key)
    except (ValueError, TypeError):
        digest = hashlib.sha256(raw_key.encode()).digest()
        return Fernet(base64.urlsafe_b64encode(digest))


def _decrypt_credential(cred: CloudCredential) -> ProviderCredential:
    """Decrypt a ``CloudCredential`` and return a parsed ``ProviderCredential``.

    Raises
    ------
    ValueError
        If the encrypted data cannot be decrypted or parsed as a dict.
    """
    if not cred.encrypted_data:
        raise ValueError(f"Credential '{cred.id}' has no encrypted data")

    fernet = _build_fernet()
    try:
        plaintext = fernet.decrypt(cred.encrypted_data.encode("utf-8"))
        fields: dict[str, str] = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise ValueError(
            f"Failed to decrypt credential '{cred.id}': {exc}",
        ) from exc

    if not isinstance(fields, dict):
        raise ValueError(f"Decrypted credential '{cred.id}' is not a dict")

    return ProviderCredential(
        credential_type=cred.credential_type,
        fields=fields,
    )


# ── Progress publishing ─────────────────────────────────────────────


def publish_progress(
    job_id: str,
    progress: float,
    status: str,
    message: str = "",
    data: dict[str, Any] | None = None,
) -> None:
    """Publish a progress update to Redis for SSE / WS consumers.

    Writes a JSON payload with an expiry of 10 minutes and publishes it
    on the ``discovery:progress:{job_id}`` channel — the same pattern
    used by :func:`app.workers.scan_tasks.publish_progress`.
    """
    import redis as sync_redis

    r = sync_redis.from_url(celery_app.conf.result_backend)
    try:
        payload = {
            "job_id": job_id,
            "status": status,
            "progress": round(progress, 2),
            "message": message,
            "data": data or {},
            "timestamp": time.time(),
        }
        channel = f"discovery:progress:{job_id}"
        r.setex(channel, 600, json.dumps(payload))
        r.publish(channel, json.dumps(payload))
    except Exception as exc:
        logger.warning("Failed to publish progress for %s: %s", job_id, exc)
    finally:
        r.close()


# ── Provider loading ────────────────────────────────────────────────


def _load_provider_with_credentials(
    session: Session,
    provider_id: str,
) -> CloudProvider | None:
    """Load a cloud provider and its credentials eagerly.

    Returns ``None`` if the provider does not exist.
    """
    stmt = (
        select(CloudProvider)
        .where(CloudProvider.id == provider_id)
        .options(selectinload(CloudProvider.credentials))
    )
    return session.scalars(stmt).first()


# ── Async discovery helpers ─────────────────────────────────────────


async def _run_provider_discovery(
    provider: CloudProviderABC,
) -> tuple[list[DiscoveredIP], list[SecurityRule], list[LBEndpoint], list[str]]:
    """Call all three discovery methods in one event loop.

    Each phase is independent — a failure in one does not lose the
    results of the others.  Returns the partial results plus a list of
    per-phase error messages.
    """
    ips: list[DiscoveredIP] = []
    rules: list[SecurityRule] = []
    lbs: list[LBEndpoint] = []
    errors: list[str] = []

    try:
        ips = await provider.discover_ip_addresses()
    except Exception as exc:
        errors.append(f"IP discovery failed: {exc}")
        logger.exception("IP discovery failed")

    try:
        rules = await provider.discover_security_rules()
    except Exception as exc:
        errors.append(f"Security rule discovery failed: {exc}")
        logger.exception("Security rule discovery failed")

    try:
        lbs = await provider.discover_load_balancers()
    except Exception as exc:
        errors.append(f"Load balancer discovery failed: {exc}")
        logger.exception("Load balancer discovery failed")

    return ips, rules, lbs, errors


def _collect_all_ips(
    ips: list[DiscoveredIP],
    lbs: list[LBEndpoint],
) -> list[DiscoveredIP]:
    """Merge discovered IPs and load-balancer endpoints into one list.

    Load-balancer endpoints with a non-empty ``ip_address`` are promoted
    to :class:`DiscoveredIP` instances so they get persisted alongside
    the provider IPs.  Deduplicates by ``ip_address`` string.
    """
    seen: set[str] = set()
    merged: list[DiscoveredIP] = []

    for dip in ips:
        if not dip.ip_address or dip.ip_address in seen:
            continue
        seen.add(dip.ip_address)
        merged.append(dip)

    for lb in lbs:
        if not lb.ip_address or lb.ip_address in seen:
            continue
        seen.add(lb.ip_address)
        merged.append(
            DiscoveredIP(
                ip_address=lb.ip_address,
                resource_type="load_balancer",
                hostname=lb.name or None,
                tags={
                    "protocol": lb.protocol or "",
                    "port_range": lb.port_range or "",
                },
            ),
        )

    return merged


# ── Persistence ─────────────────────────────────────────────────────


def _persist_discovered_ips(
    session: Session,
    ips: list[DiscoveredIP],
    provider_id: UUID,
) -> int:
    """Upsert discovered IPs into the ``ip_addresses`` table.

    For each IP: if a record with the same ``ip_address`` AND
    ``cloud_provider_id`` already exists, update ``last_seen_at`` and
    fill any missing metadata.  Otherwise insert a new row.

    Returns the number of newly inserted rows.
    """
    from datetime import UTC, datetime

    inserted = 0
    for dip in ips:
        # Guard: skip entries without an IP string.
        if not dip.ip_address:
            continue

        existing = session.scalar(
            select(IPAddress).where(
                IPAddress.ip_address == dip.ip_address,
                IPAddress.cloud_provider_id == provider_id,
            ),
        )

        if existing is not None:
            existing.last_seen_at = datetime.now(UTC)
            if not existing.resource_type and dip.resource_type:
                existing.resource_type = dip.resource_type
            if not existing.region and dip.region:
                existing.region = dip.region
            if not existing.hostname and dip.hostname:
                existing.hostname = dip.hostname
            if not existing.private_ip and dip.private_ip:
                existing.private_ip = dip.private_ip
            if not existing.resource_id and dip.resource_id:
                existing.resource_id = dip.resource_id
            continue

        session.add(
            IPAddress(
                ip_address=dip.ip_address,
                private_ip=dip.private_ip,
                resource_id=dip.resource_id,
                resource_type=dip.resource_type,
                region=dip.region,
                hostname=dip.hostname,
                tags=dip.tags,
                cloud_provider_id=provider_id,
            ),
        )
        inserted += 1

    return inserted


# ── Summary helper ──────────────────────────────────────────────────


def _summary(
    ips_discovered: int,
    security_rules_found: int,
    load_balancers_found: int,
    errors: list[str],
) -> dict[str, Any]:
    """Build the standard discovery summary dict returned by the task."""
    return {
        "ips_discovered": ips_discovered,
        "security_rules_found": security_rules_found,
        "load_balancers_found": load_balancers_found,
        "errors": errors,
    }


# ── Discovery task ──────────────────────────────────────────────────


@celery_app.task(  # type: ignore[untyped-decorator]
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    acks_late=True,
    reject_on_worker_lost=True,
    track_started=True,
    queue="discovery",
)
def run_cloud_discovery(  # type: ignore[no-untyped-def]
    self,
    provider_id: str,
) -> dict[str, Any]:
    """Run cloud discovery for a single provider and persist results.

    Loads the provider's credentials from the database, instantiates the
    matching :class:`CloudProvider` via the factory, calls the three
    async discovery methods (IPs, security rules, load balancers) inside
    a single event loop, upserts discovered IPs into ``ip_addresses``,
    and publishes progress on ``discovery:progress:{job_id}``.

    Parameters
    ----------
    provider_id : str
        UUID string of the ``CloudProvider`` to discover.

    Returns
    -------
    dict
        Summary with ``ips_discovered``, ``security_rules_found``,
        ``load_balancers_found``, and ``errors`` keys.
    """
    job_id = self.request.id
    publish_progress(job_id, 0, "started", "Discovery dispatched")

    session_factory = _make_sync_session()
    session = session_factory()

    errors: list[str] = []
    ips_discovered = 0
    security_rules_found = 0
    load_balancers_found = 0

    try:
        # ── Load provider ───────────────────────────────────────────
        provider = _load_provider_with_credentials(session, provider_id)
        if provider is None:
            msg = f"Provider '{provider_id}' not found"
            logger.error(msg)
            publish_progress(job_id, 100, "failed", msg)
            return _summary(0, 0, 0, [msg])

        if not provider.is_active:
            msg = f"Provider '{provider.name}' is not active"
            logger.warning(msg)
            publish_progress(job_id, 100, "failed", msg)
            return _summary(0, 0, 0, [msg])

        active_credentials = [c for c in provider.credentials if c.is_active]
        if not active_credentials:
            msg = f"Provider '{provider.name}' has no active credentials"
            logger.warning(msg)
            publish_progress(job_id, 100, "failed", msg)
            return _summary(0, 0, 0, [msg])

        publish_progress(
            job_id, 10, "running",
            f"Discovering via {len(active_credentials)} credential(s) "
            f"for '{provider.name}'",
        )

        # ── Decrypt credentials and run discovery per credential ──
        all_ips: list[DiscoveredIP] = []
        seen_ip_keys: set[str] = set()

        for cred in active_credentials:
            try:
                parsed = _decrypt_credential(cred)
            except Exception as exc:
                msg = f"Credential '{cred.credential_name}' decryption failed: {exc}"
                logger.warning(msg)
                errors.append(msg)
                continue

            try:
                provider_instance = get_provider(provider.provider_type, parsed)
            except Exception as exc:
                msg = f"Failed to instantiate {provider.provider_type} provider: {exc}"
                logger.exception(msg)
                errors.append(msg)
                continue

            try:
                ips, rules, lbs, phase_errors = asyncio.run(
                    _run_provider_discovery(provider_instance),
                )
            except Exception as exc:
                msg = f"Discovery call failed for '{provider.name}': {exc}"
                logger.exception(msg)
                errors.append(msg)
                continue

            errors.extend(phase_errors)

            # Merge IPs and LB endpoints, deduplicating by ip_address.
            merged = _collect_all_ips(ips, lbs)
            for dip in merged:
                if dip.ip_address in seen_ip_keys:
                    continue
                seen_ip_keys.add(dip.ip_address)
                all_ips.append(dip)

            security_rules_found += len(rules)
            load_balancers_found += len(lbs)

        publish_progress(
            job_id, 70, "running",
            f"Discovered {len(all_ips)} unique IP(s); persisting",
            {"ips_pending_persist": len(all_ips)},
        )

        # ── Persist discovered IPs ─────────────────────────────────
        try:
            inserted = _persist_discovered_ips(session, all_ips, provider.id)
            session.commit()
            ips_discovered = inserted
            logger.info(
                "Persisted %d new IP(s) for provider '%s' (total seen: %d)",
                inserted, provider.name, len(all_ips),
            )
        except Exception as exc:
            session.rollback()
            msg = f"Failed to persist discovered IPs: {exc}"
            logger.exception(msg)
            errors.append(msg)

        publish_progress(
            job_id, 100, "complete",
            f"Discovery complete — {ips_discovered} new IP(s), "
            f"{security_rules_found} security rule(s), "
            f"{load_balancers_found} load balancer(s)",
        )

        return _summary(
            ips_discovered, security_rules_found, load_balancers_found, errors,
        )

    except Exception as exc:
        session.rollback()
        logger.exception("Fatal error in discovery job %s: %s", job_id, exc)
        errors.append(f"Fatal error: {exc}")
        publish_progress(job_id, 100, "error", f"Discovery failed: {exc}")
        return _summary(0, 0, 0, errors)

    finally:
        session.close()
