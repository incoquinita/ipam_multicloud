#!/usr/bin/env python3
"""Initialize the PostgreSQL database for the IPAM Multi-Cloud Scanner.

Usage:
    python scripts/init_db.py

This script:
    1. Reads the DATABASE_URL from the application config.
    2. Connects to the default ``postgres`` database to check if the
       target database exists, creating it if needed.
    3. Runs ``alembic upgrade head`` to apply all pending migrations.
    4. Exits with a non-zero status on failure.

Environment:
    All settings (including ``DATABASE_URL``) are read from the
    application's ``Settings`` object, which supports ``.env`` file
    and environment variable overrides.
"""

import subprocess
import sys
from urllib.parse import urlparse

import asyncpg

from app.config import get_settings


def _parse_db_url(url: str) -> dict:
    """Parse a ``postgresql+asyncpg://`` URL into connection components.

    Returns:
        A dict with keys ``user``, ``password``, ``host``, ``port``, and
        ``database``.  Raises ``ValueError`` if the URL scheme is not
        recognised.
    """
    if not url.startswith("postgresql"):
        raise ValueError(
            f"Unsupported DATABASE_URL scheme: {url.split('://')[0]}://. "
            f"Expected postgresql+asyncpg://"
        )

    # Strip the driver suffix (e.g. ``+asyncpg``) so urlparse handles it.
    clean_url = url.replace("+asyncpg", "", 1)
    parsed = urlparse(clean_url)

    return {
        "user": parsed.username or "postgres",
        "password": parsed.password or "",
        "host": parsed.hostname or "localhost",
        "port": parsed.port or 5432,
        "database": parsed.path.lstrip("/") or "ipam_scanner",
    }


async def ensure_database_exists(conn_info: dict) -> None:
    """Connect to the default ``postgres`` database and create the target
    database if it does not already exist.

    Side effect:
        Creates a new database on the PostgreSQL server.
    """
    # Connect to the maintenance database (``postgres``) which always
    # exists on a running PostgreSQL instance.
    sys_conn = await asyncpg.connect(
        user=conn_info["user"],
        password=conn_info["password"],
        host=conn_info["host"],
        port=conn_info["port"],
        database="postgres",
    )

    try:
        db_name = conn_info["database"]
        # Check for existence via ``pg_database`` catalogue.
        row = await sys_conn.fetchrow(
            "SELECT 1 FROM pg_database WHERE datname = $1", db_name,
        )
        if row is None:
            print(f"Creating database '{db_name}' ...")
            # ``CREATE DATABASE`` cannot run inside a transaction block.
            await sys_conn.execute(f'CREATE DATABASE "{db_name}"')
            print(f"Database '{db_name}' created.")
        else:
            print(f"Database '{db_name}' already exists — skipping creation.")
    finally:
        await sys_conn.close()


def run_alembic_upgrade() -> None:
    """Run ``alembic upgrade head`` as a subprocess.

    Raises:
        ``SystemExit`` if the Alembic command returns a non-zero exit
        code.
    """
    print("Running: alembic upgrade head ...")
    result = subprocess.run(
        ["alembic", "upgrade", "head"],
        capture_output=False,
    )
    if result.returncode != 0:
        print("ERROR: Alembic migration failed.", file=sys.stderr)
        sys.exit(result.returncode)
    print("Alembic migrations applied successfully.")


def main() -> None:
    """Entry point — orchestrates database creation and migration."""
    settings = get_settings()
    url = settings.DATABASE_URL

    print(f"Target database URL: {url}")

    try:
        conn_info = _parse_db_url(url)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        import asyncio
        asyncio.run(ensure_database_exists(conn_info))
    except Exception as exc:
        print(f"ERROR: Failed to create database: {exc}", file=sys.stderr)
        sys.exit(1)

    run_alembic_upgrade()

    print("Database initialization complete.")


if __name__ == "__main__":
    main()
