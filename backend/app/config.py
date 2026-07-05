"""Application configuration via Pydantic Settings V2.

Uses environment variables and .env file to configure the entire application.
Parsed once at startup into a singleton; all consumers import get_settings().
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # ── App metadata ──────────────────────────────────────────────
    APP_NAME: str = "IPAM Multi-Cloud Scanner"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"

    # ── Database ──────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/ipam_scanner"
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20

    # ── Redis ─────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: str = ""

    # ── Celery ────────────────────────────────────────────────────
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # ── Security / Auth ───────────────────────────────────────────
    SECRET_KEY: str = "change-me-to-a-secure-random-string"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ENCRYPTION_KEY: str = "change-me-to-a-32-byte-encryption-key-"

    # ── CORS ──────────────────────────────────────────────────────
    # SECURITY: Wildcard origins ("*") combined with allow_credentials=True
    # is a CORS bypass vulnerability — browsers refuse credentialed wildcard
    # requests, but any origin reflecting middleware can leak credentials.
    # Always list explicit origins; override via the CORS_ORIGINS env var.
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8080",
    ]

    # ── Scanner ───────────────────────────────────────────────────
    SCAN_TIMEOUT_SECONDS: int = 300
    MAX_CONCURRENT_SCANS: int = 10
    # Age threshold (in days) for the cleanup task — scan jobs older
    # than this with a terminal status (completed/failed) are purged.
    SCAN_RETENTION_DAYS: int = 90

    # ── Rate Limiting ─────────────────────────────────────────────
    GLOBAL_RATE_LIMIT: str = "100/minute"
    AUTH_RATE_LIMIT: str = "10/minute"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton of application settings.

    Using ``lru_cache`` ensures the settings object is parsed only once
    per process lifetime, providing a single source of truth.
    """
    return Settings()  # type: ignore[call-arg]
