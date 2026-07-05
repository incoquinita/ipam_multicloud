# IPAM Multi-Cloud Security Platform — Backend

The FastAPI backend for the IPAM Multi-Cloud Security Platform. It exposes the REST + WebSocket API, manages cloud credentials with field-level encryption, orchestrates async scanning through Celery workers, and persists results in PostgreSQL.

---

## Overview

The backend is an async FastAPI application backed by PostgreSQL 16 (via SQLAlchemy 2.0 + asyncpg) and Redis 7 (Celery broker, result backend, and pub/sub for real-time progress). It follows a layered architecture: endpoints parse and validate at the boundary, services hold business logic, repositories handle data access, workers run long-running scans, and the scanner/provider engines are pure async I/O modules with no database access.

---

## Tech Stack

| Concern | Technology |
|---------|-----------|
| Web framework | FastAPI 0.115+ |
| Runtime | Python 3.12, uvicorn |
| ORM | SQLAlchemy 2.0 async (asyncpg) |
| Migrations | Alembic |
| Validation | Pydantic 2.9+ / pydantic-settings |
| Task queue | Celery 5.4+, Redis 7 |
| Scanning | python-nmap, httpx (async HTTP), custom async TCP scanner |
| Cloud SDKs | boto3 (AWS), azure-mgmt-* + azure-identity (Azure), oci (OCI), google-cloud-compute (GCP) |
| Auth | python-jose (JWT), bcrypt |
| Encryption | cryptography (Fernet) |
| Rate limiting | slowapi |
| Metrics | prometheus-fastapi-instrumentator |
| Logging | structlog |
| Testing | pytest, pytest-asyncio, pytest-cov, aiosqlite, httpx |

---

## Development Setup

### Prerequisites

- Python 3.12+
- PostgreSQL 16 (or use `docker compose up -d db`)
- Redis 7 (or use `docker compose up -d redis`)

### Install

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

The `[dev]` extra installs pytest, pytest-asyncio, pytest-cov, aiosqlite, ruff, and mypy.

### Configure

```bash
cp .env.example ../.env
# Edit ../.env:
#   DATABASE_URL=postgresql+asyncpg://ipam:ipam_pass@localhost:5432/ipam_scanner
#   REDIS_URL=redis://localhost:6379/0
#   SECRET_KEY=<strong random string>
#   ENCRYPTION_KEY=<Fernet key: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
#   ADMIN_EMAIL / ADMIN_PASSWORD
```

The application reads `.env` from the working directory. When running `uvicorn` from `backend/`, place the `.env` at the repo root (one level up) or symlink it — the `Makefile dev` target handles this.

### Run migrations

```bash
alembic upgrade head
```

Migration `005` seeds the initial superuser from `ADMIN_EMAIL` / `ADMIN_PASSWORD`. It prints a warning if the defaults are used.

### Start the app

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Interactive docs (dev only, when `DEBUG=true`): `http://localhost:8000/docs`

### Start a Celery worker

In a separate terminal:

```bash
celery -A app.workers.celery_app worker --loglevel=info \
  --queues=scans,cleanup,discovery
```

Optionally, start the beat scheduler for periodic cleanup:

```bash
celery -A app.workers.celery_app beat --loglevel=info
```

---

## Testing

```bash
cd backend
pytest -v
```

Tests are organized by layer under `tests/`:

| Directory | Coverage |
|-----------|----------|
| `test_scanner/` | `PortScanner`, `HttpAnalyzer`, `RiskClassifier`, `BannerGrabber` |
| `test_api/` | Endpoint contracts, auth flows, pagination, error responses |
| `test_services/` | `AuthService`, `CloudCredentialService`, `ScanService`, `AnalyticsService` |
| `test_repositories/` | Data access layer (against a test database) |
| `test_providers/` | `ProviderFactory` and per-provider discovery (mocked SDKs) |
| `test_workers/` | Celery task behavior, progress publishing, graceful degradation |

### Configuration

`pyproject.toml` configures pytest:

- `testpaths = ["tests"]`
- `asyncio_mode = "auto"` (no need for `@pytest.mark.asyncio` on every test)
- `addopts = "-v --cov=app --cov-report=term-missing --cov-report=xml"`

### Coverage

```bash
# Terminal + XML report (default)
pytest

# HTML report
pytest --cov-report=html && open htmlcov/index.html
```

The CI pipeline runs the full suite against PostgreSQL 16 and Redis 7 service containers with a real Fernet key.

---

## Project Structure

```
backend/
├── app/
│   ├── main.py                 # FastAPI factory + lifespan (Redis, HTTPX client)
│   ├── config.py               # Pydantic Settings (env-driven singleton)
│   ├── dependencies.py         # get_db async session dependency
│   ├── core/
│   │   ├── security.py         # JWT (access/refresh), bcrypt, Fernet encrypt/decrypt
│   │   ├── database.py         # async engine + session factory
│   │   ├── exceptions.py       # AppException hierarchy + handlers
│   │   └── logging.py          # structlog configuration
│   ├── models/                 # SQLAlchemy ORM
│   │   ├── user.py             # users
│   │   ├── cloud_provider.py   # cloud_providers
│   │   ├── cloud_credential.py # cloud_credentials (encrypted_data)
│   │   ├── scan_target.py      # scan_targets
│   │   ├── scan_job.py         # scan_jobs
│   │   ├── ip_address.py       # ip_addresses
│   │   ├── port_result.py      # port_results
│   │   ├── http_analysis.py    # http_analyses
│   │   └── scan_event.py       # scan_events (append-only audit log)
│   ├── schemas/                # Pydantic v2 request/response schemas
│   │   ├── auth.py             # UserCreate, LoginRequest, TokenResponse, TokenRefresh
│   │   ├── scan_job.py         # ScanJobCreate, ScanJobResponse, ScanStatusResponse
│   │   ├── scan_result.py      # PortResultResponse, HttpAnalysisResponse, ScanResultsResponse
│   │   ├── scan_profiles.py    # named scan profiles (quick/standard/thorough/custom)
│   │   ├── scan_target.py      # ScanTarget CRUD schemas
│   │   ├── cloud_provider.py   # CloudProvider CRUD schemas
│   │   ├── credentials.py      # CredentialCreate, CredentialResponse (no encrypted blob)
│   │   ├── analytics.py        # DashboardStats, ScanTimeline, PortDistribution, RiskSummary
│   │   ├── ip_address.py       # IPAddress list/response
│   │   ├── port_result.py      # PortResult list response
│   │   └── common.py           # enums (ScanType, RiskLevel, PortState, ...) + PaginatedResponse
│   ├── scanner/
│   │   ├── port_scanner.py     # async TCP scanner with semaphore concurrency
│   │   ├── http_analyzer.py    # static/login/rate-limit/headers/tech/TLS analysis
│   │   ├── risk_classifier.py  # score + severity (CRITICAL/HIGH/MEDIUM/LOW)
│   │   └── banner_grabber.py   # service banner grabbing
│   ├── providers/
│   │   ├── base.py             # CloudProvider ABC + DiscoveredIP/SecurityRule/LBEndpoint
│   │   ├── factory.py          # provider-type → concrete class
│   │   ├── aws_provider.py     # boto3 (EC2, EIPs, NAT GW, LBs)
│   │   ├── azure_provider.py   # azure-mgmt-network/resource/identity
│   │   ├── oci_provider.py     # oci SDK (VNICs, LBs)
│   │   ├── gcp_provider.py     # google-cloud-compute
│   │   └── retry.py            # transient failure retry helper
│   ├── services/
│   │   ├── auth_service.py             # register, authenticate, token lifecycle
│   │   ├── scan_service.py             # scan job creation + dispatch
│   │   ├── scan_result_service.py      # sync result persistence (used by workers)
│   │   ├── credential_service.py       # Fernet encrypt/decrypt + CRUD
│   │   ├── cloud_service.py            # cloud provider CRUD
│   │   ├── target_service.py           # scan target CRUD
│   │   └── analytics_service.py        # aggregation queries
│   ├── repositories/
│   │   ├── base.py
│   │   ├── scan_repository.py
│   │   ├── target_repository.py
│   │   ├── cloud_repository.py
│   │   ├── ip_address_repository.py
│   │   └── port_result_repository.py
│   ├── workers/
│   │   ├── celery_app.py       # Celery instance, queue topology, time limits
│   │   ├── scan_tasks.py       # run_port_scan, run_http_analysis, progress publishing
│   │   ├── discovery_tasks.py  # run_cloud_discovery
│   │   └── cleanup_tasks.py    # retention-based cleanup
│   ├── middleware/
│   │   ├── security_headers.py # HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy
│   │   ├── rate_limit.py       # slowapi limiter + global default
│   │   └── request_id.py       # per-request correlation ID
│   ├── api/
│   │   ├── deps.py             # oauth2_scheme → get_current_user → active → superuser
│   │   └── v1/
│   │       ├── router.py       # aggregates all endpoint routers under /api/v1
│   │       └── endpoints/      # auth, scans, targets, cloud_providers, credentials,
│   │                           #   discovery, analytics, ip_addresses, port_results, health, ws
│   └── __init__.py
├── alembic/
│   ├── env.py
│   └── versions/               # 001_initial_schema ... 005_seed_admin_user
├── tests/
├── Dockerfile                  # Multi-stage FastAPI image (non-root appuser)
├── Dockerfile.celery           # Celery worker image (scans, cleanup, discovery queues)
├── pyproject.toml              # dependencies, ruff, mypy, pytest config
├── requirements.txt
├── alembic.ini
└── .env.example
```

---

## Environment Variables

See `.env.example` for the full reference. The most important variables:

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | SQLAlchemy async URL (`postgresql+asyncpg://...`) |
| `REDIS_URL` | Redis URL (broker, results, pub/sub) |
| `CELERY_BROKER_URL` / `CELERY_RESULT_BACKEND` | Celery broker + result backend |
| `SECRET_KEY` | JWT signing key (≥32 random chars) |
| `ENCRYPTION_KEY` | Fernet key for credential encryption |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Seeded superuser (migration `005`) |
| `CORS_ORIGINS` | Explicit allowed origins (no wildcard with credentials) |
| `DEBUG` | Enables docs + disables rate limiting |
| `GLOBAL_RATE_LIMIT` / `AUTH_RATE_LIMIT` | slowapi limits |
| `SCAN_TIMEOUT_SECONDS` / `MAX_CONCURRENT_SCANS` / `SCAN_RETENTION_DAYS` | Scanner tuning |

See [docs/deployment.md](../docs/deployment.md#environment-configuration) for the complete table.

---

## API Documentation

The full REST + WebSocket API reference is in [docs/api.md](../docs/api.md). In development (with `DEBUG=true`), interactive Swagger UI is available at `http://localhost:8000/docs` and ReDoc at `http://localhost:8000/redoc`. The OpenAPI JSON is at `http://localhost:8000/openapi.json`. All three are disabled when `DEBUG=false`.

---

## Linting & Type Checking

```bash
ruff check .            # lint
ruff format --check .   # format check
ruff check --fix . && ruff format .   # auto-fix + format
mypy app --no-strict-optional   # type check
```

`pyproject.toml` configures ruff (`target-version = "py312"`, `line-length = 100`, rules `E/F/I/N/W/UP/B/SIM/ARG/C4`) and mypy (`python_version = "3.12"`, strict with per-module ignores for the cloud SDKs). Pre-commit hooks run these before each commit.

---

## Related Documentation

- [Root README](../README.md) — project overview and quick start
- [Architecture](../docs/architecture.md) — system design, data flow, database schema
- [Security](../docs/security.md) — encryption, auth, rate limiting, TLS
- [API reference](../docs/api.md) — full REST + WebSocket contract
- [Deployment](../docs/deployment.md) — Docker Compose, TLS, nginx, hardening
- [Metrics](../docs/metrics.md) — success metrics, Prometheus, Grafana, alerting
