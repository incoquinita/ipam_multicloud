# Deployment

This document covers deploying the IPAM Multi-Cloud Security Platform with Docker Compose, configuring environment variables, generating TLS certificates, setting up the nginx reverse proxy, hardening production, managing secrets, backing up, and monitoring.

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) 24 or newer
- [Docker Compose](https://docs.docker.com/compose/install/) v2 or newer
- TLS certificate pair (`cert.pem` + `key.pem`) for nginx termination
- A Fernet key for credential encryption (see [Secret Management](#secret-management))
- A strong `SECRET_KEY` for JWT signing
- Outbound network access to your cloud providers' APIs (AWS, Azure, OCI, GCP)

---

## Docker Compose Deployment

The stack is defined in `docker-compose.yml` with six services:

| Service | Container | Purpose | Profile |
|---------|-----------|---------|---------|
| `app` | `ipam-app` | FastAPI application (uvicorn) | default |
| `celery_worker` | `ipam-celery-worker` | Scan + discovery + cleanup workers | default |
| `celery_beat` | `ipam-celery-beat` | Periodic task scheduler | `scheduler` |
| `db` | `ipam-db` | PostgreSQL 16 | default |
| `redis` | `ipam-redis` | Redis 7 (broker, results, pub/sub) | default |
| `frontend` | `ipam-frontend` | nginx-served React SPA (TLS termination) | `frontend` |

The `app`, `db`, `redis`, and `celery_worker` services start with a plain `docker compose up -d`. The `celery_beat` and `frontend` services are profile-gated — they start only when you pass `--profile scheduler` and `--profile frontend` respectively.

### Step-by-step

```bash
# 1. Clone and enter the project
git clone <repo-url> ipam_multicloud
cd ipam_multicloud

# 2. Create your environment file
cp backend/.env.example .env

# 3. Generate secrets and edit .env (see Secret Management below)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Set: SECRET_KEY, ENCRYPTION_KEY, ADMIN_EMAIL, ADMIN_PASSWORD, CORS_ORIGINS

# 4. Provision TLS certificates (see TLS section below)
mkdir -p nginx/certs
openssl req -x509 -newkey rsa:4096 -nodes -keyout nginx/certs/key.pem \
  -out nginx/certs/cert.pem -days 365 -subj "/CN=scanner.example.com"

# 5. Build all images
docker compose build

# 6. Start the core stack (app, workers, db, redis)
docker compose up -d

# 7. Run database migrations (seeds the admin user from ADMIN_EMAIL/ADMIN_PASSWORD)
docker compose exec app alembic upgrade head

# 8. (Optional) Start the scheduler and frontend
docker compose --profile scheduler up -d celery_beat
docker compose --profile frontend up -d frontend

# 9. Verify
curl -sk https://localhost/api/v1/health
docker compose ps
```

### Health checks

The `app`, `db`, and `redis` services define Docker health checks. `app` depends on `db` and `redis` being healthy before starting (`condition: service_healthy`). The `app` health check hits `/api/v1/health`.

### Stopping and cleaning up

```bash
docker compose down              # stop and remove containers
docker compose down -v           # also remove pgdata and redisdata volumes
docker compose --profile scheduler --profile frontend down  # stop everything
```

---

## Environment Configuration

All configuration is driven by environment variables read from `.env` at the project root. The defaults live in `app/config.py` (`Settings`); the `.env.example` documents every variable.

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | `IPAM Multi-Cloud Scanner` | Application title (shown in OpenAPI). |
| `APP_VERSION` | `1.0.0` | Application version (reported by `/health`). |
| `DEBUG` | `false` | Enables `/docs`, `/redoc`, `/openapi.json`; disables rate limiting. Set `false` in production. |
| `ENVIRONMENT` | `production` | Environment label reported by `/health`. |
| `DATABASE_URL` | `postgresql+asyncpg://...` | SQLAlchemy async URL. Use `asyncpg` driver. |
| `DATABASE_POOL_SIZE` | `10` | Connection pool size. |
| `DATABASE_MAX_OVERFLOW` | `20` | Max overflow beyond pool size. |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis URL for pub/sub and shared client. |
| `REDIS_PASSWORD` | `` | Redis password (empty = no auth). |
| `CELERY_BROKER_URL` | `redis://localhost:6379/0` | Celery broker. |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/1` | Celery result backend. |
| `SECRET_KEY` | `change-me-...` | JWT signing key. Use ≥32 random characters. |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token lifetime setting (auth service uses 15 min). |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime. |
| `ENCRYPTION_KEY` | `change-me-...` | Fernet key for credential encryption. Generate with `Fernet.generate_key()`. |
| `ADMIN_EMAIL` | `admin@ipam.local` | Seeded admin email (migration `005`). **Change in production.** |
| `ADMIN_PASSWORD` | `ChangeMe123!` | Seeded admin password (migration `005`). **Change in production.** |
| `CORS_ORIGINS` | `["http://localhost:5173","http://localhost:3000","http://localhost:8080"]` | Explicit allowed origins. Never use `["*"]` with credentials. |
| `SCAN_TIMEOUT_SECONDS` | `300` | Scan timeout. |
| `MAX_CONCURRENT_SCANS` | `10` | Max concurrent scans. |
| `SCAN_RETENTION_DAYS` | `90` | Age threshold for cleanup task. |
| `GLOBAL_RATE_LIMIT` | `100/minute` | slowapi global default. |
| `AUTH_RATE_LIMIT` | `10/minute` | slowapi auth route default. |
| `POSTGRES_DB` | `ipam_scanner` | PostgreSQL database name (used by the `db` service). |
| `POSTGRES_USER` | `ipam` | PostgreSQL user (used by the `db` service). |
| `POSTGRES_PASSWORD` | — | PostgreSQL password (used by the `db` service). **Set a strong value.** |
| `POSTGRES_HOST` | `db` | PostgreSQL host (Docker service name). |
| `POSTGRES_PORT` | `5432` | PostgreSQL port. |

> The Docker Compose `.env` is shared by the `app`, `celery_worker`, and `celery_beat` services via `env_file: .env`. Keep `DEBUG=true` only for local development.

---

## TLS Certificate Generation

TLS terminates at nginx, which expects `cert.pem` and `key.pem` mounted at `/etc/nginx/certs/`. Both the top-level `nginx/nginx.conf` (standalone reverse proxy) and `frontend/nginx.conf` (frontend container) read from this path.

### Self-signed (development)

```bash
mkdir -p nginx/certs
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout nginx/certs/key.pem \
  -out nginx/certs/cert.pem \
  -days 365 \
  -subj "/CN=localhost"
```

Add `CN=localhost` (or your dev hostname) so the browser warning is the only friction. Browsers will warn about the self-signed cert — accept it for local testing.

### Let's Encrypt (production)

For a real deployment with a public hostname, use certbot to obtain and renew certificates:

```bash
# Install certbot
sudo apt-get install -y certbot

# Obtain a certificate (stop nginx first so port 80 is free, or use webroot)
sudo certbot certonly --standalone -d scanner.example.com

# Copy the certificates into nginx/certs/
sudo cp /etc/letsencrypt/live/scanner.example.com/fullchain.pem nginx/certs/cert.pem
sudo cp /etc/letsencrypt/live/scanner.example.com/privkey.pem   nginx/certs/key.pem
chmod 644 nginx/certs/cert.pem
chmod 600 nginx/certs/key.pem
```

Set up a renewal hook (or a cron job running `certbot renew --post-hook "docker compose restart frontend"`) to reload nginx after renewal. Certbot certificates expire after 90 days.

---

## Nginx Reverse Proxy Setup

The platform ships two nginx configurations:

1. **`nginx/nginx.conf`** — a standalone reverse proxy that terminates TLS, proxies `/api/` and `/ws/` to the FastAPI backend, and serves the frontend static files (or a separate static host). Use this when you run nginx as its own container or host process.
2. **`frontend/nginx.conf`** — baked into the frontend Docker image (`nginx:alpine`); terminates TLS, serves the Vite production build with SPA fallback, and reverse-proxies `/api/` and `/ws/` to `app:8000`. Use this when you run the `frontend` compose service.

### Key directives (both configs)

| Concern | Configuration |
|---------|---------------|
| HTTP→HTTPS redirect | `server { listen 80; return 301 https://$host$request_uri; }` |
| TLS protocols | `ssl_protocols TLSv1.2 TLSv1.3;` (1.0/1.1 disabled) |
| Ciphers | `ssl_ciphers HIGH:!aNULL:!MD5; ssl_prefer_server_ciphers on;` |
| Security headers | `HSTS`, `X-Content-Type-Options nosniff`, `X-Frame-Options DENY`, `X-XSS-Protection`, `Referrer-Policy` — all with `always` |
| API proxy | `/api/` → `http://backend` (or `http://ipam_backend`); `proxy_read_timeout 300s` for long scans |
| WebSocket proxy | `/ws/` → backend with `proxy_http_version 1.1`, `Upgrade`/`Connection: upgrade`, `proxy_read_timeout 86400s` for long-lived connections |
| SPA fallback | `try_files $uri $uri/ /index.html;` so client-side routes resolve on refresh |
| Static caching | `/assets/` → `expires 1y; Cache-Control public, immutable`; `index.html` → `no-cache` |
| Body size | `client_max_body_size 10M` for large scan configs |

### WebSocket proxy specifics

WebSocket connections require the upgrade handshake headers and a long read timeout (24 hours), since progress streams are long-lived:

```nginx
location /ws/ {
    proxy_pass http://backend;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 86400s;
}
```

---

## Production Hardening Checklist

Run through this checklist before exposing the platform to any non-local network.

- [ ] **Change default admin credentials.** Set `ADMIN_EMAIL` and `ADMIN_PASSWORD` to strong, unique values before running `alembic upgrade head`. Migration `005` prints a loud warning when defaults are used.
- [ ] **Generate a real Fernet key.** Set `ENCRYPTION_KEY` to the output of `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Store it in a secret manager; rotating it invalidates all encrypted credentials.
- [ ] **Generate a strong `SECRET_KEY`.** Use ≥32 random characters (e.g. `python -c "import secrets; print(secrets.token_urlsafe(48))"`). Never reuse the dev default.
- [ ] **Set `DEBUG=false`.** Disables `/docs`, `/redoc`, `/openapi.json` and enables rate limiting.
- [ ] **Set `ENVIRONMENT=production`.**
- [ ] **Restrict `CORS_ORIGINS`.** List only the exact frontend origin(s) you serve from. Never use `["*"]` with `allow_credentials=True`.
- [ ] **Use real TLS certificates.** Provision via Let's Encrypt or your CA. Self-signed certs are for development only.
- [ ] **Configure a firewall.** Allow only ports 80 (redirect) and 443 (HTTPS). Do not expose PostgreSQL (5432) or Redis (6379) to the public internet — the compose file maps them for local dev convenience; remove the host port mappings or bind to `127.0.0.1` in production.
- [ ] **Restrict cloud credentials to read-only.** Discovery only needs read access to enumerate IPs and security groups. Use least-privilege IAM roles.
- [ ] **Set up monitoring and alerting.** Scrape `/metrics` with Prometheus and configure alerts (see [metrics.md](metrics.md#alerting-recommendations)).
- [ ] **Configure log aggregation.** The app emits structured JSON logs via structlog; ship them to your log platform.
- [ ] **Set `SCAN_RETENTION_DAYS`** to match your data-retention policy.
- [ ] **Run containers as the non-root user.** The backend Dockerfiles already create and switch to `appuser` (UID 1001); do not override `USER` in production.

---

## Secret Management

The platform requires three secrets at minimum:

### 1. Fernet encryption key (`ENCRYPTION_KEY`)

Used to encrypt cloud credentials at the field level. Must be a valid Fernet key (32 URL-safe base64 bytes):

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

If the value is not a valid Fernet key, a key is derived via SHA-256 — this is a development convenience only. **Always use a real Fernet key in production.** Keep a backup: without this exact key, all encrypted credentials are unrecoverable.

### 2. JWT signing key (`SECRET_KEY`)

Used to sign and verify JWT access and refresh tokens:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Rotating `SECRET_KEY` invalidates all outstanding tokens (users must re-authenticate).

### 3. Admin credentials (`ADMIN_EMAIL` / `ADMIN_PASSWORD`)

Read by Alembic migration `005` to seed the initial superuser. The password is bcrypt-hashed at migration time. Set these before the first `alembic upgrade head` and change them immediately via the UI or API after first login if you could not set them before migration.

### Storing secrets

- **Do not** commit `.env` to version control (it is gitignored).
- For production, inject secrets via your orchestrator's secret mechanism (Docker Swarm secrets, Kubernetes secrets, AWS Secrets Manager, Vault, etc.) rather than a plaintext `.env` file.
- Rotate `ENCRYPTION_KEY` and `SECRET_KEY` periodically and after any suspected compromise.

---

## Backup Strategy

### PostgreSQL

The `pgdata` named volume persists the database across container restarts. Take regular logical backups with `pg_dump`:

```bash
# Backup
docker compose exec -T db pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > backup_$(date +%F).sql

# Restore
cat backup_2026-06-19.sql | docker compose exec -T db psql -U "$POSTGRES_USER" "$POSTGRES_DB"
```

Schedule this with cron or your orchestrator's job runner. For larger deployments, consider WAL archiving (`pg_basebackup` + continuous archiving) for point-in-time recovery.

### Redis

Redis is used as a transient broker and pub/sub channel — it does not store durable application state. The `redisdata` volume persists the RDB snapshot, but losing Redis only drops in-flight task state and cached progress messages; scan results are persisted in PostgreSQL. No routine Redis backup is required, though the default RDB snapshotting is retained for fast broker recovery.

### Encryption key backup

The `ENCRYPTION_KEY` is the single most critical secret: without it, all encrypted cloud credentials are unrecoverable. Store it in a secure, backed-up location (secret manager, offline backup) separate from the application deployment.

---

## Monitoring

### Prometheus metrics

The FastAPI app exposes Prometheus metrics at `/metrics` via `prometheus-fastapi-instrumentator`. No authentication is required on this endpoint so Prometheus can scrape it freely.

```yaml
# prometheus.yml scrape config
scrape_configs:
  - job_name: ipam_app
    metrics_path: /metrics
    static_configs:
      - targets: ["app:8000"]  # or your nginx host if scraping through the proxy
```

Default instrumented metrics include:

- `http_requests_total` — request counter labeled by `method`, `handler`, `status`
- `http_request_duration_seconds` — latency histogram labeled by `method`, `handler`, `status`
- `http_in_progress_requests` — in-progress request gauge

### Grafana dashboard

Build a Grafana dashboard on top of the Prometheus datasource. Recommended panels:

1. **Request rate** — `rate(http_requests_total[5m])` by status code
2. **p50 / p95 / p99 latency** — histogram quantiles of `http_request_duration_seconds`
3. **Error rate** — `rate(http_requests_total{status=~"5.."}[5m])`
4. **In-progress requests** — `http_in_progress_requests`
5. **Scan throughput** — query `scan_jobs` via a custom exporter or the `/api/v1/analytics/timeline` endpoint
6. **Open findings by severity** — `critical`/`high`/`medium`/`low` counts from `/api/v1/analytics/risk-summary`

See [metrics.md](metrics.md) for the full success-metrics catalog, formulas, and alerting thresholds.

### Health endpoint

`GET /health` (or `/api/v1/health`) reports `status: healthy|degraded` with per-dependency reachability (`database`, `redis`). Use it for load-balancer health checks and uptime monitoring. The Docker `app` service already health-checks this endpoint every 30 seconds.
