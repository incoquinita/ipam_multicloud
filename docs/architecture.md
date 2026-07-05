# Architecture

This document describes the system design of the IPAM Multi-Cloud Security Platform: the component model, the end-to-end data flow, the multicloud discovery pattern, the async scanning pipeline, the authentication and credential-encryption flows, and the database schema.

---

## System Design Overview

The platform is a three-tier async system: a React SPA at the edge, a FastAPI application in the middle, and a PostgreSQL + Redis data layer at the bottom. Long-running work (scanning, discovery, cleanup) is offloaded to Celery workers so the API stays responsive.

```mermaid
graph TB
    subgraph Edge["Edge layer"]
        Browser["Browser<br/>React 19 SPA"]
        Nginx["nginx<br/>TLS termination<br/>API + WS reverse proxy<br/>SPA static hosting"]
    end

    subgraph API["Application layer (FastAPI)"]
        Router["v1 Router<br/>/api/v1/*"]
        MW["Middleware stack<br/>CORS → SecurityHeaders → RequestID → RateLimit → Prometheus"]
        Deps["Dependencies<br/>get_current_active_user"]
        Endpoints["Endpoints<br/>auth · scans · targets · cloud-providers<br/>credentials · discovery · analytics · ip-addresses<br/>port-results · health · ws"]
        Services["Services<br/>AuthService · ScanService · CloudCredentialService<br/>CloudService · TargetService · AnalyticsService"]
        Repos["Repositories<br/>scan · target · cloud · ip_address · port_result"]
    end

    subgraph Workers["Worker layer (Celery)"]
        ScanTasks["scan_tasks<br/>run_port_scan · run_http_analysis"]
        DiscoveryTasks["discovery_tasks<br/>run_cloud_discovery"]
        CleanupTasks["cleanup_tasks"]
        Beat["celery beat<br/>scheduler"]
    end

    subgraph Scanner["Scanner engine"]
        PortScanner["PortScanner<br/>async TCP + semaphore"]
        Banner["BannerGrabber"]
        HttpAnalyzer["HttpAnalyzer<br/>static · login · rate-limit · TLS"]
        Risk["RiskClassifier<br/>score + severity"]
    end

    subgraph Providers["Cloud providers"]
        Base["CloudProvider ABC"]
        AWS["AWSProvider"]
        Azure["AzureProvider"]
        OCI["OCIProvider"]
        GCP["GCPProvider"]
        Factory["ProviderFactory"]
    end

    subgraph Data["Data layer"]
        PG[("PostgreSQL 16<br/>SQLAlchemy 2.0 async")]
        Redis[("Redis 7<br/>broker · results · pub/sub")]
    end

    Browser -->|HTTPS| Nginx
    Nginx -->|HTTP| Router
    Nginx -->|WS upgrade| Endpoints
    Router --> MW --> Deps --> Endpoints
    Endpoints --> Services --> Repos --> PG
    Endpoints -->|enqueue| Redis
    ScanTasks --> PortScanner
    ScanTasks --> Banner
    ScanTasks --> HttpAnalyzer
    ScanTasks --> Risk
    ScanTasks --> Repos
    ScanTasks -->|publish progress| Redis
    DiscoveryTasks --> Factory --> Base
    Base -.-> AWS
    Base -.-> Azure
    Base -.-> OCI
    Base -.-> GCP
    DiscoveryTasks --> Repos
    CleanupTasks --> Repos
    Beat -->|schedule| Redis
    Redis -.->|pub/sub| Endpoints
```

### Layer responsibilities

| Layer | Responsibility |
|-------|----------------|
| **Edge (nginx)** | TLS termination, HTTP→HTTPS redirect, static SPA hosting with `try_files` fallback, reverse proxy for `/api/` and `/ws/`, security headers, long timeout for scan requests and WebSockets. |
| **API (FastAPI)** | Request parsing and validation at the boundary (Pydantic), authentication, orchestration of services, pagination, error mapping with stable `code` values. No business logic in endpoints — they delegate to services. |
| **Services** | Business logic. `ScanService` creates scan jobs and dispatches Celery tasks; `CloudCredentialService` encrypts/decrypts credentials; `AuthService` issues tokens; `AnalyticsService` runs aggregation queries. |
| **Repositories** | Data access. Thin async wrappers over SQLAlchemy `select`/`insert`/`update` queries, keeping ORM details out of services. |
| **Workers (Celery)** | Long-running execution: TCP port scanning, banner grabbing, HTTP analysis, risk classification, result persistence, and cloud discovery. Publishes progress to Redis for real-time streaming. |
| **Scanner engine** | Pure async I/O modules with no database access — they return structured result dicts/objects that the worker persists. |
| **Providers** | Agentless cloud enumeration behind a common `CloudProvider` ABC, resolved by a factory. Each provider runs blocking SDK calls in an executor to avoid blocking the event loop. |

---

## Data Flow

The canonical flow from cloud discovery through to results visualization:

```mermaid
flowchart LR
    A["Cloud Discovery<br/>(Celery)"] --> B["IP Database<br/>(ip_addresses)"]
    B --> C["Scan Job Created<br/>(scan_jobs)"]
    C --> D["Port Scan<br/>(async TCP)"]
    D --> E["Risk Classification<br/>(RiskClassifier)"]
    E --> F["Banner Grab<br/>(open ports)"]
    F --> G["HTTP Analysis<br/>(web ports)"]
    G --> H["Results Persisted<br/>(port_results + http_analyses)"]
    H --> I["Real-time Progress<br/>(Redis pub/sub → WS)"]
    H --> J["Analytics & Dashboard<br/>(aggregations)"]
```

1. **Cloud Discovery.** An operator registers a cloud provider and its (encrypted) credentials, then `POST /api/v1/discovery/run` enqueues a `run_cloud_discovery` Celery task on the `discovery` queue.
2. **IP Database.** The discovery task instantiates the provider via the factory, calls `discover_ip_addresses`, `discover_security_rules`, and `discover_load_balancers`, and upserts the discovered IPs into the `ip_addresses` table.
3. **Scan Job.** An operator creates a scan target (CIDR, IP list, hostname, or cloud provider) and submits a scan job (`POST /api/v1/scans/`). `ScanService` inserts a `scan_jobs` row and dispatches `run_port_scan` on the `scans` queue.
4. **Port Scan.** The Celery task resolves each target host to an `ip_addresses` row, then runs `PortScanner.scan_host` — async TCP connect probes bounded by an internal semaphore — across the profile's port list.
5. **Risk Classification.** Every open port is classified by `RiskClassifier.classify_port`, which combines a service baseline score, exposure multiplier, encryption multiplier, SSL multiplier, and CVE penalty into a final 0–10 score mapped to `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`.
6. **Banner Grab + HTTP Analysis.** For open ports, the task optionally grabs the service banner (disambiguating SSH vs SFTP on port 22) and, for web ports (`80, 443, 8080, 8443`), runs `HttpAnalyzer.analyze` to detect static/dynamic content, login forms, rate-limiting, security headers, technology fingerprints, and TLS certificate info.
7. **Results Persisted.** Each port outcome is stored as a `port_results` row; each HTTP analysis as an `http_analyses` row. Running counters (`ports_found`, `findings_critical`, etc.) are updated on the `scan_jobs` row after each host.
8. **Real-time Progress.** After each host, the task publishes a JSON message to the Redis channel `scan:progress:{scan_job_id}`. The WebSocket endpoint subscribes to that channel and forwards messages to connected clients.
9. **Analytics & Dashboard.** The `AnalyticsService` and `ScanRepository.get_dashboard_stats` run aggregate queries (timeline, port distribution, risk summary, KPI counts) that power the dashboard charts and KPI cards.

---

## Multicloud Discovery Pattern

Discovery is **agentless** — no software is installed inside the cloud accounts. Each provider uses the official cloud SDK authenticated with credentials the operator supplies (and which are Fernet-encrypted at rest).

### Abstract interface

Every provider implements the `CloudProvider` ABC (`app/providers/base.py`):

```python
class CloudProvider(ABC):
    async def discover_ip_addresses(self) -> list[DiscoveredIP]: ...
    async def discover_security_rules(self) -> list[SecurityRule]: ...
    async def discover_load_balancers(self) -> list[LBEndpoint]: ...
    async def health_check(self) -> bool: ...
    async def get_regions(self) -> list[str]: ...
```

A shared `_run_in_executor` helper runs the blocking SDK calls (which are synchronous in boto3, the Azure SDK, the OCI SDK, and the GCP SDK) on the default executor so the async event loop is never blocked.

### Factory resolution

`ProviderFactory.get_provider(provider_type, credential)` maps a provider-type string (`aws`, `azure`, `gcp`, `oci`) to the concrete class. Unknown types raise `ValueError` at the boundary so internal code receives a trusted `CloudProvider` instance.

### Per-provider enumeration

| Provider | SDK | Enumeration sources |
|----------|-----|---------------------|
| **AWS** | `boto3` | EC2 instances, Elastic IPs, NAT Gateways, Load Balancers |
| **Azure** | `azure-mgmt-network`, `azure-mgmt-resource`, `azure-identity` | Public IPs, NICs, Load Balancers |
| **OCI** | `oci` | VNICs, Load Balancers |
| **GCP** | `google-cloud-compute` | Instance NICs, Static IPs, Forwarding Rules |

Each provider returns `DiscoveredIP` dataclass instances (carrying `ip_address`, `private_ip`, `resource_id`, `resource_type`, `region`, `hostname`, `tags`), plus `SecurityRule` and `LBEndpoint` records for firewall and load-balancer context. A shared `retry` helper in `app/providers/retry.py` wraps transient SDK failures.

---

## Scanning Pipeline

Scanning runs entirely inside a Celery task (`run_port_scan` in `app/workers/scan_tasks.py`). The task is the orchestrator; the scanner modules are pure async I/O with no database access.

### Phases

```mermaid
sequenceDiagram
    participant API as Scan API
    participant Q as Celery / Redis
    participant W as scan_task (worker)
    participant S as Scanner engine
    participant DB as Database
    participant PubSub as Redis pub/sub

    API->>DB: INSERT scan_jobs (status=pending)
    API->>Q: run_port_scan.delay(job_id, targets, config)
    API-->>API: return 201 (job_id)
    W->>W: parse config + resolve profile
    W->>DB: UPDATE status=running, started_at
    W->>PubSub: publish scan_progress (0%)
    loop each host
        W->>S: asyncio.run(_scan_all_hosts(...))
        S->>S: PortScanner.scan_host (async TCP, semaphore-bounded)
        S->>S: BannerGrabber.grab_banner (open ports)
        S->>S: HttpAnalyzer.analyze (web ports)
        S-->>W: result dict per host
        W->>W: RiskClassifier.classify_port per open port
        W->>DB: INSERT port_results + http_analyses
        W->>DB: UPDATE scan_jobs counters + progress
        W->>PubSub: publish scan_progress (%)
    end
    W->>DB: UPDATE status=completed, completed_at
    W->>PubSub: publish scan_complete (100%)
```

### Key design decisions

- **Single event loop for the whole batch.** All hosts are scanned concurrently via `asyncio.gather` inside one `asyncio.run` call, so the event loop is created once instead of per host. The `PortScanner`'s internal semaphore already caps concurrent socket connections, so batching hosts does not overwhelm the network.
- **Pure-async scanner, sync persistence.** The scanner engine performs only async I/O and returns structured result objects. The (synchronous) Celery task handles all database writes through `ScanResultService`, keeping the event loop free of blocking DB calls.
- **Graceful per-host degradation.** `asyncio.gather(..., return_exceptions=True)` surfaces per-host failures as `Exception` values. A failed host is logged, published as a progress event, and skipped — it never aborts the batch.
- **Lazy imports.** Scanner classes are imported inside the task body so Celery worker startup is not blocked by scanner/engine initialization.
- **SSH/SFTP disambiguation.** Port 22 is reported as `SSH/SFTP` when the grabbed banner contains `"sftp"`, since SSH and SFTP share port 22.
- **Time limits.** Celery enforces a 600-second soft time limit and a 900-second hard time limit per task. `acks_late=True` and `reject_on_worker_lost=True` ensure lost workers do not silently drop scans.

### Scan profiles

Profiles (`app/schemas/scan_profiles.py`) bundle a port list with scanning behavior so callers select a name instead of raw config:

| Profile | Ports | Timeout | Concurrency | Banner grab | HTTP analysis |
|---------|-------|---------|-------------|-------------|---------------|
| `quick` | Top 10 admin ports | 1.0s | 500 | No | No |
| `standard` | Top 31+ admin ports | 2.0s | 200 | Yes | Yes |
| `thorough` | Ports 1–1024 + key admin ports | 3.0s | 100 | Yes | Yes |
| `custom` | Caller-supplied | 2.0s | 200 | Yes | Yes |

### Progress streaming

After each host, `publish_progress` writes a JSON message shaped to the frontend `WsMessage` contract to Redis with a 10-minute expiry, and publishes it on the `scan:progress:{scan_job_id}` channel:

```json
{
  "type": "scan_progress",
  "scan_job_id": "<uuid>",
  "timestamp": "<iso-8601>",
  "payload": {
    "task_id": "<celery-id>",
    "progress": 42.0,
    "status": "running",
    "message": "Scanned 10.0.0.5 — found 3 open port(s)",
    "data": {"current_host": "10.0.0.5", "ports_found_this_host": 3}
  }
}
```

The internal status label is mapped to the WebSocket `type` (`scan_progress`, `scan_complete`, `scan_error`, `scan_cancelled`) so the worker keeps passing internal status strings while the frontend receives the contract types it expects.

---

## Authentication Flow

```mermaid
sequenceDiagram
    participant U as User
    participant FE as Frontend
    participant API as FastAPI
    participant Auth as AuthService
    participant Sec as core.security
    participant DB as Database

    U->>FE: enter username + password
    FE->>API: POST /api/v1/auth/login
    API->>Auth: authenticate(db, username, password)
    Auth->>DB: SELECT user WHERE username=?
    Auth->>Sec: verify_password(plain, hashed)
    Sec-->>Auth: True/False
    Auth-->>API: user (or None → 401)
    API->>Sec: create_access_token({sub, username, type:access}, 15min)
    API->>Sec: create_refresh_token({sub}, 7d, type:refresh)
    API-->>FE: {access_token, refresh_token, expires_in}
    FE->>FE: store tokens (authStore)
    Note over FE: subsequent requests carry Authorization: Bearer <access>
    FE->>API: GET /api/v1/scans/ (Bearer)
    API->>Sec: decode_access_token → payload
    API->>Auth: get_user_by_id(payload.sub)
    Auth->>DB: SELECT user WHERE id=?
    Auth-->>API: user
    API->>API: get_current_active_user → ok
    API-->>FE: 200 (scans)
```

See [security.md](security.md#jwt-authentication) for the token lifetimes, claims, and the dependency chain that enforces authorization.

---

## Credential Encryption Flow

```mermaid
sequenceDiagram
    participant Op as Operator
    participant API as Credentials API
    participant Svc as CloudCredentialService
    participant F as Fernet
    participant DB as Database
    participant Worker as Celery discovery task

    Op->>API: POST /credentials/ {credentials: {...plaintext...}}
    API->>Svc: create_credential(provider_id, type, name, fields)
    Svc->>DB: verify provider exists (fail-fast)
    Svc->>F: encrypt(JSON.stringify(fields))
    F-->>Svc: encrypted blob
    Svc->>DB: INSERT cloud_credentials (encrypted_data=blob)
    Svc-->>API: credential (no encrypted_data in response)
    API-->>Op: {id, provider_type, name, ...}

    Note over Worker: later, a discovery task runs
    Worker->>Svc: decrypt_and_parse(credential_id)
    Svc->>DB: SELECT credential
    Svc->>F: decrypt(encrypted_data)
    F-->>Svc: plaintext JSON
    Svc->>Svc: json.loads → ProviderCredential
    Svc-->>Worker: ProviderCredential
    Worker->>Worker: ProviderFactory.get_provider(type, cred)
```

The encrypted blob is never included in any API response. Decryption happens only inside the worker process, immediately before provider instantiation, and the decrypted `ProviderCredential` is never persisted or logged.

---

## Database Schema Overview

The schema is managed by Alembic (migrations `001`–`005`) and uses PostgreSQL `UUID`, `JSONB`, and `TIMESTAMP WITH TIME ZONE` types. All primary keys are UUIDs generated in the application.

```mermaid
erDiagram
    users ||--o{ scan_jobs : "creates"
    cloud_providers ||--o{ cloud_credentials : "owns"
    cloud_providers ||--o{ ip_addresses : "discovers"
    scan_targets ||--o{ scan_jobs : "scanned by"
    scan_jobs ||--o{ port_results : "produces"
    scan_jobs ||--o{ http_analyses : "produces"
    scan_jobs ||--o{ scan_events : "logs"
    ip_addresses ||--o{ port_results : "host"
    ip_addresses ||--o{ http_analyses : "host"

    users {
        uuid id PK
        string email UK
        string username UK
        string hashed_password
        bool is_active
        bool is_superuser
        timestamp created_at
        timestamp updated_at
    }
    cloud_providers {
        uuid id PK
        string name
        string provider_type "aws|azure|gcp|oci"
        bool is_active
        string regions
        timestamp created_at
    }
    cloud_credentials {
        uuid id PK
        uuid cloud_provider_id FK
        string credential_type
        string credential_name
        text encrypted_data "Fernet blob"
        bool is_active
        timestamp expires_at
    }
    scan_targets {
        uuid id PK
        string name
        string target_type "cidr|ip_list|cloud_provider|hostname"
        text target_value
        jsonb ports
        bool is_active
        jsonb tags
    }
    ip_addresses {
        uuid id PK
        uuid cloud_provider_id FK
        string resource_id
        string resource_type
        string ip_address
        string private_ip
        string region
        jsonb tags
        bool is_alive
        timestamp discovered_at
    }
    scan_jobs {
        uuid id PK
        uuid target_id FK
        string scan_type "quick|standard|thorough|custom"
        string status "pending|queued|running|completed|failed|cancelled"
        float progress
        jsonb config
        int total_ips
        int ips_scanned
        int ports_found
        int findings_critical
        int findings_high
        int findings_medium
        int findings_low
        timestamp started_at
        timestamp completed_at
        string celery_task_id
    }
    port_results {
        uuid id PK
        uuid scan_job_id FK
        uuid ip_address_id FK
        int port "1-65535"
        string protocol
        string state "open|closed|filtered|unfiltered"
        string service_name
        string banner
        string risk_level "critical|high|medium|low|info"
        float risk_score
        jsonb cve_ids
    }
    http_analyses {
        uuid id PK
        uuid scan_job_id FK
        uuid ip_address_id FK
        int port
        string url
        int status_code
        bool is_static
        bool has_login
        bool has_rate_limit
        jsonb response_headers
        jsonb technologies
        jsonb certificates
        jsonb security_headers
        int security_headers_score "0-10"
        string tls_version
        string title
        jsonb static_evidence
        jsonb login_evidence
        jsonb rate_limit_details
    }
    scan_events {
        uuid id PK
        uuid scan_job_id FK
        string event_type
        text message
        jsonb metadata
        float progress
        timestamp created_at
    }
```

### Key relationships

- A `ScanTarget` (CIDR, IP list, hostname, or cloud provider reference) owns many `ScanJobs`.
- A `ScanJob` produces many `PortResults` and `HttpAnalyses`, and logs an append-only stream of `ScanEvents`.
- `PortResult` and `HttpAnalysis` both reference the `ScanJob` and the `IPAddress` they pertain to, with `ondelete="CASCADE"` so deleting a scan job removes its findings.
- `IPAddress` optionally belongs to a `CloudProvider` (`ondelete="SET NULL"`), so deleting a provider retains the IP history.
- `CloudCredential` belongs to a `CloudProvider` with cascade delete — removing a provider removes its encrypted credentials.

### Migrations

| Migration | Description |
|-----------|-------------|
| `001_initial_schema` | Base tables: `scan_targets`, `scan_jobs`, `ip_addresses`, `port_results`, `cloud_providers` |
| `002_add_scan_profiles` | Scan profile column on `scan_jobs` |
| `003_add_http_analysis_fields` | `http_analyses` table and static/login/rate-limit/headers/TLS columns |
| `004_add_users_table` | `users` table for JWT authentication |
| `005_seed_admin_user` | Seeds the initial superuser from `ADMIN_EMAIL` / `ADMIN_PASSWORD` (with bcrypt hashing) |
