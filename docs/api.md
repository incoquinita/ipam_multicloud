# API Reference

The IPAM Multi-Cloud Security Platform exposes a versioned REST API under `/api/v1` and a WebSocket endpoint for real-time scan progress. This documents every endpoint with its method, path, auth requirement, request/response schemas, and examples.

- **Base URL (local dev):** `http://localhost:8000`
- **Base URL (via nginx):** `https://localhost`
- **OpenAPI spec (dev only):** `http://localhost:8000/openapi.json` (disabled when `DEBUG=False`)
- **Interactive docs (dev only):** `http://localhost:8000/docs` (Swagger UI), `http://localhost:8000/redoc`

---

## Authentication

All domain endpoints (`/scans`, `/targets`, `/cloud-providers`, `/credentials`, `/discovery`, `/analytics`, `/ip-addresses`, `/port-results`) require a valid JWT access token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

The `/auth` and `/health` endpoints are public. The WebSocket endpoint authenticates via a `token` query parameter (see [WebSocket](#websocket)).

### Obtain tokens

`POST /api/v1/auth/login` returns an access + refresh token pair. The access token expires in 15 minutes; the refresh token in 7 days. When the access token expires, call `POST /api/v1/auth/refresh` with the refresh token to get a new pair.

### Error responses

Every error returns a consistent JSON body:

```json
{
  "detail": "Human-readable message",
  "code": "machine_readable_code"
}
```

Common codes: `unauthorized` (401), `forbidden` (403), `not_found` (404), `conflict` (409), `bad_request` (400), `validation_error` (422), `cloud_provider_error` (502), `internal_error` (500). Rate-limited requests return `429` via slowapi.

---

## Auth

### POST /api/v1/auth/register

Register a new user account. Rate-limited to 5 requests/minute/IP.

**Auth:** None

**Request body** (`UserCreate`):

| Field | Type | Constraints |
|-------|------|-------------|
| `email` | string (email) | Unique |
| `username` | string | 3–50 chars, `^[A-Za-z0-9_]+$`, unique |
| `password` | string | 8–128 chars |

```json
{
  "email": "analyst@example.com",
  "username": "analyst",
  "password": "s3cureP@ss!"
}
```

**Response** `201 Created` (`UserResponse`):

```json
{
  "id": "7c1f2e3a-...",
  "email": "analyst@example.com",
  "username": "analyst",
  "is_active": true,
  "is_superuser": false,
  "created_at": "2026-06-19T10:00:00Z",
  "updated_at": "2026-06-19T10:00:00Z"
}
```

**Errors:** `409 conflict` if email or username already registered.

---

### POST /api/v1/auth/login

Authenticate and receive a token pair. Rate-limited to 10 requests/minute/IP. Returns a generic `401` for invalid credentials or inactive users.

**Auth:** None

**Request body** (`LoginRequest`):

```json
{
  "username": "analyst",
  "password": "s3cureP@ss!"
}
```

**Response** `200 OK` (`TokenResponse`):

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 900
}
```

**Errors:** `401 unauthorized` — `"Invalid username or password"`.

---

### POST /api/v1/auth/refresh

Exchange a valid refresh token for a new token pair.

**Auth:** None (the refresh token in the body authenticates the request)

**Request body** (`TokenRefresh`):

```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response** `200 OK` (`TokenResponse`): same shape as login.

**Errors:** `401 unauthorized` — `"Invalid or expired refresh token"`.

---

### GET /api/v1/auth/me

Return the authenticated user's profile.

**Auth:** Bearer access token

**Response** `200 OK` (`UserResponse`):

```json
{
  "id": "7c1f2e3a-...",
  "email": "analyst@example.com",
  "username": "analyst",
  "is_active": true,
  "is_superuser": false,
  "created_at": "2026-06-19T10:00:00Z",
  "updated_at": "2026-06-19T10:00:00Z"
}
```

---

## Scans

### POST /api/v1/scans/

Submit a new scan job for asynchronous execution.

**Auth:** Bearer access token

**Request body** (`ScanJobCreate`):

| Field | Type | Description |
|-------|------|-------------|
| `target_id` | UUID | Target to scan |
| `scan_type` | enum | `quick` \| `standard` \| `thorough` \| `custom` (default `quick`) |
| `config` | object \| null | Scan configuration overrides (e.g. `{"profile": "standard", "banner_grab": true}`) |
| `ports` | int[] \| null | Port list override |

```json
{
  "target_id": "a3b4c5d6-...",
  "scan_type": "standard",
  "config": {"profile": "standard", "http_analysis": true}
}
```

**Response** `201 Created` (`ScanJobResponse`):

```json
{
  "id": "e5f6a7b8-...",
  "target_id": "a3b4c5d6-...",
  "scan_type": "standard",
  "status": "pending",
  "progress": 0.0,
  "config": {"profile": "standard", "http_analysis": true},
  "total_ips": null,
  "ips_scanned": null,
  "ports_found": null,
  "findings_critical": null,
  "findings_high": null,
  "started_at": null,
  "completed_at": null,
  "duration_seconds": null,
  "error_message": null,
  "celery_task_id": "c7d8e9f0-...",
  "created_at": "2026-06-19T10:05:00Z",
  "updated_at": "2026-06-19T10:05:00Z"
}
```

---

### GET /api/v1/scans/

List scan jobs with pagination and optional status filter.

**Auth:** Bearer access token

**Query parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `page` | int | 1 | Page number (≥1) |
| `size` | int | 50 | Page size (1–200) |
| `status` | string | null | Filter by status |

**Response** `200 OK` (`PaginatedResponse[ScanJobResponse]`):

```json
{
  "items": [ { "...": "ScanJobResponse" } ],
  "total": 137,
  "page": 1,
  "size": 50,
  "pages": 3
}
```

---

### GET /api/v1/scans/{scan_id}

Return details for a specific scan job.

**Auth:** Bearer access token

**Response** `200 OK` (`ScanJobResponse`).

**Errors:** `404 not_found` if the scan does not exist.

---

### GET /api/v1/scans/{scan_id}/status

Return lightweight status for progress polling.

**Auth:** Bearer access token

**Response** `200 OK` (`ScanStatusResponse`):

```json
{
  "id": "e5f6a7b8-...",
  "status": "running",
  "progress": 45.0,
  "total_ips": 12,
  "ips_scanned": 5,
  "ports_found": 18,
  "findings_critical": 3,
  "findings_high": 7,
  "duration_seconds": 42,
  "error_message": null
}
```

---

### POST /api/v1/scans/{scan_id}/cancel

Cancel a pending, queued, or running scan.

**Auth:** Bearer access token

**Response** `200 OK` (`ScanJobResponse`) — the updated scan job with `status` set to `cancelled`.

---

### GET /api/v1/scans/stats

Return aggregate dashboard statistics (KPI cards). This route is registered before `/{scan_id}` so the static `stats` segment is not mistaken for a UUID.

**Auth:** Bearer access token

**Response** `200 OK` (`DashboardStats`):

```json
{
  "total_targets": 24,
  "total_scans": 137,
  "active_scans": 2,
  "completed_scans": 130,
  "total_open_ports": 412,
  "critical_findings": 18,
  "high_findings": 47,
  "medium_findings": 120,
  "low_findings": 227,
  "total_ips": 318,
  "scans_last_7_days": 29
}
```

---

### GET /api/v1/scans/{scan_id}/results

Return the combined results bundle for a scan: status, all port results, all HTTP analyses, and an aggregate summary. Not paginated — use the dedicated `/results/ports` and `/results/http` routes for page-by-page retrieval.

**Auth:** Bearer access token

**Response** `200 OK` (`ScanResultsResponse`):

```json
{
  "scan_job": { "...": "ScanStatusResponse" },
  "port_results": [ { "...": "PortResultResponse" } ],
  "http_analyses": [ { "...": "HttpAnalysisResponse" } ],
  "summary": {
    "total_ports": 42,
    "open_ports": 18,
    "critical_findings": 3,
    "high_findings": 7,
    "medium_findings": 5,
    "low_findings": 3,
    "http_analyzed": 6,
    "static_sites": 2,
    "login_sites": 3,
    "rate_limited_sites": 1
  }
}
```

---

### GET /api/v1/scans/{scan_id}/results/ports

Return a paginated list of port results for a scan.

**Auth:** Bearer access token

**Query parameters:** `page` (default 1), `size` (default 50, max 200).

**Response** `200 OK` (`PortResultListResponse`):

```json
{
  "items": [
    {
      "id": "p1q2r3s4-...",
      "scan_job_id": "e5f6a7b8-...",
      "ip_address_id": "i9j0k1l2-...",
      "port": 3389,
      "protocol": "tcp",
      "state": "open",
      "service_name": "RDP",
      "service_product": null,
      "service_version": null,
      "banner": null,
      "risk_level": "critical",
      "risk_score": 9.5,
      "cve_ids": [],
      "scanned_at": "2026-06-19T10:06:12Z"
    }
  ],
  "total": 18,
  "page": 1,
  "page_size": 50,
  "total_pages": 1
}
```

---

### GET /api/v1/scans/{scan_id}/results/http

Return a paginated list of HTTP analysis results for a scan.

**Auth:** Bearer access token

**Query parameters:** `page` (default 1), `size` (default 50, max 200).

**Response** `200 OK` — `HttpAnalysisResponse[]`:

```json
[
  {
    "id": "h3g4f5e6-...",
    "scan_job_id": "e5f6a7b8-...",
    "ip_address_id": "i9j0k1l2-...",
    "port": 443,
    "url": "https://10.0.0.5:443",
    "status_code": 200,
    "is_static": false,
    "has_login": true,
    "has_rate_limit": false,
    "response_headers": { "server": "nginx", "...": "..." },
    "technologies": ["nginx", "Python/FastAPI"],
    "certificates": { "subject": {}, "notAfter": "..." },
    "security_headers": { "HSTS": "max-age=..." },
    "security_headers_score": 6,
    "tls_version": "TLSv1.3",
    "title": "Sign In",
    "static_evidence": ["/api/:404", "/admin:200"],
    "login_evidence": ["password_input_field_found", "login_form_action_detected"],
    "rate_limit_details": { "rate_limited": false, "status_codes": [200] },
    "analyzed_at": "2026-06-19T10:06:30Z"
  }
]
```

---

## Targets

CRUD endpoints for scan targets (CIDR ranges, IP lists, hostnames, or cloud-provider references).

### POST /api/v1/targets/

**Auth:** Bearer access token

**Request body** (`ScanTargetCreate`):

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Human-readable name (max 256) |
| `description` | string \| null | Optional |
| `target_type` | enum | `cidr` \| `ip_list` \| `cloud_provider` \| `hostname` (default `cidr`) |
| `target_value` | string | CIDR, comma-separated IPs, provider ID, or hostname |
| `ports` | int[] \| null | Port list override (null = common ports) |
| `tags` | object \| null | Arbitrary tags |

```json
{
  "name": "Corporate DMZ",
  "target_type": "cidr",
  "target_value": "10.0.0.0/24",
  "ports": [22, 80, 443, 3389]
}
```

**Response** `201 Created` (`ScanTargetResponse`).

---

### GET /api/v1/targets/

**Auth:** Bearer access token

**Query parameters:** `page` (default 1), `page_size` (default 50, max 200), `active_only` (bool, default false).

**Response** `200 OK` (`PaginatedResponse[ScanTargetResponse]`).

---

### GET /api/v1/targets/{target_id}

**Auth:** Bearer access token

**Response** `200 OK` (`ScanTargetResponse`). **Errors:** `404 not_found`.

---

### PATCH /api/v1/targets/{target_id}

**Auth:** Bearer access token

**Request body** (`ScanTargetUpdate`): all fields optional.

**Response** `200 OK` (`ScanTargetResponse`).

---

### DELETE /api/v1/targets/{target_id}

**Auth:** Bearer access token

**Response** `204 No Content`.

---

## Cloud Providers

CRUD endpoints for registered cloud provider accounts/projects.

### POST /api/v1/cloud-providers/

**Auth:** Bearer access token

**Request body** (`CloudProviderCreate`):

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Human-readable name (max 128) |
| `provider_type` | enum | `aws` \| `azure` \| `gcp` \| `oci` |
| `description` | string \| null | Optional |
| `regions` | string[] \| null | Regions to scan |
| `metadata` | object \| null | Arbitrary provider metadata |

```json
{
  "name": "Production AWS",
  "provider_type": "aws",
  "regions": ["us-east-1", "us-west-2"]
}
```

**Response** `201 Created` (`CloudProviderResponse`).

---

### GET /api/v1/cloud-providers/

**Query parameters:** `page`, `page_size`, `active_only`.

**Response** `200 OK` (`PaginatedResponse[CloudProviderResponse]`).

---

### GET /api/v1/cloud-providers/{provider_id}

**Response** `200 OK` (`CloudProviderResponse`). **Errors:** `404 not_found`.

---

### PATCH /api/v1/cloud-providers/{provider_id}

**Request body** (`CloudProviderUpdate`): all fields optional.

**Response** `200 OK` (`CloudProviderResponse`).

---

### DELETE /api/v1/cloud-providers/{provider_id}

**Response** `204 No Content`.

---

## Credentials

Cloud credential management. The plaintext `credentials` dict is accepted only on create and is Fernet-encrypted before persistence. **No response ever includes the encrypted blob.**

### POST /api/v1/credentials/

**Auth:** Bearer access token

**Request body** (`CredentialCreate`):

| Field | Type | Description |
|-------|------|-------------|
| `cloud_provider_id` | UUID | Owning cloud provider |
| `provider_type` | string | `access_key` \| `service_principal` \| `service_account` \| `api_key` \| `oci_config` |
| `name` | string | Human-readable label |
| `credentials` | object | Plaintext credential fields (encrypted before storage) |
| `metadata` | object \| null | Optional non-secret metadata |

```json
{
  "cloud_provider_id": "c1d2e3f4-...",
  "provider_type": "access_key",
  "name": "prod-ro-key",
  "credentials": {
    "aws_access_key_id": "AKIA...",
    "aws_secret_access_key": "..."
  }
}
```

**Response** `201 Created` (`CredentialResponse`):

```json
{
  "id": "d5e6f7a8-...",
  "provider_type": "access_key",
  "name": "prod-ro-key",
  "created_at": "2026-06-19T10:10:00Z",
  "updated_at": "2026-06-19T10:10:00Z"
}
```

**Errors:** `404 not_found` if the cloud provider does not exist.

---

### GET /api/v1/credentials/

**Query parameters:** `page`, `page_size`, `cloud_provider_id` (UUID, filter), `active_only` (bool).

**Response** `200 OK` (`CredentialListResponse`):

```json
{
  "items": [ { "...": "CredentialResponse" } ],
  "total": 7
}
```

---

### GET /api/v1/credentials/{credential_id}

**Response** `200 OK` (`CredentialResponse`). **Errors:** `404 not_found`.

---

### DELETE /api/v1/credentials/{credential_id}

**Response** `204 No Content`.

---

## Discovery

Dispatch and monitor asynchronous cloud discovery via Celery.

### POST /api/v1/discovery/run

Enqueue a discovery job for the given provider. Returns immediately with the Celery task id.

**Auth:** Bearer access token

**Request body** (`DiscoveryRunRequest`):

```json
{ "provider_id": "c1d2e3f4-..." }
```

**Response** `200 OK` (`DiscoveryRunResponse`):

```json
{ "job_id": "b8c7d6e5-...", "status": "pending" }
```

---

### GET /api/v1/discovery/status/{job_id}

Poll the status of a dispatched discovery job. `status` is the raw Celery state (`PENDING`, `STARTED`, `SUCCESS`, `FAILURE`).

**Auth:** Bearer access token

**Response** `200 OK` (`DiscoveryStatusResponse`):

```json
{
  "job_id": "b8c7d6e5-...",
  "status": "SUCCESS",
  "ready": true,
  "successful": true,
  "result": {
    "ips_discovered": 42,
    "security_rules_found": 18,
    "load_balancers_found": 3,
    "errors": []
  },
  "error": null
}
```

---

### GET /api/v1/discovery/status  (deprecated)

Legacy endpoint retained for backward compatibility. Always returns `has_run: false`. Use `GET /discovery/status/{job_id}` instead.

---

## Analytics

Aggregation endpoints powering the dashboard charts.

### GET /api/v1/analytics/timeline

Scan counts and findings per day for the last N days.

**Auth:** Bearer access token

**Query parameters:** `days` (int, default 30, range 1–365).

**Response** `200 OK` (`ScanTimeline`):

```json
{
  "items": [
    { "date": "2026-06-18", "scans": 5, "findings": 23 },
    { "date": "2026-06-19", "scans": 8, "findings": 41 }
  ]
}
```

---

### GET /api/v1/analytics/port-distribution

The most frequently discovered open ports.

**Auth:** Bearer access token

**Query parameters:** `limit` (int, default 20, range 1–200).

**Response** `200 OK` (`PortDistribution`):

```json
{
  "items": [
    { "port": 443, "service_name": "HTTPS", "count": 187, "critical_count": 0 },
    { "port": 22, "service_name": "SSH", "count": 142, "critical_count": 0 },
    { "port": 3389, "service_name": "RDP", "count": 31, "critical_count": 31 }
  ]
}
```

---

### GET /api/v1/analytics/risk-summary

Aggregate risk counts and average risk score.

**Auth:** Bearer access token

**Response** `200 OK` (`RiskSummary`):

```json
{
  "critical": 18,
  "high": 47,
  "medium": 120,
  "low": 227,
  "total": 412,
  "risk_score_average": 5.7
}
```

---

## IP Addresses

### GET /api/v1/ip-addresses/

Paginated, filterable list of discovered IP addresses.

**Auth:** Bearer access token

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `page` | int | Page number (default 1) |
| `page_size` | int | Page size (default 50, max 200) |
| `cloud_provider_id` | UUID \| null | Filter by cloud provider |
| `scan_job_id` | UUID \| null | Filter to IPs scanned by a job |

**Response** `200 OK` (`IPAddressListResponse`):

```json
{
  "items": [
    {
      "id": "i9j0k1l2-...",
      "cloud_provider_id": "c1d2e3f4-...",
      "resource_id": "i-0abc123",
      "resource_type": "instance",
      "ip_address": "10.0.0.5",
      "private_ip": "10.0.0.5",
      "region": "us-east-1",
      "is_alive": true,
      "hostname": null,
      "discovered_at": "2026-06-19T09:00:00Z"
    }
  ],
  "total": 318,
  "page": 1,
  "page_size": 50,
  "total_pages": 7
}
```

---

## Port Results

### GET /api/v1/port-results/

Paginated, filterable list of port scan findings across all scans.

**Auth:** Bearer access token

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `page` | int | Page number (default 1) |
| `page_size` | int | Page size (default 50, max 200) |
| `scan_job_id` | UUID \| null | Filter by scan job |
| `port` | int \| null | Filter by port number (1–65535) |
| `risk_level` | string \| null | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `state` | string \| null | `open` \| `closed` \| `filtered` \| `unfiltered` |

**Response** `200 OK` (`PortResultListResponse`).

**Errors:** `400 bad_request` if `risk_level` or `state` is not one of the allowed values.

---

## Health

### GET /health  (root-level, no auth)

Returns application liveness and dependency connectivity. Also available at `/api/v1/health`.

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "environment": "development",
  "database": "ok",
  "redis": "ok"
}
```

`status` is `healthy` when both database and Redis are reachable, otherwise `degraded`. Used by Docker healthchecks and load balancers.

---

## Metrics

### GET /metrics  (no auth)

Prometheus-formatted metrics exposed by `prometheus-fastapi-instrumentator`. Instrumented by default with HTTP request latency histograms, request counts, and in-progress request gauges, all labeled by route, method, and status. Scraped by Prometheus without authentication. See [metrics.md](metrics.md) for the full metrics catalog and alerting recommendations.

---

## WebSocket

### WS /api/v1/ws/scan/{scan_job_id}?token=<jwt>

Stream real-time scan progress for a specific scan job.

**Authentication:** JWT access token passed as the `token` query parameter. Invalid or missing tokens close the connection with code `4401`.

**Channel:** The worker publishes JSON messages to the Redis pub/sub channel `scan:progress:{scan_job_id}`; the WebSocket handler subscribes and forwards every message to the client.

### Message types

Every message is a JSON object with `type`, `scan_job_id`, `timestamp`, and `payload`:

#### scan_progress

Emitted after each host is scanned. `payload.progress` is a 0–100 float.

```json
{
  "type": "scan_progress",
  "scan_job_id": "e5f6a7b8-...",
  "timestamp": "2026-06-19T10:06:15Z",
  "payload": {
    "task_id": "c7d8e9f0-...",
    "progress": 41.6,
    "status": "running",
    "message": "Scanned 10.0.0.5 — found 3 open port(s)",
    "data": { "current_host": "10.0.0.5", "ports_found_this_host": 3 }
  }
}
```

#### scan_complete

Emitted when the scan reaches a terminal successful state.

```json
{
  "type": "scan_complete",
  "scan_job_id": "e5f6a7b8-...",
  "timestamp": "2026-06-19T10:08:00Z",
  "payload": {
    "task_id": "c7d8e9f0-...",
    "progress": 100,
    "status": "complete",
    "message": "Scan complete. Found 18 open port(s).",
    "data": {}
  }
}
```

#### scan_error

Emitted when the scan fails. `payload.status` is `error` or `failed`.

```json
{
  "type": "scan_error",
  "scan_job_id": "e5f6a7b8-...",
  "timestamp": "2026-06-19T10:07:00Z",
  "payload": {
    "task_id": "c7d8e9f0-...",
    "progress": 0,
    "status": "error",
    "message": "Scan failed: connection refused",
    "data": {}
  }
}
```

#### scan_cancelled

Emitted when a scan is cancelled. `payload.status` is `cancelled`.

### Close codes

| Code | Meaning |
|------|---------|
| `4401` | Unauthorized — token missing, invalid, expired, or not an access token |
| `1000` | Normal closure (server shutdown / unsubscribe) |
