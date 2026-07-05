# Metrics

This document defines the success metrics for the IPAM Multi-Cloud Security Platform, the Prometheus metrics exposed at `/metrics`, how each success metric is calculated, a Grafana dashboard template, and alerting recommendations.

---

## Success Metrics

The platform tracks eight success metrics that measure scanning reliability, detection quality, performance, availability, and discovery accuracy.

### 1. Scan Completion Rate

The percentage of submitted scans that reach a terminal status (`completed`, `failed`, or `cancelled`) — the primary reliability indicator. A scan that hangs in `running` indefinitely is a reliability failure.

**Formula:**

```
scan_completion_rate = (scans with terminal status / total submitted scans) × 100
```

**Measurement:**

```sql
SELECT
  100.0 * COUNT(*) FILTER (
    WHERE status IN ('completed', 'failed', 'cancelled')
  ) / NULLIF(COUNT(*), 0) AS completion_rate
FROM scan_jobs
WHERE created_at >= now() - interval '7 days';
```

**Target:** ≥ 95%. Investigate any sustained drop — it usually indicates worker crashes (check `reject_on_worker_lost`), exhausted time limits, or database connectivity issues.

---

### 2. Mean Scan Duration

The average wall-clock time from `started_at` to `completed_at` for completed scans. Drives capacity planning (how many scans the worker pool can sustain) and user experience expectations.

**Formula:**

```
mean_scan_duration = AVG(EXTRACT(EPOCH FROM (completed_at - started_at)))
                     for scan_jobs WHERE status = 'completed'
```

**Measurement:**

```sql
SELECT
  AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) AS mean_duration_seconds,
  PERCENTILE_CONT(0.5)  WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - started_at))) AS p50,
  PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - started_at))) AS p95
FROM scan_jobs
WHERE status = 'completed'
  AND completed_at >= now() - interval '7 days';
```

**Target:** Depends on profile and target size. Establish a baseline per profile (`quick`, `standard`, `thorough`) and alert on sustained deviation. The Celery hard time limit is 900 seconds — scans approaching that indicate targets too large for one task.

---

### 3. False Positive Rate

The percentage of ports flagged as `open` that are actually `closed` or `filtered` when re-verified. Measures scanner accuracy.

**Formula:**

```
false_positive_rate = (ports confirmed not-open on re-verification / total ports flagged open) × 100
```

**Measurement:** Requires a re-verification workflow (a follow-up scan or an external ground-truth source). Track as:

```sql
-- With a verification_flag column or a re-scan comparison job
SELECT
  100.0 * COUNT(*) FILTER (WHERE verification_status IN ('closed', 'filtered'))
         / NULLIF(COUNT(*), 0) AS fp_rate
FROM port_results
WHERE state = 'open'
  AND verified_at IS NOT NULL;
```

**Target:** ≤ 5%. The async TCP connect scanner with a per-profile `timeout` minimizes false positives, but transient network conditions and firewalls that silently drop SYN packets can cause ambiguity between `open` and `filtered`.

---

### 4. Vulnerability Detection Coverage

The percentage of known management ports assessed by at least one scan in the period. Measures whether the platform is actually evaluating the full risk surface.

**Formula:**

```
detection_coverage = (distinct management ports assessed / total known management ports) × 100
```

The `standard` profile scans 31+ known management ports. The known set is defined in `RiskClassifier.SERVICE_RISK_BASELINE` (35 entries) and the `standard` profile port list.

**Measurement:**

```sql
-- Known management ports = 35 (RiskClassifier baseline set)
WITH known AS (SELECT COUNT(*) AS n FROM (VALUES
  (23),(3389),(3200),(3300),(3601),(445),(139),(27017),(2049),(5900),
  (5901),(491),(1494),(2598),(3901),(5432),(6379),(3306),(1433),(1521),
  (111),(135),(5985),(22),(21),(389),(5986),(25),(161),(9090),(53),(80),
  (8080),(443),(993),(995)
) AS v(port))
SELECT
  100.0 * COUNT(DISTINCT pr.port) / (SELECT n FROM known) AS coverage
FROM port_results pr
JOIN scan_jobs sj ON sj.id = pr.scan_job_id
WHERE sj.completed_at >= now() - interval '30 days';
```

**Target:** ≥ 90% coverage of the `RiskClassifier` baseline port set over a rolling 30-day window.

---

### 5. Time-to-Remediation

The average elapsed time from a finding being recorded to it being resolved (e.g., the port is no longer open on a subsequent scan, or a ticket is closed). Measures operational follow-through.

**Formula:**

```
time_to_remediation = AVG(time from first finding to confirmed resolution)
```

**Measurement:** Requires tracking finding lifecycle (open → resolved). With a remediation workflow:

```sql
SELECT
  AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 86400) AS avg_days_to_remediate
FROM findings
WHERE resolved_at IS NOT NULL
  AND resolved_at >= now() - interval '30 days';
```

**Target:** Critical findings remediated within 7 days; high within 30 days. Track by severity — critical management ports (RDP, Telnet, database ports) exposed to the internet should be driven to the shortest SLA.

---

### 6. API Response Latency (p50 / p95 / p99)

The request latency distribution for the FastAPI application, measured at the HTTP layer. Directly available from Prometheus.

**Formula:**

```
latency_pXX = histogram_quantile(0.XX, rate(http_request_duration_seconds_bucket[5m]))
```

**Measurement:** Query Prometheus (see [Prometheus Metrics](#prometheus-metrics-exposed-at-metrics)):

```promql
# p50
histogram_quantile(0.50, rate(http_request_duration_seconds_bucket[5m]))

# p95
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# p99
histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))
```

**Targets:** p50 ≤ 100ms, p95 ≤ 500ms, p99 ≤ 1s for read endpoints. Scan submission (`POST /scans/`) should return within 200ms (it only enqueues the Celery task). Result retrieval latency scales with result set size — paginate with `size`.

---

### 7. System Uptime

The percentage of time the application is available and healthy over a rolling window.

**Formula:**

```
uptime = (total time - downtime) / total time × 100
```

**Measurement:** Probe `GET /health` with an external uptime monitor (e.g. Prometheus blackbox exporter, Uptime Kuma, Pingdom) at 30-second intervals. The endpoint returns `status: healthy` or `status: degraded`:

```promql
# blackbox exporter success over 24h
avg_over_time(probe_success[24h]) * 100
```

**Target:** ≥ 99.5% per 30-day window. Note that `degraded` (a dependency unreachable) still answers — decide whether to count it as available based on your SLA.

---

### 8. Discovery Accuracy

The ratio of IPs discovered by the platform to the actual cloud inventory. Measures whether the agentless discovery is complete.

**Formula:**

```
discovery_accuracy = (discovered IPs matching actual inventory / actual inventory IPs) × 100
```

**Measurement:** Compare `ip_addresses` rows from a discovery run against an independent inventory source (cloud provider console, CMDB, or a second tool):

```sql
SELECT
  100.0 * COUNT(*) FILTER (WHERE matched_in_cmdb) / NULLIF(COUNT(*), 0) AS accuracy
FROM ip_addresses
WHERE discovered_at >= now() - interval '7 days';
```

Also track the inverse — IPs in the CMDB not discovered by the platform — as the miss rate.

**Target:** ≥ 95% accuracy with < 5% miss rate. Drops usually indicate stale credentials, missing regions in the provider config, or IAM permissions too narrow to enumerate all resources.

---

## Prometheus Metrics Exposed at /metrics

The FastAPI application exposes Prometheus metrics at `GET /metrics` via `prometheus-fastapi-instrumentator`. The endpoint is unauthenticated so Prometheus can scrape it without credential management.

### Default instrumented metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `http_requests_total` | counter | `method`, `handler`, `status`, `status_group` | Total HTTP requests processed |
| `http_request_duration_seconds` | histogram | `method`, `handler`, `status` | Request latency in seconds |
| `http_request_duration_seconds_bucket` | histogram buckets | `le`, `method`, `handler`, `status` | Cumulative latency buckets |
| `http_request_duration_seconds_sum` | counter | `method`, `handler`, `status` | Cumulative latency sum |
| `http_request_duration_seconds_count` | counter | `method`, `handler`, `status` | Cumulative request count |
| `http_in_progress_requests` | gauge | `method`, `handler` | Requests currently in flight |

### Scrape configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: ipam_app
    metrics_path: /metrics
    scrape_interval: 15s
    static_configs:
      - targets: ["app:8000"]
        labels:
          service: ipam
          environment: production
```

If scraping through nginx, target `https://scanner.example.com` and set `scheme: https` with `insecure_skip_verify: true` for self-signed certs.

### Derived metrics from the database

Some success metrics (completion rate, mean duration, detection coverage) are not directly exported by the default instrumentator. To expose them, either:

1. **Custom Prometheus exporter** — add a periodic Celery task or a `/metrics/custom` endpoint that queries the database and emits gauges. Recommended for production.
2. **Grafana queries via a Postgres datasource** — connect Grafana directly to PostgreSQL (read-only user) and run the SQL queries above as dashboard panels.

---

## Grafana Dashboard Template

A Grafana dashboard on a Prometheus datasource with the following panels. Panel titles use the Grafana convention; each lists the PromQL or SQL query.

### Row 1: HTTP performance

| Panel | Type | Query |
|-------|------|-------|
| Request Rate (req/s) | Time series | `sum(rate(http_requests_total[5m])) by (status_group)` |
| p50 / p95 / p99 Latency | Time series | `histogram_quantile(0.50, rate(http_request_duration_seconds_bucket[5m]))`, repeat for 0.95, 0.99 |
| Error Rate (%) | Stat | `100 * sum(rate(http_requests_total{status_group=~"5.."}[5m])) / sum(rate(http_requests_total[5m]))` |
| In-Progress Requests | Time series | `http_in_progress_requests` |

### Row 2: Scan reliability (Postgres datasource)

| Panel | Type | Query |
|-------|------|-------|
| Scan Completion Rate (%) | Stat | success metric #1 SQL |
| Mean Scan Duration (s) | Time series | success metric #2 SQL grouped by day |
| Scans by Status | Pie chart | `SELECT status, COUNT(*) FROM scan_jobs WHERE created_at >= now() - interval '7 days' GROUP BY status` |

### Row 3: Detection quality (Postgres datasource)

| Panel | Type | Query |
|-------|------|-------|
| Vulnerability Detection Coverage (%) | Stat | success metric #4 SQL |
| Open Ports by Severity | Bar chart | `SELECT risk_level, COUNT(*) FROM port_results WHERE state = 'open' GROUP BY risk_level` |
| Top Open Ports | Table | `SELECT port, service_name, COUNT(*) FROM port_results WHERE state = 'open' GROUP BY port, service_name ORDER BY COUNT(*) DESC LIMIT 20` |

### Row 4: Discovery & analytics

| Panel | Type | Query / Source |
|-------|------|----------------|
| Discovered IPs by Provider | Bar chart | `SELECT cp.provider_type, COUNT(*) FROM ip_addresses ia JOIN cloud_providers cp ON cp.id = ia.cloud_provider_id GROUP BY cp.provider_type` |
| Scans Timeline | Time series | `/api/v1/analytics/timeline` (or Postgres) |
| Risk Summary | Stat row | `/api/v1/analytics/risk-summary` |

### Dashboard JSON skeleton

```json
{
  "title": "IPAM Multi-Cloud Security Platform",
  "schemaVersion": 39,
  "time": { "from": "now-7d", "to": "now" },
  "refresh": "30s",
  "panels": [
    {
      "title": "Request Rate",
      "type": "timeseries",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "targets": [{ "expr": "sum(rate(http_requests_total[5m])) by (status_group)" }]
    },
    {
      "title": "p95 Latency",
      "type": "stat",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "targets": [{ "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))" }],
      "fieldConfig": { "defaults": { "unit": "s" } }
    },
    {
      "title": "Scan Completion Rate",
      "type": "stat",
      "datasource": { "type": "postgres", "uid": "postgres-ro" },
      "targets": [{
        "rawSql": "SELECT 100.0 * COUNT(*) FILTER (WHERE status IN ('completed','failed','cancelled')) / NULLIF(COUNT(*),0) FROM scan_jobs WHERE created_at >= now() - interval '7 days'"
      }]
    }
  ]
}
```

---

## Alerting Recommendations

Configure Prometheus alerting rules with the thresholds below. Route alerts through Alertmanager to your notification channel (Slack, PagerDuty, email).

### `alerting_rules.yml`

```yaml
groups:
  - name: ipam_http
    rules:
      - alert: IpamHighErrorRate
        expr: |
          100 * sum(rate(http_requests_total{status_group=~"5.."}[5m]))
            / sum(rate(http_requests_total[5m])) > 5
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "IPAM error rate above 5%"
          description: "HTTP 5xx responses exceed 5% of total traffic for 10 minutes."

      - alert: IpamHighLatencyP95
        expr: |
          histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "IPAM p95 latency above 1s"
          description: "95th-percentile API latency exceeds 1 second for 10 minutes."

      - alert: IpamAppDown
        expr: up{job="ipam_app"} == 0
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "IPAM app unreachable"
          description: "Prometheus cannot scrape the IPAM app /metrics endpoint."

  - name: ipam_scans
    rules:
      - alert: IpamLowScanCompletionRate
        expr: ipam_scan_completion_rate < 95
        for: 1h
        labels: { severity: warning }
        annotations:
          summary: "IPAM scan completion rate below 95%"
          description: "Less than 95% of scans reach terminal status over the last hour."

      - alert: IpamScanDurationHigh
        expr: ipam_mean_scan_duration_seconds > 600
        for: 30m
        labels: { severity: warning }
        annotations:
          summary: "IPAM mean scan duration above 10 minutes"
          description: "Average scan duration is approaching the 900s hard time limit."

  - name: ipam_health
    rules:
      - alert: IpamDegraded
        expr: ipam_health_status{status="degraded"} == 1
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "IPAM health degraded"
          description: "A dependency (database or Redis) is unreachable."

      - alert: IpamUptimeLow
        expr: avg_over_time(probe_success[24h]) * 100 < 99.5
        for: 30m
        labels: { severity: critical }
        annotations:
          summary: "IPAM uptime below 99.5%"
          description: "24-hour rolling uptime dropped below the 99.5% SLO."
```

### Threshold summary

| Metric | Warning | Critical |
|--------|---------|----------|
| Scan completion rate | < 95% for 1h | < 80% for 15m |
| Mean scan duration | > 600s for 30m | > 850s (near hard limit) for 10m |
| API p95 latency | > 1s for 10m | > 2s for 5m |
| HTTP error rate (5xx) | > 5% for 10m | > 10% for 5m |
| System uptime (24h) | < 99.5% for 30m | < 99% for 15m |
| Discovery accuracy | < 95% | < 85% |
| Health status | degraded for 5m | app down for 2m |
