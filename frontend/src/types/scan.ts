export type ScanStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface Scan {
  id: string;
  name: string;
  description?: string;
  status: ScanStatus;
  progress: number;
  target_ids: string[];
  provider_ids?: string[];
  ports?: string;
  scan_type: "quick" | "standard" | "thorough" | "custom";
  created_at: string;
  started_at?: string;
  completed_at?: string;
  duration_seconds?: number;
  result_summary?: ScanResultSummary;
  error_message?: string;
}

export interface ScanResultSummary {
  total_hosts: number;
  hosts_up: number;
  hosts_down: number;
  total_ports: number;
  open_ports: number;
  closed_ports: number;
  filtered_ports: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
}

export interface ScanResult {
  id: string;
  scan_id: string;
  host: string;
  hostname?: string;
  state: "up" | "down";
  ports: PortResult[];
  os?: string;
  mac_address?: string;
  vendor?: string;
}

export interface PortResult {
  port: number;
  protocol: "tcp" | "udp";
  state: "open" | "closed" | "filtered";
  service?: string;
  version?: string;
  cves?: string[];
  risk_level?: "critical" | "high" | "medium" | "low" | "info";
}

export interface ScanFormData {
  name: string;
  description?: string;
  target_ids: string[];
  provider_ids?: string[];
  ports?: string;
  scan_type: "quick" | "standard" | "thorough" | "custom";
  /** Optional scan behaviour overrides (banner grab, HTTP analysis, ...). */
  config?: Record<string, unknown>;
}

// ─────────────────────────────────────────────────────────────────────
// Backend-accurate scan job & result types.
//
// These mirror the FastAPI response schemas (research-verified against
// `app/schemas/scan_job.py` and `app/schemas/scan_result.py`) and back the
// scan results detail view. The legacy `Scan` / `PortResult` interfaces
// above are retained for backward compatibility with existing list views.
// ─────────────────────────────────────────────────────────────────────

export type ScanJobStatus =
  | "pending"
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface ScanJob {
  id: string;
  target_id: string;
  scan_type: string;
  status: ScanJobStatus;
  progress: number;
  config?: Record<string, unknown> | null;
  total_ips?: number | null;
  ips_scanned?: number | null;
  ports_found?: number | null;
  findings_critical?: number | null;
  findings_high?: number | null;
  started_at?: string | null;
  completed_at?: string | null;
  duration_seconds?: number | null;
  error_message?: string | null;
  celery_task_id?: string | null;
  created_at: string;
  updated_at: string;
}

export type RiskLevel = "critical" | "high" | "medium" | "low" | "info";

/** Single port-result row — `GET /scans/{id}/results/ports` items. */
export interface PortResultItem {
  id: string;
  scan_job_id: string;
  ip_address_id?: string | null;
  port: number;
  protocol: string;
  state: string;
  service_name?: string | null;
  service_product?: string | null;
  service_version?: string | null;
  banner?: string | null;
  risk_level?: RiskLevel | null;
  risk_score?: number | null;
  cve_ids?: string[] | null;
  scanned_at: string;
}

/**
 * Paginated port-results envelope.
 *
 * NOTE: unlike the generic `PaginatedResponse`, this endpoint serialises
 * `page_size` / `total_pages` (no `size` / `pages` aliases).
 */
export interface PortResultListResponse {
  items: PortResultItem[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

/** HTTP analysis row — `GET /scans/{id}/results/http` (returned as a bare array). */
export interface HttpAnalysisItem {
  id: string;
  scan_job_id: string;
  ip_address_id?: string | null;
  port: number;
  url?: string | null;
  status_code?: number | null;
  is_static?: boolean | null;
  has_login?: boolean | null;
  has_rate_limit?: boolean | null;
  response_headers?: Record<string, unknown> | null;
  technologies?: string[] | null;
  certificates?: Record<string, unknown> | null;
  security_headers?: Record<string, unknown> | null;
  security_headers_score?: number | null;
  tls_version?: string | null;
  title?: string | null;
  static_evidence?: string[] | null;
  login_evidence?: string[] | null;
  rate_limit_details?: Record<string, unknown> | null;
  analyzed_at: string;
}
