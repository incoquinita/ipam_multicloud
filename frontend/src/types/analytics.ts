/**
 * Analytics types — mirror the backend analytics schemas
 * (`app/schemas/analytics.py`) so data is parsed into a trusted
 * shape at the API boundary.
 */

export interface DashboardStats {
  total_targets: number;
  total_scans: number;
  active_scans: number;
  completed_scans: number;
  total_open_ports: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  total_ips: number;
  scans_last_7_days: number;
}

export interface PortDistributionItem {
  port: number;
  service_name: string;
  count: number;
  critical_count: number;
}

export interface PortDistribution {
  items: PortDistributionItem[];
}

export interface ScanTimelineItem {
  /** ISO date string (YYYY-MM-DD). */
  date: string;
  scans: number;
  findings: number;
}

export interface ScanTimeline {
  items: ScanTimelineItem[];
}
