export type WsMessageType =
  | "scan_progress"
  | "scan_log"
  | "scan_result"
  | "scan_complete"
  | "scan_error"
  | "scan_cancelled";

export interface WsMessage {
  type: WsMessageType;
  scan_job_id: string;
  timestamp: string;
  payload: Record<string, unknown>;
}

export interface WsProgressPayload {
  progress: number;
  current_host?: string;
  hosts_completed: number;
  hosts_total: number;
  ports_found: number;
}

export interface WsLogPayload {
  level: "info" | "warn" | "error" | "debug";
  message: string;
  host?: string;
  port?: number;
}

export interface WsResultPayload {
  host: string;
  hostname?: string;
  state: "up" | "down";
  ports: Array<{
    port: number;
    protocol: string;
    state: string;
    service?: string;
  }>;
}
