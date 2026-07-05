export interface HealthCheck {
  status: "healthy" | "unhealthy" | "degraded";
  version: string;
  environment?: string;
  database?: string;
  redis?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface ApiError {
  detail: string;
  code?: string;
  status?: number;
}
