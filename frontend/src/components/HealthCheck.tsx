import { useEffect, useState } from "react";
import { api } from "@/lib/api";

interface HealthStatus {
  status: string;
  version: string;
  database?: string;
  redis?: string;
}

export function HealthCheck() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const result = await api.get<HealthStatus>("/health");
        setHealth(result);
        setError(null);
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Connection failed",
        );
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 30_000);
    return () => clearInterval(interval);
  }, []);

  if (error) {
    return (
      <div className="flex items-center gap-2 rounded-lg bg-danger/10 px-3 py-1 text-xs text-danger">
        <span className="h-2 w-2 rounded-full bg-danger" />
        API: Disconnected
      </div>
    );
  }

  if (!health) {
    return (
      <div className="flex items-center gap-2 rounded-lg bg-warning/10 px-3 py-1 text-xs text-warning">
        <span className="h-2 w-2 animate-pulse rounded-full bg-warning" />
        Checking...
      </div>
    );
  }

  const isHealthy = health.status === "healthy";
  return (
    <div className="flex items-center gap-2 rounded-lg bg-surface-800 px-3 py-1 text-xs">
      <span
        className={`h-2 w-2 rounded-full ${
          isHealthy ? "bg-success" : "bg-danger"
        }`}
      />
      <span className="text-surface-400">API v{health.version}</span>
      {health.database && (
        <span className="text-surface-500">DB: {health.database}</span>
      )}
    </div>
  );
}
