import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import {
  ArrowLeft,
  RefreshCw,
  Globe,
  ShieldAlert,
  Lock,
  Gauge,
  Server,
  Clock,
  CircleDot,
} from "lucide-react";

import { api } from "@/lib/api";
import { formatDate, formatDuration, cn } from "@/lib/utils";
import {
  useScanJob,
  useScanPortResults,
  useScanHttpAnalyses,
} from "@/hooks/useScans";
import type { Target } from "@/hooks/useTargets";
import type {
  ScanStatus,
  PortResultItem,
  HttpAnalysisItem,
  RiskLevel,
} from "@/types/scan";

import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { DataTable } from "@/components/ui/DataTable";
import {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
} from "@/components/ui/Tabs";

// ── Risk → badge colour mapping ────────────────────────────────────────
// A single source of truth so the table cell and the risk summary agree.

const riskVariant: Record<RiskLevel, "danger" | "warning" | "info" | "brand" | "default"> = {
  critical: "danger",
  high: "warning",
  medium: "info",
  low: "brand",
  info: "default",
};

const riskBarColor: Record<RiskLevel, string> = {
  critical: "bg-danger",
  high: "bg-warning",
  medium: "bg-info",
  low: "bg-brand-500",
  info: "bg-surface-500",
};

const SEVERITY_ORDER: RiskLevel[] = ["critical", "high", "medium", "low", "info"];

/** Map the backend's `ScanJobStatus` onto the legacy `ScanStatus` the
 *  `StatusBadge` understands (collapsing `queued` → `pending`). */
function toBadgeStatus(status: string): ScanStatus {
  return status === "queued" ? "pending" : (status as ScanStatus);
}

export function ScanResults() {
  const { id } = useParams<{ id: string }>();

  const {
    data: scan,
    isLoading: scanLoading,
    isError: scanError,
  } = useScanJob(id ?? "");
  const { data: portData, isLoading: portsLoading } = useScanPortResults(
    id ?? "",
  );
  const { data: httpAnalyses, isLoading: httpLoading } = useScanHttpAnalyses(
    id ?? "",
  );

  // Resolve the target UUID → a human-readable target_value, fetched only
  // once the scan job (and therefore target_id) is known.
  const { data: target } = useQuery<Target>({
    queryKey: ["target", scan?.target_id],
    queryFn: () => api.get<Target>(`/targets/${scan!.target_id}`),
    enabled: !!scan?.target_id,
  });

  if (!id) {
    return (
      <div className="p-6">
        <p className="text-sm text-surface-400">No scan id provided.</p>
      </div>
    );
  }

  if (scanLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <RefreshCw className="h-6 w-6 animate-spin text-surface-500" />
      </div>
    );
  }

  if (scanError || !scan) {
    return (
      <div className="space-y-4 p-6">
        <BackLink />
        <Card>
          <CardContent className="py-10 text-center">
            <ShieldAlert className="mx-auto mb-3 h-8 w-8 text-danger" />
            <p className="text-sm text-surface-300">
              Could not load scan details.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const ports = portData?.items ?? [];
  const riskCounts = countByRisk(ports);
  const maxRiskCount = Math.max(1, ...SEVERITY_ORDER.map((s) => riskCounts[s]));

  return (
    <div className="space-y-6 p-6">
      <BackLink />

      {/* ── Scan header ───────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-3">
                <CardTitle className="font-mono text-base">
                  Scan {scan.id.slice(0, 8)}
                </CardTitle>
                <StatusBadge status={toBadgeStatus(scan.status)} />
                <Badge variant="info">{scan.scan_type}</Badge>
              </div>
              <p className="text-xs text-surface-400">
                Created {formatDate(scan.created_at)}
              </p>
            </div>
            <div className="w-full max-w-sm">
              <ProgressBar
                value={scan.progress}
                showLabel
                variant={
                  scan.status === "failed"
                    ? "danger"
                    : scan.status === "completed"
                      ? "success"
                      : "info"
                }
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
            <StatCell
              icon={<Server className="h-3.5 w-3.5" />}
              label="Target"
              value={target?.target_value ?? scan.target_id}
              mono
            />
            <StatCell
              icon={<CircleDot className="h-3.5 w-3.5" />}
              label="IPs scanned"
              value={scan.ips_scanned ?? "—"}
            />
            <StatCell
              icon={<Gauge className="h-3.5 w-3.5" />}
              label="Ports found"
              value={scan.ports_found ?? "—"}
            />
            <StatCell
              icon={<ShieldAlert className="h-3.5 w-3.5" />}
              label="Critical"
              value={scan.findings_critical ?? 0}
              accent="text-danger"
            />
            <StatCell
              icon={<Clock className="h-3.5 w-3.5" />}
              label="Duration"
              value={
                scan.duration_seconds != null
                  ? formatDuration(scan.duration_seconds)
                  : "—"
              }
            />
            <StatCell
              icon={<Clock className="h-3.5 w-3.5" />}
              label="Completed"
              value={
                scan.completed_at ? formatDate(scan.completed_at) : "—"
              }
            />
          </div>
          {scan.error_message && (
            <p className="mt-4 rounded-lg border border-danger/30 bg-danger/10 p-3 text-xs text-danger">
              {scan.error_message}
            </p>
          )}
        </CardContent>
      </Card>

      {/* ── Result tabs ───────────────────────────────────────────── */}
      <Tabs defaultValue="ports">
        <TabsList>
          <TabsTrigger value="ports">
            Port Results{ports.length > 0 ? ` (${ports.length})` : ""}
          </TabsTrigger>
          <TabsTrigger value="http">
            HTTP Analysis
            {httpAnalyses && httpAnalyses.length > 0
              ? ` (${httpAnalyses.length})`
              : ""}
          </TabsTrigger>
          <TabsTrigger value="risk">Risk Summary</TabsTrigger>
        </TabsList>

        {/* Port Results ────────────────────────────────────────────── */}
        <TabsContent value="ports">
          <Card>
            <CardContent className="pt-6">
              {portsLoading ? (
                <LoadingRow />
              ) : ports.length === 0 ? (
                <EmptyRow message="No port results yet." />
              ) : (
                <DataTable
                  columns={portColumns}
                  data={ports}
                  pageSize={10}
                />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* HTTP Analysis ───────────────────────────────────────────── */}
        <TabsContent value="http">
          {httpLoading ? (
            <Card>
              <CardContent className="pt-6">
                <LoadingRow />
              </CardContent>
            </Card>
          ) : !httpAnalyses || httpAnalyses.length === 0 ? (
            <Card>
              <CardContent className="pt-6">
                <EmptyRow message="No HTTP analyses for this scan." />
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {httpAnalyses.map((h) => (
                <HttpCard key={h.id} item={h} />
              ))}
            </div>
          )}
        </TabsContent>

        {/* Risk Summary ────────────────────────────────────────────── */}
        <TabsContent value="risk">
          <Card>
            <CardHeader>
              <CardTitle>Findings by Severity</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-xs text-surface-400">
                Aggregated from {ports.length} port result
                {ports.length === 1 ? "" : "s"}.
              </p>
              {SEVERITY_ORDER.map((level) => (
                <RiskBar
                  key={level}
                  level={level}
                  count={riskCounts[level]}
                  max={maxRiskCount}
                />
              ))}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ── Port results table ─────────────────────────────────────────────────

const portColumns: ColumnDef<PortResultItem>[] = [
  {
    accessorKey: "port",
    header: "Port",
    cell: ({ row }) => (
      <span className="font-mono font-medium text-surface-100">
        {row.getValue("port")}
      </span>
    ),
  },
  {
    accessorKey: "protocol",
    header: "Protocol",
    cell: ({ row }) => (
      <span className="text-surface-300 uppercase">
        {row.getValue("protocol")}
      </span>
    ),
  },
  {
    accessorKey: "state",
    header: "State",
    cell: ({ row }) => {
      const state = row.getValue("state") as string;
      return (
        <Badge
          variant={
            state === "open"
              ? "warning"
              : state === "filtered"
                ? "info"
                : "default"
          }
        >
          {state}
        </Badge>
      );
    },
  },
  {
    accessorKey: "service_name",
    header: "Service",
    cell: ({ row }) => (
      <span className="text-surface-200">
        {(row.getValue("service_name") as string | null) ?? "—"}
      </span>
    ),
  },
  {
    accessorKey: "banner",
    header: "Banner",
    cell: ({ row }) => {
      const banner = row.getValue("banner") as string | null;
      return banner ? (
        <span
          className="block max-w-[280px] truncate font-mono text-xs text-surface-400"
          title={banner}
        >
          {banner}
        </span>
      ) : (
        <span className="text-surface-500">—</span>
      );
    },
  },
  {
    accessorKey: "risk_level",
    header: "Risk",
    cell: ({ row }) => {
      const level = row.getValue("risk_level") as RiskLevel | null;
      return level ? (
        <Badge variant={riskVariant[level]} className="uppercase">
          {level}
        </Badge>
      ) : (
        <span className="text-surface-500">—</span>
      );
    },
  },
  {
    accessorKey: "risk_score",
    header: "Score",
    cell: ({ row }) => {
      const score = row.getValue("risk_score") as number | null;
      return score != null ? (
        <span className="font-mono text-surface-100">{score.toFixed(1)}</span>
      ) : (
        <span className="text-surface-500">—</span>
      );
    },
  },
];

// ── HTTP analysis card ─────────────────────────────────────────────────

function HttpCard({ item }: { item: HttpAnalysisItem }) {
  return (
    <Card>
      <CardContent className="space-y-3 pt-6">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-surface-100">
              {item.title ?? item.url ?? `Port ${item.port}`}
            </p>
            {item.url && (
              <p className="mt-0.5 flex items-center gap-1 truncate font-mono text-xs text-surface-400">
                <Globe className="h-3 w-3" />
                {item.url}
              </p>
            )}
          </div>
          {item.status_code != null && (
            <Badge variant={item.status_code < 400 ? "success" : "danger"}>
              {item.status_code}
            </Badge>
          )}
        </div>

        <div className="grid grid-cols-2 gap-2 text-xs">
          <Flag label="Static" value={item.is_static} />
          <Flag label="Login" value={item.has_login} icon={<Lock className="h-3 w-3" />} />
          <Flag label="Rate limited" value={item.has_rate_limit} />
          <div className="rounded-lg border border-surface-800 bg-surface-950 p-2">
            <p className="text-surface-500">Headers score</p>
            <p
              className={cn(
                "mt-0.5 font-mono font-medium",
                (item.security_headers_score ?? 0) >= 75
                  ? "text-success"
                  : (item.security_headers_score ?? 0) >= 50
                    ? "text-warning"
                    : "text-danger",
              )}
            >
              {item.security_headers_score != null
                ? `${item.security_headers_score}/100`
                : "—"}
            </p>
          </div>
        </div>

        {item.technologies && item.technologies.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {item.technologies.map((tech) => (
              <Badge key={tech} variant="brand">
                {tech}
              </Badge>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function Flag({
  label,
  value,
  icon,
}: {
  label: string;
  value: boolean | null | undefined;
  icon?: React.ReactNode;
}) {
  const known = value != null;
  return (
    <div className="rounded-lg border border-surface-800 bg-surface-950 p-2">
      <p className="flex items-center gap-1 text-surface-500">
        {icon}
        {label}
      </p>
      <p
        className={cn(
          "mt-0.5 font-medium",
          !known
            ? "text-surface-500"
            : value
              ? "text-warning"
              : "text-surface-300",
        )}
      >
        {!known ? "—" : value ? "Yes" : "No"}
      </p>
    </div>
  );
}

// ── Risk summary bar ───────────────────────────────────────────────────

function RiskBar({
  level,
  count,
  max,
}: {
  level: RiskLevel;
  count: number;
  max: number;
}) {
  const pct = Math.round((count / max) * 100);
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-sm">
        <span className="flex items-center gap-2">
          <Badge variant={riskVariant[level]} className="uppercase">
            {level}
          </Badge>
        </span>
        <span className="font-mono text-surface-300">{count}</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-surface-800">
        <div
          className={cn("h-full rounded-full transition-all duration-500", riskBarColor[level])}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

// ── Helpers & small presentational pieces ──────────────────────────────

function countByRisk(ports: PortResultItem[]): Record<RiskLevel, number> {
  const counts: Record<RiskLevel, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const p of ports) {
    if (p.risk_level) counts[p.risk_level] += 1;
  }
  return counts;
}

function StatCell({
  icon,
  label,
  value,
  mono,
  accent,
}: {
  icon: React.ReactNode;
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  accent?: string;
}) {
  return (
    <div className="rounded-lg border border-surface-800 bg-surface-950 p-3">
      <p className="flex items-center gap-1.5 text-xs text-surface-500">
        {icon}
        {label}
      </p>
      <p
        className={cn(
          "mt-1 truncate text-sm font-medium text-surface-100",
          mono && "font-mono text-xs",
          accent,
        )}
        title={typeof value === "string" ? value : undefined}
      >
        {value}
      </p>
    </div>
  );
}

function BackLink() {
  return (
    <Link
      to="/scans"
      className="inline-flex items-center gap-1.5 text-sm text-surface-400 transition-colors hover:text-surface-100"
    >
      <ArrowLeft className="h-4 w-4" />
      Back to scans
    </Link>
  );
}

function LoadingRow() {
  return (
    <div className="flex items-center justify-center py-10">
      <RefreshCw className="h-5 w-5 animate-spin text-surface-500" />
    </div>
  );
}

function EmptyRow({ message }: { message: string }) {
  return (
    <div className="flex items-center justify-center py-10">
      <p className="text-sm text-surface-500">{message}</p>
    </div>
  );
}
