import { useQuery } from "@tanstack/react-query";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { TrendingUp, Activity } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { api } from "@/lib/api";
import type { ScanTimeline as ScanTimelineData } from "@/types/analytics";

interface ChartDatum {
  date: string;
  scans: number;
  findings: number;
}

function formatDay(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  });
}

function TimelineTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: { payload: ChartDatum }[];
}) {
  if (!active || !payload || payload.length === 0) return null;
  const datum = payload[0]?.payload;
  if (!datum) return null;
  return (
    <div className="rounded-lg border border-surface-800 bg-surface-900 p-2.5 shadow-lg">
      <p className="text-sm font-medium text-surface-50">
        {formatDay(datum.date)}
      </p>
      <p className="text-xs text-brand-200">{datum.scans} scans</p>
      <p className="text-xs text-warning">{datum.findings} findings</p>
    </div>
  );
}

export function ScanOverview() {
  const { data, isLoading } = useQuery<ScanTimelineData>({
    queryKey: ["scan-timeline"],
    queryFn: () => api.get("/analytics/timeline?days=7"),
  });

  const items = data?.items ?? [];
  const chartData: ChartDatum[] = items.map((item) => ({
    date: item.date,
    scans: item.scans,
    findings: item.findings,
  }));

  const totalScans = chartData.reduce((sum, d) => sum + d.scans, 0);
  const totalFindings = chartData.reduce((sum, d) => sum + d.findings, 0);

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-brand-500" />
            Scan Activity
          </CardTitle>
          <p className="mt-1 text-xs text-surface-400">Last 7 days</p>
        </div>
        {chartData.length > 0 && (
          <div className="flex items-center gap-3 text-xs">
            <span className="flex items-center gap-1.5 text-surface-300">
              <span className="inline-block h-2 w-2 rounded-full bg-brand-500" />
              {totalScans} scans
            </span>
            <span className="flex items-center gap-1.5 text-surface-300">
              <span className="inline-block h-2 w-2 rounded-full bg-warning" />
              {totalFindings} findings
            </span>
          </div>
        )}
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex h-[260px] items-center justify-center">
            <Activity className="h-5 w-5 animate-pulse text-surface-500" />
          </div>
        ) : chartData.length === 0 ? (
          <div className="flex h-[260px] flex-col items-center justify-center gap-2">
            <TrendingUp className="h-6 w-6 text-surface-600" />
            <p className="text-sm text-surface-500">
              No scan activity yet. Start a scan to track progress over time.
            </p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart
              data={chartData}
              margin={{ top: 8, right: 8, left: -16, bottom: 0 }}
            >
              <defs>
                <linearGradient id="scansArea" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366f1" stopOpacity={0.5} />
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="findingsArea" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#1e293b"
                vertical={false}
              />
              <XAxis
                dataKey="date"
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={false}
                tickFormatter={formatDay}
              />
              <YAxis
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
              />
              <Tooltip
                content={<TimelineTooltip />}
                cursor={{ stroke: "#1e293b", strokeWidth: 1 }}
              />
              <Area
                type="monotone"
                dataKey="scans"
                stroke="#6366f1"
                strokeWidth={2}
                fill="url(#scansArea)"
              />
              <Area
                type="monotone"
                dataKey="findings"
                stroke="#f59e0b"
                strokeWidth={2}
                fill="url(#findingsArea)"
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
