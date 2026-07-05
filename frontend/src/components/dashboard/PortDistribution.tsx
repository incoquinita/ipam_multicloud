import { useQuery } from "@tanstack/react-query";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { Network, Activity } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import type { PortDistribution as PortDistributionData } from "@/types/analytics";

interface ChartDatum {
  port: number;
  count: number;
  service_name: string;
  critical_count: number;
}

function PortTooltip({
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
        :{datum.port} · {datum.service_name || "unknown"}
      </p>
      <p className="text-xs text-surface-300">{datum.count} findings</p>
      {datum.critical_count > 0 && (
        <p className="text-xs text-danger">{datum.critical_count} critical</p>
      )}
    </div>
  );
}

export function PortDistribution() {
  const { data, isLoading } = useQuery<PortDistributionData>({
    queryKey: ["port-distribution"],
    queryFn: () => api.get("/analytics/port-distribution?limit=10"),
  });

  const items = data?.items ?? [];
  const chartData: ChartDatum[] = items.map((item) => ({
    port: item.port,
    count: item.count,
    service_name: item.service_name,
    critical_count: item.critical_count,
  }));

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Network className="h-4 w-4 text-brand-500" />
            Port Distribution
          </CardTitle>
          <p className="mt-1 text-xs text-surface-400">
            Top open ports by finding count
          </p>
        </div>
        {chartData.length > 0 && (
          <Badge variant="brand">{chartData.length} ports</Badge>
        )}
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex h-[260px] items-center justify-center">
            <Activity className="h-5 w-5 animate-pulse text-surface-500" />
          </div>
        ) : chartData.length === 0 ? (
          <div className="flex h-[260px] flex-col items-center justify-center gap-2">
            <Network className="h-6 w-6 text-surface-600" />
            <p className="text-sm text-surface-500">
              No port findings yet. Run a scan to see distribution.
            </p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <BarChart
              data={chartData}
              margin={{ top: 8, right: 8, left: -16, bottom: 0 }}
            >
              <defs>
                <linearGradient id="portBar" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#6366f1" stopOpacity={0.95} />
                  <stop offset="100%" stopColor="#4338ca" stopOpacity={0.55} />
                </linearGradient>
              </defs>
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#1e293b"
                vertical={false}
              />
              <XAxis
                dataKey="port"
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={false}
                tickFormatter={(value) => `:${value}`}
              />
              <YAxis
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
              />
              <Tooltip
                content={<PortTooltip />}
                cursor={{ fill: "#1e293b55" }}
              />
              <Bar
                dataKey="count"
                fill="url(#portBar)"
                radius={[4, 4, 0, 0]}
                maxBarSize={44}
              />
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
