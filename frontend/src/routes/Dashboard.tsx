import { useQuery } from "@tanstack/react-query";
import { Shield, AlertTriangle, Activity, Target } from "lucide-react";
import { KpiCard } from "@/components/ui/KpiCard";
import { ScanOverview } from "@/components/dashboard/ScanOverview";
import { RecentScans } from "@/components/dashboard/RecentScans";
import { PortDistribution } from "@/components/dashboard/PortDistribution";
import { CloudStatus } from "@/components/dashboard/CloudStatus";
import { api } from "@/lib/api";
import type { DashboardStats } from "@/types/analytics";

export function Dashboard() {
  const { data: stats } = useQuery<DashboardStats>({
    queryKey: ["dashboard-stats"],
    queryFn: () => api.get("/scans/stats"),
    refetchInterval: 10_000,
  });

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-surface-50">Dashboard</h1>
        <p className="text-sm text-surface-400 mt-1">
          Multi-Cloud IPAM Security Overview
        </p>
      </div>

      {/* KPI Cards — wired to live /scans/stats data, no fabricated trends */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard
          title="Total Targets"
          value={stats?.total_targets ?? 0}
          icon={<Target className="h-4 w-4" />}
        />
        <KpiCard
          title="Open Ports Found"
          value={stats?.total_open_ports ?? 0}
          variant="warning"
          icon={<Activity className="h-4 w-4" />}
        />
        <KpiCard
          title="Active Scans"
          value={stats?.active_scans ?? 0}
          variant="info"
          icon={<Shield className="h-4 w-4" />}
        />
        <KpiCard
          title="Critical Findings"
          value={stats?.critical_findings ?? 0}
          variant="danger"
          icon={<AlertTriangle className="h-4 w-4" />}
        />
      </div>

      {/* Dashboard Grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <ScanOverview />
        <PortDistribution />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <RecentScans />
        <CloudStatus />
      </div>
    </div>
  );
}
