import { useScans } from "@/hooks/useScans";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { formatDate } from "@/lib/utils";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";

export function RecentScans() {
  const { data, isLoading } = useScans({ page: 1, size: 5 });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Scans</CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <p className="text-sm text-surface-500">Loading scans...</p>
          </div>
        ) : !data?.items?.length ? (
          <div className="flex items-center justify-center py-8">
            <p className="text-sm text-surface-500">No scans yet.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {data.items.map((scan) => (
              <div
                key={scan.id}
                className="flex items-center justify-between rounded-lg border border-surface-800 bg-surface-950 p-3"
              >
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-surface-100 truncate">
                    {scan.name}
                  </p>
                  <p className="text-xs text-surface-400 mt-0.5">
                    {formatDate(scan.created_at)}
                  </p>
                </div>
                <StatusBadge status={scan.status} />
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
