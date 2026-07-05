import { ProgressBar } from "@/components/ui/ProgressBar";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import type { Scan } from "@/types/scan";

interface ScanProgressProps {
  scan: Scan;
}

export function ScanProgress({ scan }: ScanProgressProps) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>{scan.name}</CardTitle>
          <StatusBadge status={scan.status} />
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <ProgressBar
          value={scan.progress}
          showLabel
          variant={scan.status === "failed" ? "danger" : "info"}
        />
        {scan.status === "running" && (
          <p className="text-xs text-surface-400">
            Scanning in progress... {scan.progress}% complete
          </p>
        )}
        {scan.error_message && (
          <p className="text-xs text-danger">{scan.error_message}</p>
        )}
      </CardContent>
    </Card>
  );
}
