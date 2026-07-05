import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";
import { Loader2, CheckCircle, XCircle, Clock, AlertTriangle } from "lucide-react";
import type { ScanStatus } from "@/types/scan";

const statusBadgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium",
  {
    variants: {
      status: {
        pending: "bg-surface-800 text-surface-300",
        running: "bg-info/20 text-info",
        completed: "bg-success/20 text-success",
        failed: "bg-danger/20 text-danger",
        cancelled: "bg-warning/20 text-warning",
      },
    },
    defaultVariants: {
      status: "pending",
    },
  },
);

const statusIcons: Record<ScanStatus, typeof Loader2> = {
  pending: Clock,
  running: Loader2,
  completed: CheckCircle,
  failed: XCircle,
  cancelled: AlertTriangle,
};

interface StatusBadgeProps
  extends VariantProps<typeof statusBadgeVariants> {
  status: ScanStatus;
  className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const Icon = statusIcons[status];
  return (
    <span className={cn(statusBadgeVariants({ status }), className)}>
      <Icon className={cn("h-3 w-3", status === "running" && "animate-spin")} />
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}
