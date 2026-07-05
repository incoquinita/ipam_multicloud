import { cn } from "@/lib/utils";
import { TrendingUp, TrendingDown } from "lucide-react";
import type { ReactNode } from "react";

interface KpiCardProps {
  title: string;
  value: number | string;
  trend?: string;
  variant?: "default" | "warning" | "danger" | "info";
  icon?: ReactNode;
  className?: string;
}

const variantStyles = {
  default: "border-surface-800",
  warning: "border-warning/30",
  danger: "border-danger/30",
  info: "border-info/30",
};

export function KpiCard({
  title,
  value,
  trend,
  variant = "default",
  icon,
  className,
}: KpiCardProps) {
  const isPositive = trend?.startsWith("+");
  const TrendIcon = isPositive ? TrendingUp : TrendingDown;

  return (
    <div
      className={cn(
        "rounded-xl border bg-surface-900 p-4 transition-colors hover:bg-surface-800/50",
        variantStyles[variant],
        className,
      )}
    >
      <div className="flex items-center justify-between">
        <span className="text-sm text-surface-400">{title}</span>
        {icon && <span className="text-surface-500">{icon}</span>}
      </div>
      <div className="mt-2 flex items-baseline gap-2">
        <span className="text-2xl font-bold">{value}</span>
        {trend && (
          <span
            className={cn(
              "flex items-center text-xs font-medium",
              isPositive ? "text-success" : "text-danger",
            )}
          >
            <TrendIcon className="mr-1 h-3 w-3" />
            {trend}
          </span>
        )}
      </div>
    </div>
  );
}
