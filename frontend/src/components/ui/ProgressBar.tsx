import { cn } from "@/lib/utils";

interface ProgressBarProps {
  value: number;
  max?: number;
  variant?: "default" | "success" | "warning" | "danger" | "info";
  showLabel?: boolean;
  className?: string;
}

const variantStyles = {
  default: "bg-brand-500",
  success: "bg-success",
  warning: "bg-warning",
  danger: "bg-danger",
  info: "bg-info",
};

export function ProgressBar({
  value,
  max = 100,
  variant = "default",
  showLabel = false,
  className,
}: ProgressBarProps) {
  const percent = Math.min(Math.max((value / max) * 100, 0), 100);

  return (
    <div className={cn("flex items-center gap-2", className)}>
      <div className="flex-1 rounded-full bg-surface-800 h-2 overflow-hidden">
        <div
          className={cn(
            "h-full rounded-full transition-all duration-500 ease-out",
            variantStyles[variant],
          )}
          style={{ width: `${percent}%` }}
        />
      </div>
      {showLabel && (
        <span className="text-xs text-surface-400 min-w-[3rem] text-right">
          {Math.round(percent)}%
        </span>
      )}
    </div>
  );
}
