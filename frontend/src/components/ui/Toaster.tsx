import { CheckCircle, XCircle, Info, AlertTriangle, X } from "lucide-react";
import { useToastStore, type ToastVariant } from "@/stores/toastStore";
import { cn } from "@/lib/utils";

const toastIcons: Record<ToastVariant, typeof CheckCircle> = {
  success: CheckCircle,
  error: XCircle,
  info: Info,
  warning: AlertTriangle,
};

const toastBorders: Record<ToastVariant, string> = {
  success: "border-success/40",
  error: "border-danger/40",
  info: "border-info/40",
  warning: "border-warning/40",
};

const toastIconColors: Record<ToastVariant, string> = {
  success: "text-success",
  error: "text-danger",
  info: "text-info",
  warning: "text-warning",
};

/**
 * Global toast renderer — reads from {@link useToastStore} and stacks
 * notifications in the top-right corner. Mounted once at the app root.
 */
export function Toaster() {
  const { toasts, removeToast } = useToastStore();

  if (toasts.length === 0) return null;

  return (
    <div
      className="pointer-events-none fixed right-4 top-4 z-[100] flex w-80 flex-col gap-2"
      role="region"
      aria-label="Notifications"
    >
      {toasts.map((toast) => {
        const Icon = toastIcons[toast.variant];
        return (
          <div
            key={toast.id}
            className={cn(
              "toast-in pointer-events-auto flex items-start gap-3 rounded-lg border bg-surface-900/95 p-3 shadow-xl backdrop-blur",
              toastBorders[toast.variant],
            )}
            role="status"
          >
            <Icon
              className={cn(
                "mt-0.5 h-4 w-4 shrink-0",
                toastIconColors[toast.variant],
              )}
            />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-surface-50">
                {toast.title}
              </p>
              {toast.description && (
                <p className="mt-0.5 text-xs text-surface-300">
                  {toast.description}
                </p>
              )}
            </div>
            <button
              type="button"
              onClick={() => removeToast(toast.id)}
              className="shrink-0 rounded text-surface-400 transition-colors hover:text-surface-100"
              aria-label="Dismiss notification"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
