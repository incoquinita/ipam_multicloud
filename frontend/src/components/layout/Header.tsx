import { Bell } from "lucide-react";
import { useUiStore } from "@/stores/uiStore";
import { useAuthStore } from "@/stores/authStore";
import { Input } from "@/components/ui/Input";
import { HealthCheck } from "@/components/HealthCheck";

export function Header() {
  const { toggleSidebar } = useUiStore();
  const { isAuthenticated } = useAuthStore();

  return (
    <header className="flex h-14 items-center justify-between border-b border-surface-800 bg-surface-900 px-6">
      <div className="flex items-center gap-4">
        {/* Mobile menu toggle */}
        <button
          onClick={toggleSidebar}
          className="rounded-lg p-1.5 text-surface-400 hover:bg-surface-800 hover:text-surface-100 lg:hidden"
        >
          <svg
            className="h-5 w-5"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M4 6h16M4 12h16M4 18h16"
            />
          </svg>
        </button>

        {/* Search */}
        <div className="hidden sm:block">
          <Input
            placeholder="Search targets, scans, findings..."
            className="max-w-md"
          />
        </div>
      </div>

      <div className="flex items-center gap-3">
        {/* Health check */}
        <HealthCheck />

        {/* Notifications */}
        <button className="relative rounded-lg p-1.5 text-surface-400 hover:bg-surface-800 hover:text-surface-100">
          <Bell className="h-5 w-5" />
          <span className="absolute right-1 top-1 h-2 w-2 rounded-full bg-danger" />
        </button>

        {/* Auth status */}
        {isAuthenticated && (
          <div className="flex items-center gap-2 border-l border-surface-800 pl-3">
            <div className="h-8 w-8 rounded-full bg-brand-700 flex items-center justify-center">
              <span className="text-xs font-medium text-white">SA</span>
            </div>
          </div>
        )}
      </div>
    </header>
  );
}
