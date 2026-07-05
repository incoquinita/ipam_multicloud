import { NavLink } from "react-router-dom";
import { cn } from "@/lib/utils";
import {
  Shield,
  LayoutDashboard,
  Scan,
  Crosshair,
  Key,
  Settings,
} from "lucide-react";

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/scans", icon: Scan, label: "Scans" },
  { to: "/targets", icon: Crosshair, label: "Targets" },
  { to: "/credentials", icon: Key, label: "Credentials" },
  { to: "/settings", icon: Settings, label: "Settings" },
] as const;

export function Sidebar() {
  return (
    <aside className="flex w-56 flex-col border-r border-surface-800 bg-surface-900">
      {/* Logo */}
      <div className="flex h-14 items-center gap-2 border-b border-surface-800 px-4">
        <Shield className="h-6 w-6 text-brand-500" />
        <span className="font-bold text-surface-50">IPAM Scanner</span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 p-3">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === "/"}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                isActive
                  ? "bg-brand-700 text-white"
                  : "text-surface-400 hover:bg-surface-800 hover:text-surface-100",
              )
            }
          >
            <item.icon className="h-4 w-4" />
            {item.label}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="border-t border-surface-800 p-3">
        <p className="text-xs text-surface-500">v1.0.0</p>
      </div>
    </aside>
  );
}
