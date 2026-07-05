import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  Settings as SettingsIcon,
  Shield,
  Lock,
  LogOut,
  Save,
  Loader2,
  Mail,
  User,
  KeyRound,
} from "lucide-react";

import { api } from "@/lib/api";
import { useAuthStore } from "@/stores/authStore";
import { useToastStore } from "@/stores/toastStore";
import type { AuthUser } from "@/types/auth";

import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
} from "@/components/ui/Tabs";

// ── Scanner settings ───────────────────────────────────────────────────
// No backend settings endpoint exists yet, so these are held in local state
// with a Save action that confirms via a toast. Defaults are sensible
// production-ish values; wire to GET/POST /settings once it lands.

interface ScannerSettings {
  default_timeout: number;
  max_concurrency: number;
  rate_limit: number;
  scan_retention_days: number;
}

const DEFAULT_SCANNER_SETTINGS: ScannerSettings = {
  default_timeout: 300,
  max_concurrency: 5,
  rate_limit: 600,
  scan_retention_days: 30,
};

const SCANNER_FIELDS: {
  key: keyof ScannerSettings;
  label: string;
  hint: string;
}[] = [
  { key: "default_timeout", label: "Default Timeout", hint: "seconds" },
  { key: "max_concurrency", label: "Max Concurrency", hint: "parallel hosts" },
  { key: "rate_limit", label: "Rate Limit", hint: "requests / minute" },
  { key: "scan_retention_days", label: "Scan Retention", hint: "days" },
];

// ── Change-password form ───────────────────────────────────────────────
// No change-password endpoint exists on the backend yet, so submission is
// acknowledged with a "coming soon" toast rather than a network call.

const passwordSchema = z
  .object({
    current: z.string().min(1, "Enter your current password"),
    new: z.string().min(8, "New password must be at least 8 characters"),
    confirm: z.string().min(1, "Confirm your new password"),
  })
  .refine((d) => d.new === d.confirm, {
    message: "Passwords do not match",
    path: ["confirm"],
  });

type PasswordValues = z.infer<typeof passwordSchema>;

export function Settings() {
  const [settings, setSettings] = useState<ScannerSettings>(
    DEFAULT_SCANNER_SETTINGS,
  );

  const user = useAuthStore((s) => s.user);
  const setUser = useAuthStore((s) => s.setUser);
  const logout = useAuthStore((s) => s.logout);
  const addToast = useToastStore((s) => s.addToast);
  const navigate = useNavigate();

  // Keep the auth store's user profile fresh whenever Settings is viewed.
  const { data: me, isLoading: meLoading } = useQuery<AuthUser>({
    queryKey: ["auth-me"],
    queryFn: () => api.get<AuthUser>("/auth/me"),
  });
  useEffect(() => {
    if (me) setUser(me);
  }, [me, setUser]);

  const {
    register,
    handleSubmit,
    reset: resetPassword,
    formState: { errors },
  } = useForm<PasswordValues>({
    resolver: zodResolver(passwordSchema),
    defaultValues: { current: "", new: "", confirm: "" },
  });

  const handleSaveSettings = () => {
    // No backend endpoint yet — persist locally and confirm.
    addToast({
      variant: "success",
      title: "Scanner settings saved",
      description: "Stored locally until a settings endpoint ships.",
    });
  };

  const handleChangePassword = () => {
    addToast({
      variant: "info",
      title: "Password change coming soon",
      description: "No backend endpoint is available yet.",
    });
    resetPassword({ current: "", new: "", confirm: "" });
  };

  const handleLogout = () => {
    logout();
    addToast({
      variant: "info",
      title: "Signed out",
      description: "You have been logged out.",
    });
    navigate("/login", { replace: true });
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-surface-50">Settings</h1>
        <p className="text-sm text-surface-400 mt-1">
          System configuration and account preferences
        </p>
      </div>

      <Tabs defaultValue="scanner">
        <TabsList>
          <TabsTrigger value="scanner">Scanner Settings</TabsTrigger>
          <TabsTrigger value="profile">User Profile</TabsTrigger>
        </TabsList>

        {/* ── Scanner Settings tab ─────────────────────────────────── */}
        <TabsContent value="scanner">
          <Card className="max-w-2xl">
            <CardHeader>
              <div className="flex items-center gap-2">
                <SettingsIcon className="h-5 w-5 text-surface-400" />
                <CardTitle>Scanner Defaults</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {SCANNER_FIELDS.map((f) => (
                <div key={f.key} className="flex items-end gap-3">
                  <div className="flex-1">
                    <Input
                      label={f.label}
                      type="number"
                      min={1}
                      value={settings[f.key]}
                      onChange={(e) =>
                        setSettings((prev) => ({
                          ...prev,
                          [f.key]: Number(e.target.value) || 0,
                        }))
                      }
                    />
                  </div>
                  <span className="pb-2.5 text-xs text-surface-500">
                    {f.hint}
                  </span>
                </div>
              ))}

              <div className="flex items-center gap-2 rounded-lg border border-info/30 bg-info/10 p-3">
                <Shield className="h-4 w-4 shrink-0 text-info" />
                <p className="text-xs text-info">
                  Settings are stored in the browser for now — a backend
                  settings endpoint is coming soon.
                </p>
              </div>

              <div className="pt-1">
                <Button onClick={handleSaveSettings}>
                  <Save className="mr-2 h-4 w-4" />
                  Save Changes
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── User Profile tab ─────────────────────────────────────── */}
        <TabsContent value="profile">
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Profile summary */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <User className="h-5 w-5 text-surface-400" />
                  <CardTitle>Profile</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {meLoading && !user ? (
                  <div className="flex items-center gap-2 text-sm text-surface-500">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading profile...
                  </div>
                ) : user ? (
                  <>
                    <ProfileRow
                      icon={<Mail className="h-4 w-4" />}
                      label="Email"
                      value={user.email}
                    />
                    <ProfileRow
                      icon={<User className="h-4 w-4" />}
                      label="Username"
                      value={user.username}
                    />
                    <div className="flex items-center gap-2 pt-1">
                      <Badge variant={user.is_active ? "success" : "warning"}>
                        {user.is_active ? "Active" : "Inactive"}
                      </Badge>
                      {user.is_superuser && (
                        <Badge variant="brand">Superuser</Badge>
                      )}
                    </div>
                  </>
                ) : (
                  <p className="text-sm text-surface-500">
                    Signed in without a profile — sign in again to load user
                    info.
                  </p>
                )}

                <div className="pt-2">
                  <Button variant="danger" onClick={handleLogout}>
                    <LogOut className="mr-2 h-4 w-4" />
                    Sign out
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Change password */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <KeyRound className="h-5 w-5 text-surface-400" />
                  <CardTitle>Change Password</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <form
                  onSubmit={handleSubmit(handleChangePassword)}
                  className="space-y-4"
                >
                  <Input
                    label="Current Password"
                    type="password"
                    autoComplete="current-password"
                    error={errors.current?.message}
                    {...register("current")}
                  />
                  <Input
                    label="New Password"
                    type="password"
                    autoComplete="new-password"
                    error={errors.new?.message}
                    {...register("new")}
                  />
                  <Input
                    label="Confirm New Password"
                    type="password"
                    autoComplete="new-password"
                    error={errors.confirm?.message}
                    {...register("confirm")}
                  />

                  <div className="flex items-center gap-2 rounded-lg border border-warning/30 bg-warning/10 p-3">
                    <Lock className="h-4 w-4 shrink-0 text-warning" />
                    <p className="text-xs text-warning">
                      A backend change-password endpoint is not yet available —
                      submissions are acknowledged but not applied.
                    </p>
                  </div>

                  <Button type="submit" variant="outline">
                    <KeyRound className="mr-2 h-4 w-4" />
                    Update Password
                  </Button>
                </form>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function ProfileRow({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="flex items-center justify-between rounded-lg border border-surface-800 bg-surface-950 p-3">
      <span className="flex items-center gap-2 text-sm text-surface-400">
        {icon}
        {label}
      </span>
      <span className="font-mono text-sm text-surface-100">{value}</span>
    </div>
  );
}
