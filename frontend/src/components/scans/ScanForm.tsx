import { useState } from "react";
import { useForm, Controller, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  Loader2,
  Rocket,
  Globe,
  Server,
  Eye,
  Zap,
  ShieldCheck,
  ScanLine,
  ListChecks,
  AlertCircle,
} from "lucide-react";
import type { ReactNode } from "react";

import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Switch } from "@/components/ui/Switch";
import { Checkbox } from "@/components/ui/Checkbox";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/Select";
import { useCreateScan } from "@/hooks/useScans";
import { useProviders } from "@/hooks/useProviders";
import { useToastStore } from "@/stores/toastStore";
import type { ScanFormData } from "@/types/scan";
import { cn } from "@/lib/utils";

// ── Port catalog ──────────────────────────────────────────────────────
// Defined once at the module boundary so the form renders from a single
// trusted source of truth (Parse, Don't Validate).

interface PortOption {
  label: string;
  port: number;
}
interface PortCategory {
  name: string;
  options: PortOption[];
}

const PORT_CATEGORIES: PortCategory[] = [
  {
    name: "Management",
    options: [
      { label: "SSH", port: 22 },
      { label: "Telnet", port: 23 },
      { label: "RDP", port: 3389 },
      { label: "WinRM", port: 5985 },
      { label: "WinRM (TLS)", port: 5986 },
      { label: "VNC", port: 5900 },
      { label: "VNC :1", port: 5901 },
    ],
  },
  {
    name: "Database",
    options: [
      { label: "MySQL", port: 3306 },
      { label: "PostgreSQL", port: 5432 },
      { label: "MSSQL", port: 1433 },
      { label: "Oracle", port: 1521 },
      { label: "MongoDB", port: 27017 },
      { label: "Redis", port: 6379 },
    ],
  },
  {
    name: "Web",
    options: [
      { label: "HTTP", port: 80 },
      { label: "HTTPS", port: 443 },
      { label: "HTTP-Alt", port: 8080 },
      { label: "HTTPS-Alt", port: 8443 },
    ],
  },
  {
    name: "SAP",
    options: [
      { label: "SAP Dispatcher", port: 3200 },
      { label: "SAP Dispatcher", port: 3300 },
      { label: "SAP Message Server", port: 3601 },
      { label: "SAP Message Server", port: 3901 },
    ],
  },
  {
    name: "Citrix",
    options: [
      { label: "Citrix ICA", port: 1494 },
      { label: "Citrix CGP", port: 2598 },
    ],
  },
  {
    name: "GoGlobal",
    options: [{ label: "GoGlobal", port: 491 }],
  },
  {
    name: "FTP / SFTP",
    options: [
      { label: "FTP", port: 21 },
      { label: "SFTP (via SSH)", port: 22 },
    ],
  },
];

// ── Profile catalog ───────────────────────────────────────────────────
// Mirrors the backend `SCAN_PROFILES` so the preview reflects reality.

type ScanProfile = "quick" | "standard" | "thorough" | "custom";

const PROFILE_DESCRIPTIONS: Record<ScanProfile, string> = {
  quick: "Fast — top 10 admin ports",
  standard: "Standard — top 38 admin ports + banners",
  thorough: "Deep — ports 1–1024 + admin ports + HTTP",
  custom: "Custom — pick exactly what to scan",
};

const PROFILE_PORTS: Record<Exclude<ScanProfile, "custom">, number[]> = {
  quick: [22, 23, 80, 443, 3389, 8080, 8443, 21, 445, 3306],
  standard: [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 491, 993,
    995, 1433, 1494, 1521, 2049, 2598, 3200, 3300, 3306, 3389, 3601, 3901,
    5432, 5900, 5901, 5985, 5986, 6379, 8080, 8443, 9090, 27017,
  ],
  // thorough scans ports 1–1024 plus a handful of admin ports; represented
  // as an empty list here because the preview summarises the range.
  thorough: [],
};

const PROFILE_OPTIONS: { value: ScanProfile; label: string; icon: ReactNode }[] =
  [
    { value: "quick", label: "Quick", icon: <Zap className="h-3.5 w-3.5" /> },
    {
      value: "standard",
      label: "Standard",
      icon: <ShieldCheck className="h-3.5 w-3.5" />,
    },
    {
      value: "thorough",
      label: "Thorough",
      icon: <ScanLine className="h-3.5 w-3.5" />,
    },
    {
      value: "custom",
      label: "Custom",
      icon: <ListChecks className="h-3.5 w-3.5" />,
    },
  ];

// ── Validation schema ─────────────────────────────────────────────────

const IPV4_OCTET = "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const IP_OR_CIDR = new RegExp(
  `^${IPV4_OCTET}(\\.${IPV4_OCTET}){3}(/(3[0-2]|[12]?\\d))?$`,
);

/** Parse a comma-separated port string into a validated, de-duplicated list. */
function parseCustomPorts(raw: string): number[] {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((s) => Number(s))
    .filter((n) => Number.isInteger(n) && n > 0 && n <= 65535);
}

const scanFormSchema = z
  .object({
    targetMode: z.enum(["manual", "cloud"]),
    targetValue: z.string(),
    providerId: z.string(),
    profile: z.enum(["quick", "standard", "thorough", "custom"]),
    selectedPorts: z.array(z.number()),
    customPorts: z.string(),
    bannerGrab: z.boolean(),
    httpAnalysis: z.boolean(),
    rateLimitProbing: z.boolean(),
  })
  .refine((d) => d.targetMode !== "manual" || IP_OR_CIDR.test(d.targetValue), {
    message: "Enter a valid IP or CIDR (e.g. 192.168.1.1 or 10.0.0.0/24)",
    path: ["targetValue"],
  })
  .refine((d) => d.targetMode !== "cloud" || d.providerId !== "", {
    message: "Select a cloud provider",
    path: ["providerId"],
  })
  .refine(
    (d) =>
      d.profile !== "custom" ||
      d.selectedPorts.length > 0 ||
      parseCustomPorts(d.customPorts).length > 0,
    {
      message: "Select at least one port for a custom scan",
      path: ["selectedPorts"],
    },
  );

type ScanFormValues = z.infer<typeof scanFormSchema>;

// ── Form → API mapping ────────────────────────────────────────────────

function buildPortList(values: ScanFormValues): number[] {
  // Only the custom profile sends a port override; the backend derives
  // ports from the profile for the other scan types.
  if (values.profile !== "custom") return [];
  const fromCustom = parseCustomPorts(values.customPorts);
  return [...new Set([...values.selectedPorts, ...fromCustom])].sort(
    (a, b) => a - b,
  );
}

function toScanFormData(values: ScanFormValues): ScanFormData {
  const targetLabel =
    values.targetMode === "manual"
      ? values.targetValue
      : `cloud:${values.providerId}`;
  const ports = buildPortList(values);
  return {
    name: `${values.profile} scan — ${targetLabel}`,
    target_ids: values.targetMode === "manual" ? [values.targetValue] : [],
    provider_ids:
      values.targetMode === "cloud" && values.providerId
        ? [values.providerId]
        : undefined,
    ports: ports.length > 0 ? ports.join(",") : undefined,
    scan_type: values.profile,
    config: {
      banner_grab: values.bannerGrab,
      http_analysis: values.httpAnalysis,
      rate_limit_probing: values.rateLimitProbing,
    },
  };
}

/** Compute the read-only port preview for the selected profile. */
function previewPortsForProfile(
  profile: ScanProfile,
  selectedPorts: number[],
  customPorts: string,
): { chips: number[]; summary?: string } {
  if (profile === "thorough") {
    return {
      chips: [1494, 2598, 3200, 3300, 3601, 3901],
      summary: "Ports 1–1024 plus the admin ports shown here",
    };
  }
  if (profile === "custom") {
    return {
      chips: [
        ...new Set([...selectedPorts, ...parseCustomPorts(customPorts)]),
      ].sort((a, b) => a - b),
    };
  }
  return { chips: PROFILE_PORTS[profile] };
}

// ── Segmented control ─────────────────────────────────────────────────

interface SegmentedOption<T extends string> {
  value: T;
  label: string;
  icon?: ReactNode;
}

function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  columns = "grid-cols-2",
}: {
  options: SegmentedOption<T>[];
  value: T;
  onChange: (next: T) => void;
  columns?: string;
}) {
  return (
    <div
      className={cn(
        "grid gap-1 rounded-lg border border-surface-800 bg-surface-950 p-1",
        columns,
      )}
    >
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          onClick={() => onChange(opt.value)}
          className={cn(
            "flex items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors",
            value === opt.value
              ? "bg-brand-600 text-white shadow-sm"
              : "text-surface-300 hover:bg-surface-800 hover:text-surface-100",
          )}
        >
          {opt.icon}
          {opt.label}
        </button>
      ))}
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────

interface ScanFormProps {
  /** Called after a scan is successfully created (parent refetches/closes). */
  onSuccess?: () => void;
}

export function ScanForm({ onSuccess }: ScanFormProps) {
  const createScan = useCreateScan();
  const { data: providersData, isLoading: providersLoading } = useProviders();
  const addToast = useToastStore((s) => s.addToast);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const {
    register,
    control,
    handleSubmit,
    formState: { errors },
  } = useForm<ScanFormValues>({
    resolver: zodResolver(scanFormSchema),
    defaultValues: {
      targetMode: "manual",
      targetValue: "",
      providerId: "",
      profile: "quick",
      selectedPorts: [],
      customPorts: "",
      bannerGrab: true,
      httpAnalysis: true,
      rateLimitProbing: true,
    },
  });

  // useWatch (vs. watch()) keeps the component memoization-safe.
  const targetMode = useWatch({ control, name: "targetMode", defaultValue: "manual" });
  const profile = useWatch({ control, name: "profile", defaultValue: "quick" });
  const httpAnalysis = useWatch({ control, name: "httpAnalysis", defaultValue: true });
  const selectedPorts = useWatch({ control, name: "selectedPorts", defaultValue: [] });
  const customPorts = useWatch({ control, name: "customPorts", defaultValue: "" });
  const providerId = useWatch({ control, name: "providerId", defaultValue: "" });

  const providers = providersData?.items ?? [];
  const selectedProvider = providers.find((p) => p.id === providerId);
  const preview = previewPortsForProfile(profile, selectedPorts, customPorts);

  const onSubmit = (values: ScanFormValues) => {
    setSubmitError(null);
    createScan.mutate(toScanFormData(values), {
      onSuccess: () => {
        addToast({
          variant: "success",
          title: "Scan started",
          description: `${values.profile} scan has been queued.`,
        });
        onSuccess?.();
      },
      onError: (err) => {
        const message = err.message ?? "Failed to start scan";
        setSubmitError(message);
        addToast({ variant: "error", title: "Scan failed", description: message });
      },
    });
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
      {/* ── Target selection ── */}
      <section className="space-y-3">
        <div>
          <p className="mb-2 text-sm font-medium text-surface-300">Target</p>
          <Controller
            control={control}
            name="targetMode"
            render={({ field }) => (
              <SegmentedControl
                value={field.value}
                onChange={field.onChange}
                options={[
                  {
                    value: "manual",
                    label: "Manual",
                    icon: <Server className="h-3.5 w-3.5" />,
                  },
                  {
                    value: "cloud",
                    label: "Cloud Provider",
                    icon: <Globe className="h-3.5 w-3.5" />,
                  },
                ]}
              />
            )}
          />
        </div>

        {targetMode === "manual" ? (
          <Input
            label="Target IP / CIDR"
            placeholder="192.168.1.1 or 10.0.0.0/24"
            error={errors.targetValue?.message}
            {...register("targetValue")}
          />
        ) : (
          <div className="space-y-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-surface-300">
                Cloud provider
              </label>
              <Controller
                control={control}
                name="providerId"
                render={({ field }) => (
                  <Select value={field.value} onValueChange={field.onChange}>
                    <SelectTrigger>
                      <SelectValue
                        placeholder={
                          providersLoading
                            ? "Loading providers..."
                            : "Select a cloud provider"
                        }
                      />
                    </SelectTrigger>
                    <SelectContent>
                      {providers.length === 0 && !providersLoading ? (
                        <SelectItem value="__none" disabled>
                          No providers configured
                        </SelectItem>
                      ) : (
                        providers.map((p) => (
                          <SelectItem key={p.id} value={p.id}>
                            {p.name} · {p.provider_type.toUpperCase()}
                          </SelectItem>
                        ))
                      )}
                    </SelectContent>
                  </Select>
                )}
              />
              {errors.providerId && (
                <p className="text-xs text-danger">
                  {errors.providerId.message}
                </p>
              )}
            </div>

            {selectedProvider && (
              <div className="flex items-center gap-3 rounded-lg border border-surface-800 bg-surface-950 p-3">
                <Globe className="h-5 w-5 shrink-0 text-brand-500" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-surface-100">
                    {selectedProvider.name}
                  </p>
                  <p className="text-xs text-surface-400">
                    {selectedProvider.provider_type.toUpperCase()}
                    {selectedProvider.regions?.length
                      ? ` · ${selectedProvider.regions.length} regions`
                      : ""}
                  </p>
                </div>
                <Badge variant="brand">Discovered IPs will be scanned</Badge>
              </div>
            )}
          </div>
        )}
      </section>

      {/* ── Profile selection ── */}
      <section className="space-y-3">
        <div>
          <p className="mb-2 text-sm font-medium text-surface-300">Profile</p>
          <Controller
            control={control}
            name="profile"
            render={({ field }) => (
              <SegmentedControl
                value={field.value}
                onChange={field.onChange}
                options={PROFILE_OPTIONS}
                columns="grid-cols-4"
              />
            )}
          />
          <p className="mt-1.5 text-xs text-surface-400">
            {PROFILE_DESCRIPTIONS[profile]}
          </p>
        </div>

        {preview.chips.length > 0 && (
          <div className="rounded-lg border border-surface-800 bg-surface-950 p-3">
            <p className="mb-2 flex items-center gap-1.5 text-xs font-medium text-surface-400">
              <Eye className="h-3 w-3" /> Ports to scan
            </p>
            {preview.summary && (
              <p className="mb-2 text-xs text-surface-300">{preview.summary}</p>
            )}
            <div className="flex flex-wrap gap-1.5">
              {preview.chips.slice(0, 24).map((port) => (
                <Badge key={port} variant="brand">
                  {port}
                </Badge>
              ))}
              {preview.chips.length > 24 && (
                <Badge variant="default">
                  +{preview.chips.length - 24} more
                </Badge>
              )}
            </div>
          </div>
        )}
      </section>

      {/* ── Custom port selection ── */}
      {profile === "custom" && (
        <section className="space-y-3">
          <p className="text-sm font-medium text-surface-300">Custom ports</p>
          {errors.selectedPorts && (
            <p className="text-xs text-danger">
              {errors.selectedPorts.message}
            </p>
          )}
          <Controller
            control={control}
            name="selectedPorts"
            render={({ field }) => {
              const togglePort = (port: number) => {
                field.onChange(
                  field.value.includes(port)
                    ? field.value.filter((p) => p !== port)
                    : [...field.value, port],
                );
              };
              return (
                <div className="space-y-2.5">
                  {PORT_CATEGORIES.map((category) => (
                    <div
                      key={category.name}
                      className="rounded-lg border border-surface-800 bg-surface-950 p-3"
                    >
                      <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-surface-400">
                        {category.name}
                      </p>
                      <div className="grid grid-cols-2 gap-1 sm:grid-cols-3">
                        {category.options.map((opt) => (
                          <label
                            key={`${category.name}-${opt.label}-${opt.port}`}
                            className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 transition-colors hover:bg-surface-800/60"
                          >
                            <Checkbox
                              checked={field.value.includes(opt.port)}
                              onCheckedChange={() => togglePort(opt.port)}
                            />
                            <span className="truncate text-xs text-surface-200">
                              {opt.label}
                            </span>
                            <span className="ml-auto text-xs text-surface-500">
                              {opt.port}
                            </span>
                          </label>
                        ))}
                      </div>
                    </div>
                  ))}
                  <Input
                    label="Additional custom ports"
                    placeholder="e.g. 8888, 9000, 5601"
                    error={errors.customPorts?.message}
                    {...register("customPorts")}
                  />
                </div>
              );
            }}
          />
        </section>
      )}

      {/* ── Scan options ── */}
      <section className="space-y-2.5">
        <p className="text-sm font-medium text-surface-300">Options</p>

        <ToggleRow
          title="Banner grabbing"
          description="Capture service banners from open ports"
          control={control}
          name="bannerGrab"
        />
        <ToggleRow
          title="HTTP analysis"
          description="Probe web ports for headers, logins & rate limits"
          control={control}
          name="httpAnalysis"
        />
        <ToggleRow
          title="Rate-limit probing"
          description="Test endpoints for brute-force rate limiting"
          control={control}
          name="rateLimitProbing"
          disabled={!httpAnalysis}
        />
      </section>

      {/* ── Submit ── */}
      {submitError && (
        <div className="flex items-start gap-2 rounded-lg border border-danger/30 bg-danger/10 p-3">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-danger" />
          <p className="text-xs text-danger">{submitError}</p>
        </div>
      )}

      <Button
        type="submit"
        size="lg"
        className="w-full"
        disabled={createScan.isPending}
      >
        {createScan.isPending ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Starting...
          </>
        ) : (
          <>
            <Rocket className="mr-2 h-4 w-4" />
            Start Scan
          </>
        )}
      </Button>
    </form>
  );
}

// ── Toggle row helper ─────────────────────────────────────────────────

interface ToggleRowProps<N extends "bannerGrab" | "httpAnalysis" | "rateLimitProbing"> {
  title: string;
  description: string;
  control: ReturnType<typeof useForm<ScanFormValues>>["control"];
  name: N;
  disabled?: boolean;
}

function ToggleRow<N extends "bannerGrab" | "httpAnalysis" | "rateLimitProbing">({
  title,
  description,
  control,
  name,
  disabled,
}: ToggleRowProps<N>) {
  return (
    <div
      className={cn(
        "flex items-center justify-between rounded-lg border border-surface-800 bg-surface-950 p-3 transition-opacity",
        disabled && "opacity-50",
      )}
    >
      <div className="pr-4">
        <p className="text-sm font-medium text-surface-100">{title}</p>
        <p className="mt-0.5 text-xs text-surface-400">{description}</p>
      </div>
      <Controller
        control={control}
        name={name}
        render={({ field }) => (
          <Switch
            checked={field.value}
            onCheckedChange={field.onChange}
            ref={field.ref}
            disabled={disabled}
          />
        )}
      />
    </div>
  );
}
