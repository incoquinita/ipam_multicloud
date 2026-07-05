import { useState } from "react";
import { useForm, Controller } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Plus, RefreshCw, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { formatDate } from "@/lib/utils";
import { useTargets, useDeleteTarget, useCreateTarget } from "@/hooks/useTargets";
import type { Target, TargetType } from "@/hooks/useTargets";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/ui/DataTable";
import {
  Dialog,
  DialogContent,
  DialogTrigger,
} from "@/components/ui/Dialog";
import { Input } from "@/components/ui/Input";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/Select";
import { useToastStore } from "@/stores/toastStore";

// ── Validation ─────────────────────────────────────────────────────────
// Form values are a UI-friendly shape; `toTargetPayload` converts them into
// the backend-shaped `TargetFormData` at the API boundary (Parse, Don't
// Validate).

const TARGET_TYPE_OPTIONS: { value: TargetType; label: string }[] = [
  { value: "cidr", label: "CIDR" },
  { value: "ip_list", label: "IP List" },
  { value: "hostname", label: "Hostname" },
  { value: "cloud_provider", label: "Cloud Provider" },
];

const targetSchema = z.object({
  name: z
    .string()
    .min(1, "Name is required")
    .max(256, "Name must be 256 characters or fewer"),
  target_value: z.string().min(1, "Target value is required"),
  target_type: z.enum(["cidr", "ip_list", "cloud_provider", "hostname"]),
  ports: z.string().optional(),
  tags: z.string().optional(),
  description: z.string().optional(),
});

type TargetFormValues = z.infer<typeof targetSchema>;

/** Parse a comma-separated port string into a validated, de-duplicated list. */
function parsePorts(raw: string): number[] {
  return [
    ...new Set(
      raw
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .map((s) => Number(s))
        .filter((n) => Number.isInteger(n) && n > 0 && n <= 65535),
    ),
  ].sort((a, b) => a - b);
}

/** Parse a `key:value, key2:value2` string into a tags object. */
function parseTags(raw: string): Record<string, string> | undefined {
  const tags: Record<string, string> = {};
  for (const pair of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    const [key, ...rest] = pair.split(":");
    const value = rest.join(":").trim();
    const cleanKey = key?.trim();
    if (cleanKey && value) tags[cleanKey] = value;
  }
  return Object.keys(tags).length ? tags : undefined;
}

function toTargetPayload(values: TargetFormValues) {
  const ports = values.ports ? parsePorts(values.ports) : undefined;
  return {
    name: values.name.trim(),
    target_value: values.target_value.trim(),
    target_type: values.target_type,
    description: values.description?.trim() || undefined,
    ports: ports?.length ? ports : undefined,
    tags: values.tags ? parseTags(values.tags) : undefined,
  };
}

const EMPTY_VALUES: TargetFormValues = {
  name: "",
  target_value: "",
  target_type: "cidr",
  ports: "",
  tags: "",
  description: "",
};

export function Targets() {
  const [open, setOpen] = useState(false);
  const { data, isLoading, refetch, isFetching } = useTargets();
  const deleteTarget = useDeleteTarget();
  const createTarget = useCreateTarget();
  const addToast = useToastStore((s) => s.addToast);

  const {
    register,
    control,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<TargetFormValues>({
    resolver: zodResolver(targetSchema),
    defaultValues: EMPTY_VALUES,
  });

  const onSubmit = (values: TargetFormValues) => {
    createTarget.mutate(toTargetPayload(values), {
      onSuccess: (target) => {
        addToast({
          variant: "success",
          title: "Target added",
          description: `${target.name} is ready to scan.`,
        });
        reset(EMPTY_VALUES);
        setOpen(false);
      },
      onError: (err) => {
        addToast({
          variant: "error",
          title: "Could not add target",
          description: err.message,
        });
      },
    });
  };

  const columns: ColumnDef<Target>[] = [
    {
      accessorKey: "name",
      header: "Name",
      cell: ({ row }) => (
        <span className="font-medium text-surface-100">
          {row.getValue("name")}
        </span>
      ),
    },
    {
      accessorKey: "target_value",
      header: "Target",
      cell: ({ row }) => (
        <span className="font-mono text-sm text-surface-100">
          {row.getValue("target_value")}
        </span>
      ),
    },
    {
      accessorKey: "target_type",
      header: "Type",
      cell: ({ row }) => (
        <Badge variant="info">{row.getValue("target_type")}</Badge>
      ),
    },
    {
      accessorKey: "ports",
      header: "Ports",
      cell: ({ row }) => {
        const ports = row.getValue("ports") as number[] | undefined;
        return ports?.length ? (
          <span className="text-surface-300">{ports.join(", ")}</span>
        ) : (
          <span className="text-surface-500">Default</span>
        );
      },
    },
    {
      accessorKey: "tags",
      header: "Tags",
      cell: ({ row }) => {
        const tags = row.getValue("tags") as Record<string, string> | undefined;
        const entries = tags ? Object.entries(tags) : [];
        return entries.length ? (
          <div className="flex gap-1 flex-wrap">
            {entries.map(([key, value]) => (
              <Badge key={key} variant="brand">
                {key}: {value}
              </Badge>
            ))}
          </div>
        ) : (
          <span className="text-surface-500">—</span>
        );
      },
    },
    {
      accessorKey: "created_at",
      header: "Created",
      cell: ({ row }) => (
        <span className="text-surface-400">
          {formatDate(row.getValue("created_at"))}
        </span>
      ),
    },
    {
      id: "actions",
      header: "",
      cell: ({ row }) => (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => deleteTarget.mutate(row.original.id)}
        >
          Delete
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-surface-50">Targets</h1>
          <p className="text-sm text-surface-400 mt-1">
            Manage IP targets for scanning
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RefreshCw
              className={`mr-2 h-4 w-4 ${isFetching ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
          <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="mr-2 h-4 w-4" />
                Add Target
              </Button>
            </DialogTrigger>
            <DialogContent
              title="Add Target"
              description="Add a new IP, CIDR, or hostname to scan. New targets are created active by default."
            >
              <form
                onSubmit={handleSubmit(onSubmit)}
                className="space-y-4 mt-4"
              >
                <Input
                  label="Name"
                  placeholder="e.g. Corporate LAN"
                  error={errors.name?.message}
                  {...register("name")}
                />
                <Input
                  label="Target Value"
                  placeholder="e.g. 192.168.1.0/24 or example.com"
                  error={errors.target_value?.message}
                  {...register("target_value")}
                />

                <div className="space-y-1.5">
                  <label className="text-sm font-medium text-surface-300">
                    Target Type
                  </label>
                  <Controller
                    control={control}
                    name="target_type"
                    render={({ field }) => (
                      <Select
                        value={field.value}
                        onValueChange={field.onChange}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Select a type" />
                        </SelectTrigger>
                        <SelectContent>
                          {TARGET_TYPE_OPTIONS.map((opt) => (
                            <SelectItem key={opt.value} value={opt.value}>
                              {opt.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    )}
                  />
                </div>

                <Input
                  label="Ports"
                  placeholder="e.g. 22, 80, 443 (leave blank for defaults)"
                  error={errors.ports?.message}
                  {...register("ports")}
                />
                <Input
                  label="Tags"
                  placeholder="e.g. env:prod, owner:sec-team"
                  error={errors.tags?.message}
                  {...register("tags")}
                />
                <Input
                  label="Description"
                  placeholder="Optional notes about this target"
                  error={errors.description?.message}
                  {...register("description")}
                />

                <div className="flex justify-end gap-2 pt-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setOpen(false)}
                  >
                    Cancel
                  </Button>
                  <Button type="submit" disabled={createTarget.isPending}>
                    {createTarget.isPending ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Adding...
                      </>
                    ) : (
                      "Add Target"
                    )}
                  </Button>
                </div>
              </form>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Content */}
      {isLoading ? (
        <div className="flex items-center justify-center py-16">
          <RefreshCw className="h-6 w-6 animate-spin text-surface-500" />
        </div>
      ) : (
        <DataTable columns={columns} data={data?.items ?? []} />
      )}
    </div>
  );
}
