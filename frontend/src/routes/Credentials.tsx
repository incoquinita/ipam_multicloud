import { useState } from "react";
import { useForm, Controller, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Plus, RefreshCw, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { formatDate } from "@/lib/utils";
import { useProviders, useDeleteProvider } from "@/hooks/useProviders";
import { useCreateCredential } from "@/hooks/useCredentials";
import type { CredentialCreateInput } from "@/hooks/useCredentials";
import type { CloudProvider } from "@/hooks/useProviders";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/ui/DataTable";
import {
  Dialog,
  DialogContent,
  DialogTrigger,
} from "@/components/ui/Dialog";
import { Input } from "@/components/ui/Input";
import { Textarea } from "@/components/ui/Textarea";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/Select";
import { useToastStore } from "@/stores/toastStore";

// ── Provider form ──────────────────────────────────────────────────────
// The "Add Provider" dialog actually creates a credential (POST /credentials/)
// attached to an existing cloud provider. The credential's `provider_type`
// (the cloud type) drives which secret fields are rendered and, on submit,
// maps to the backend credential-type enum.

type ProviderType = "aws" | "azure" | "gcp" | "oci";

const PROVIDER_TYPE_OPTIONS: { value: ProviderType; label: string }[] = [
  { value: "aws", label: "AWS" },
  { value: "azure", label: "Azure" },
  { value: "gcp", label: "GCP" },
  { value: "oci", label: "OCI" },
];

/** Cloud type → backend credential type (see `app/schemas/credentials.py`). */
const CREDENTIAL_TYPE_MAP: Record<ProviderType, string> = {
  aws: "access_key",
  azure: "service_principal",
  gcp: "service_account",
  oci: "oci_config",
};

interface CredentialField {
  name: string;
  label: string;
  placeholder?: string;
  secret?: boolean;
  textarea?: boolean;
}

/**
 * Per-provider secret fields.
 *
 * Field names mirror the keys the backend providers actually read
 * (`app/providers/*.py`), so submissions are functional — not just stored.
 * GCP keeps a `service_account_json` textarea (extra fields are encrypted
 * and stored harmlessly even if unused by the current provider impl).
 */
const PROVIDER_FIELDS: Record<ProviderType, CredentialField[]> = {
  aws: [
    { name: "access_key_id", label: "Access Key ID", placeholder: "AKIA..." },
    {
      name: "secret_access_key",
      label: "Secret Access Key",
      secret: true,
      placeholder: "••••••••",
    },
    { name: "region", label: "Region", placeholder: "us-east-1" },
  ],
  azure: [
    { name: "tenant_id", label: "Tenant ID" },
    { name: "client_id", label: "Client ID" },
    { name: "client_secret", label: "Client Secret", secret: true },
    { name: "subscription_id", label: "Subscription ID" },
  ],
  gcp: [
    { name: "project_id", label: "Project ID", placeholder: "my-project-123" },
    {
      name: "service_account_json",
      label: "Service Account JSON",
      textarea: true,
      placeholder: '{ "type": "service_account", ... }',
    },
  ],
  oci: [
    { name: "tenancy_ocid", label: "Tenancy OCID", placeholder: "ocid1.tenancy..." },
    { name: "user_ocid", label: "User OCID", placeholder: "ocid1.user..." },
    { name: "fingerprint", label: "Fingerprint" },
    {
      name: "key_file_path",
      label: "Key File Path",
      placeholder: "/path/to/private_key.pem",
    },
    { name: "region", label: "Region", placeholder: "us-ashburn-1" },
  ],
};

const credentialSchema = z
  .object({
    cloud_provider_id: z.string().min(1, "Select a cloud provider"),
    provider_type: z.enum(["aws", "azure", "gcp", "oci"]),
    name: z
      .string()
      .min(1, "Credential name is required")
      .max(128, "Name must be 128 characters or fewer"),
    // All possible secret fields — required-ness is enforced per provider below.
    access_key_id: z.string().optional(),
    secret_access_key: z.string().optional(),
    region: z.string().optional(),
    tenant_id: z.string().optional(),
    client_id: z.string().optional(),
    client_secret: z.string().optional(),
    subscription_id: z.string().optional(),
    project_id: z.string().optional(),
    service_account_json: z.string().optional(),
    tenancy_ocid: z.string().optional(),
    user_ocid: z.string().optional(),
    fingerprint: z.string().optional(),
    key_file_path: z.string().optional(),
  })
  .superRefine((data, ctx) => {
    const required = PROVIDER_FIELDS[data.provider_type].map((f) => f.name);
    const values = data as unknown as Record<string, string | undefined>;
    for (const field of required) {
      if (!values[field] || values[field].trim() === "") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [field],
          message: "Required",
        });
      }
    }
  });

type CredentialFormValues = z.infer<typeof credentialSchema>;

const EMPTY_CREDENTIALS: CredentialFormValues = {
  cloud_provider_id: "",
  provider_type: "aws",
  name: "",
  access_key_id: "",
  secret_access_key: "",
  region: "",
  tenant_id: "",
  client_id: "",
  client_secret: "",
  subscription_id: "",
  project_id: "",
  service_account_json: "",
  tenancy_ocid: "",
  user_ocid: "",
  fingerprint: "",
  key_file_path: "",
};

function toCredentialPayload(
  values: CredentialFormValues,
): CredentialCreateInput {
  const fields = PROVIDER_FIELDS[values.provider_type];
  const source = values as unknown as Record<string, string | undefined>;
  const credentials: Record<string, string> = {};
  for (const f of fields) {
    const v = source[f.name];
    if (v && v.trim()) credentials[f.name] = v.trim();
  }
  return {
    provider_type: CREDENTIAL_TYPE_MAP[values.provider_type],
    name: values.name.trim(),
    cloud_provider_id: values.cloud_provider_id,
    credentials,
  };
}

export function Credentials() {
  const [open, setOpen] = useState(false);
  const { data, isLoading, refetch, isFetching } = useProviders();
  const deleteProvider = useDeleteProvider();
  const createCredential = useCreateCredential();
  const addToast = useToastStore((s) => s.addToast);

  const {
    register,
    control,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<CredentialFormValues>({
    resolver: zodResolver(credentialSchema),
    defaultValues: EMPTY_CREDENTIALS,
  });

  // Subscription-based watch — avoids re-rendering the whole form on every
  // keystroke and keeps the dynamic field set in sync with `provider_type`.
  const providerType = useWatch({ control, name: "provider_type" }) as ProviderType;
  const providers = data?.items ?? [];
  const dynamicFields = PROVIDER_FIELDS[providerType] ?? PROVIDER_FIELDS.aws;

  const onSubmit = (values: CredentialFormValues) => {
    createCredential.mutate(toCredentialPayload(values), {
      onSuccess: (cred) => {
        addToast({
          variant: "success",
          title: "Credential saved",
          description: `${cred.name} was encrypted and stored.`,
        });
        reset(EMPTY_CREDENTIALS);
        setOpen(false);
      },
      onError: (err) => {
        addToast({
          variant: "error",
          title: "Could not save credential",
          description: err.message,
        });
      },
    });
  };

  const columns: ColumnDef<CloudProvider>[] = [
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
      accessorKey: "provider_type",
      header: "Type",
      cell: ({ row }) => {
        const type = row.getValue("provider_type") as string;
        return <Badge variant="brand">{type.toUpperCase()}</Badge>;
      },
    },
    {
      accessorKey: "is_configured",
      header: "Status",
      cell: ({ row }) => {
        const configured = row.getValue("is_configured") as boolean;
        return (
          <Badge variant={configured ? "success" : "warning"}>
            {configured ? "Connected" : "Unconfigured"}
          </Badge>
        );
      },
    },
    {
      accessorKey: "regions",
      header: "Regions",
      cell: ({ row }) => {
        const regions = row.getValue("regions") as string[] | undefined;
        return (
          <span className="text-surface-400">
            {regions?.length ? regions.length : 0} configured
          </span>
        );
      },
    },
    {
      accessorKey: "created_at",
      header: "Added",
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
          onClick={() => deleteProvider.mutate(row.original.id)}
        >
          Remove
        </Button>
      ),
    },
  ];

  // Helper to read a dynamic field's error message.
  const fieldError = (name: string): string | undefined =>
    (errors as unknown as Record<string, { message?: string }>)[name]?.message;

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-surface-50">Credentials</h1>
          <p className="text-sm text-surface-400 mt-1">
            Manage cloud provider credentials and connections
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
                Add Provider
              </Button>
            </DialogTrigger>
            <DialogContent
              title="Add Cloud Provider Credential"
              description="Attach encrypted credentials to an existing cloud provider."
              className="max-w-xl max-h-[90vh] overflow-y-auto"
            >
              <form
                onSubmit={handleSubmit(onSubmit)}
                className="space-y-4 mt-4"
              >
                {/* Credential name */}
                <Input
                  label="Credential Name"
                  placeholder="e.g. AWS Prod"
                  error={errors.name?.message}
                  {...register("name")}
                />

                {/* Cloud provider */}
                <div className="space-y-1.5">
                  <label className="text-sm font-medium text-surface-300">
                    Cloud Provider
                  </label>
                  <Controller
                    control={control}
                    name="cloud_provider_id"
                    render={({ field }) => (
                      <Select
                        value={field.value}
                        onValueChange={field.onChange}
                      >
                        <SelectTrigger>
                          <SelectValue
                            placeholder={
                              isLoading
                                ? "Loading providers..."
                                : "Select a cloud provider"
                            }
                          />
                        </SelectTrigger>
                        <SelectContent>
                          {providers.length === 0 && !isLoading ? (
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
                  {fieldError("cloud_provider_id") && (
                    <p className="text-xs text-danger">
                      {fieldError("cloud_provider_id")}
                    </p>
                  )}
                </div>

                {/* Provider type (drives dynamic fields) */}
                <div className="space-y-1.5">
                  <label className="text-sm font-medium text-surface-300">
                    Provider Type
                  </label>
                  <Controller
                    control={control}
                    name="provider_type"
                    render={({ field }) => (
                      <Select
                        value={field.value}
                        onValueChange={field.onChange}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Select a type" />
                        </SelectTrigger>
                        <SelectContent>
                          {PROVIDER_TYPE_OPTIONS.map((opt) => (
                            <SelectItem key={opt.value} value={opt.value}>
                              {opt.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    )}
                  />
                </div>

                {/* Dynamic credential fields */}
                <div className="space-y-3 rounded-lg border border-surface-800 bg-surface-950 p-3">
                  <p className="text-xs font-medium uppercase tracking-wider text-surface-400">
                    {PROVIDER_TYPE_OPTIONS.find(
                      (o) => o.value === providerType,
                      )?.label}{" "}
                    credentials
                  </p>
                  {dynamicFields.map((f) =>
                    f.textarea ? (
                      <Textarea
                        key={f.name}
                        label={f.label}
                        placeholder={f.placeholder}
                        error={fieldError(f.name)}
                        {...register(f.name as keyof CredentialFormValues)}
                      />
                    ) : (
                      <Input
                        key={f.name}
                        label={f.label}
                        type={f.secret ? "password" : "text"}
                        placeholder={f.placeholder}
                        error={fieldError(f.name)}
                        autoComplete="off"
                        {...register(f.name as keyof CredentialFormValues)}
                      />
                    ),
                  )}
                </div>

                <div className="flex justify-end gap-2 pt-1">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setOpen(false)}
                  >
                    Cancel
                  </Button>
                  <Button type="submit" disabled={createCredential.isPending}>
                    {createCredential.isPending ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Saving...
                      </>
                    ) : (
                      "Save Credential"
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
