import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

// ─────────────────────────────────────────────────────────────────────
// Credentials API.
//
// Credentials are a distinct resource from cloud providers: each credential
// is keyed by a `cloud_provider_id` and carries an encrypted `credentials`
// blob whose keys depend on the provider type. Mirrors
// `app/api/v1/endpoints/credentials.py` and `app/schemas/credentials.py`.
// ─────────────────────────────────────────────────────────────────────

/**
 * Credential response.
 *
 * The encrypted secret blob is NEVER returned by the backend — only the
 * `id`, credential `provider_type` (e.g. `access_key`, `service_principal`),
 * `name` and timestamps.
 */
export interface CredentialResponse {
  id: string;
  provider_type: string;
  name: string;
  created_at: string;
  updated_at?: string | null;
}

/**
 * Credential list envelope.
 *
 * NOTE: the backend returns only `{ items, total }` here — no pagination
 * fields — so this is intentionally narrower than `PaginatedResponse`.
 */
export interface CredentialListResponse {
  items: CredentialResponse[];
  total: number;
}

/** Payload for `POST /credentials/`. */
export interface CredentialCreateInput {
  /** Credential type — `access_key | service_principal | service_account | oci_config`. */
  provider_type: string;
  name: string;
  cloud_provider_id: string;
  /** Provider-specific secret fields, encrypted at rest by the backend. */
  credentials: Record<string, string>;
  metadata?: Record<string, unknown> | null;
}

export function useCredentials(cloudProviderId?: string) {
  const params = cloudProviderId
    ? `?cloud_provider_id=${encodeURIComponent(cloudProviderId)}`
    : "";
  return useQuery<CredentialListResponse>({
    queryKey: ["credentials", cloudProviderId],
    queryFn: () => api.get(`/credentials/${params}`),
  });
}

export function useCreateCredential() {
  const queryClient = useQueryClient();
  return useMutation<CredentialResponse, Error, CredentialCreateInput>({
    // Trailing slash matches the route definition exactly (avoids a 307).
    mutationFn: (data) => api.post("/credentials/", data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["credentials"] });
      // A newly configured credential may flip a provider's connected state.
      queryClient.invalidateQueries({ queryKey: ["providers"] });
    },
  });
}
