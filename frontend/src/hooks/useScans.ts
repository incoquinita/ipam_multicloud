import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type {
  Scan,
  ScanFormData,
  ScanJob,
  PortResultListResponse,
  HttpAnalysisItem,
} from "@/types/scan";
import type { PaginatedResponse } from "@/types/api";

export function useScans(filters?: Record<string, unknown>) {
  const params = filters
    ? "?" + new URLSearchParams(
        Object.entries(filters).map(([k, v]) => [k, String(v)]),
      ).toString()
    : "";

  return useQuery<PaginatedResponse<Scan>>({
    queryKey: ["scans", filters],
    queryFn: () => api.get(`/scans${params}`),
  });
}

export function useScan(id: string) {
  return useQuery<Scan>({
    queryKey: ["scan", id],
    queryFn: () => api.get(`/scans/${id}`),
    refetchInterval: 10_000,
  });
}

export function useCreateScan() {
  const queryClient = useQueryClient();
  return useMutation<Scan, Error, ScanFormData>({
    mutationFn: (data: ScanFormData) => api.post("/scans", data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });
}

export function useCancelScan() {
  const queryClient = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (id: string) => api.post(`/scans/${id}/cancel`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });
}

// ── Scan detail & results ──────────────────────────────────────────────
// Backend-accurate queries backing the scan results detail view.

/** Fetch a single scan job (`GET /scans/{id}`) as the backend-shaped `ScanJob`. */
export function useScanJob(id: string) {
  return useQuery<ScanJob>({
    queryKey: ["scan-job", id],
    queryFn: () => api.get(`/scans/${id}`),
    // Keep live scans fresh while the user watches the results view.
    refetchInterval: 10_000,
  });
}

/** Fetch paginated port results for a scan (`GET /scans/{id}/results/ports`). */
export function useScanPortResults(id: string, page = 1, size = 200) {
  return useQuery<PortResultListResponse>({
    queryKey: ["scan-port-results", id, page, size],
    queryFn: () =>
      api.get(`/scans/${id}/results/ports?page=${page}&size=${size}`),
  });
}

/** Fetch HTTP analyses for a scan (`GET /scans/{id}/results/http`, bare array). */
export function useScanHttpAnalyses(id: string) {
  return useQuery<HttpAnalysisItem[]>({
    queryKey: ["scan-http-analyses", id],
    queryFn: () => api.get(`/scans/${id}/results/http`),
  });
}
