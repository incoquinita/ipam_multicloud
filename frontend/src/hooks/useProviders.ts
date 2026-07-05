import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { PaginatedResponse } from "@/types/api";

export interface CloudProvider {
  id: string;
  name: string;
  provider_type: "aws" | "azure" | "gcp" | "digitalocean" | "other";
  regions?: string[];
  is_configured: boolean;
  created_at: string;
  updated_at?: string;
}

export interface ProviderFormData {
  name: string;
  provider_type: CloudProvider["provider_type"];
  credentials: Record<string, string>;
  regions?: string[];
}

export function useProviders() {
  return useQuery<PaginatedResponse<CloudProvider>>({
    queryKey: ["providers"],
    queryFn: () => api.get("/cloud-providers"),
  });
}

export function useProvider(id: string) {
  return useQuery<CloudProvider>({
    queryKey: ["provider", id],
    queryFn: () => api.get(`/cloud-providers/${id}`),
  });
}

export function useCreateProvider() {
  const queryClient = useQueryClient();
  return useMutation<CloudProvider, Error, ProviderFormData>({
    mutationFn: (data: ProviderFormData) =>
      api.post("/cloud-providers", data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["providers"] });
    },
  });
}

export function useUpdateProvider() {
  const queryClient = useQueryClient();
  return useMutation<
    CloudProvider,
    Error,
    { id: string; data: Partial<ProviderFormData> }
  >({
    mutationFn: ({ id, data }) => api.put(`/cloud-providers/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["providers"] });
    },
  });
}

export function useDeleteProvider() {
  const queryClient = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (id: string) => api.delete(`/cloud-providers/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["providers"] });
    },
  });
}
