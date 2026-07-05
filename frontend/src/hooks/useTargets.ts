import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { PaginatedResponse } from "@/types/api";

export type TargetType = "cidr" | "ip_list" | "cloud_provider" | "hostname";

export interface Target {
  id: string;
  name: string;
  description?: string;
  target_type: TargetType;
  target_value: string;
  ports?: number[];
  is_active: boolean;
  tags?: Record<string, string>;
  created_at: string;
  updated_at?: string;
}

export interface TargetFormData {
  name: string;
  target_type?: TargetType;
  target_value: string;
  description?: string;
  ports?: number[];
  tags?: Record<string, string>;
}

export function useTargets() {
  return useQuery<PaginatedResponse<Target>>({
    queryKey: ["targets"],
    queryFn: () => api.get("/targets"),
  });
}

export function useTarget(id: string) {
  return useQuery<Target>({
    queryKey: ["target", id],
    queryFn: () => api.get(`/targets/${id}`),
  });
}

export function useCreateTarget() {
  const queryClient = useQueryClient();
  return useMutation<Target, Error, TargetFormData>({
    mutationFn: (data: TargetFormData) => api.post("/targets", data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["targets"] });
    },
  });
}

export function useUpdateTarget() {
  const queryClient = useQueryClient();
  return useMutation<Target, Error, { id: string; data: TargetFormData }>({
    mutationFn: ({ id, data }) => api.put(`/targets/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["targets"] });
    },
  });
}

export function useDeleteTarget() {
  const queryClient = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (id: string) => api.delete(`/targets/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["targets"] });
    },
  });
}
