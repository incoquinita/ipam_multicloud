import { create } from "zustand";
import type { AuthUser } from "@/types/auth";

interface AuthState {
  /** Access token (also persisted to localStorage for the API client). */
  token: string | null;
  /** Refresh token for obtaining a new access token. */
  refreshToken: string | null;
  /** Authenticated user profile (fetched from /auth/me). */
  user: AuthUser | null;
  isAuthenticated: boolean;
  /** Store an access + refresh token pair after a successful login. */
  setTokens: (access: string, refresh: string) => void;
  /** Store the authenticated user profile. */
  setUser: (user: AuthUser | null) => void;
  /** Back-compat single-token setter. */
  setToken: (token: string | null) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  token: localStorage.getItem("access_token"),
  refreshToken: localStorage.getItem("refresh_token"),
  user: null,
  isAuthenticated: !!localStorage.getItem("access_token"),
  setTokens: (access, refresh) => {
    localStorage.setItem("access_token", access);
    localStorage.setItem("refresh_token", refresh);
    set({ token: access, refreshToken: refresh, isAuthenticated: true });
  },
  setUser: (user) => set({ user }),
  setToken: (token) => {
    if (token) {
      localStorage.setItem("access_token", token);
    } else {
      localStorage.removeItem("access_token");
    }
    set({ token, isAuthenticated: !!token });
  },
  logout: () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    set({ token: null, refreshToken: null, user: null, isAuthenticated: false });
  },
}));
