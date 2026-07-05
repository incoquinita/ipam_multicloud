import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation } from "@tanstack/react-query";
import { useNavigate, Link } from "react-router-dom";
import { Radar, Lock, Loader2, AlertCircle, LogIn } from "lucide-react";

import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { api } from "@/lib/api";
import { useAuthStore } from "@/stores/authStore";
import { useToastStore } from "@/stores/toastStore";
import type { LoginRequest, TokenResponse, AuthUser } from "@/types/auth";

const loginSchema = z.object({
  username: z.string().min(1, "Enter your username"),
  password: z.string().min(1, "Enter your password"),
});

type LoginValues = z.infer<typeof loginSchema>;

export function Login() {
  const navigate = useNavigate();
  const setTokens = useAuthStore((s) => s.setTokens);
  const setUser = useAuthStore((s) => s.setUser);
  const addToast = useToastStore((s) => s.addToast);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { username: "", password: "" },
  });

  const loginMutation = useMutation<TokenResponse, Error, LoginRequest>({
    mutationFn: (data) => api.post<TokenResponse>("/auth/login", data),
    onSuccess: async (tokens) => {
      // Persist tokens first so /auth/me can authenticate.
      setTokens(tokens.access_token, tokens.refresh_token);
      try {
        const user = await api.get<AuthUser>("/auth/me");
        setUser(user);
      } catch {
        // /auth/me failure is non-fatal — tokens are already stored.
      }
      addToast({
        variant: "success",
        title: "Welcome back",
        description: "Signed in successfully.",
      });
      navigate("/", { replace: true });
    },
  });

  const onSubmit = (values: LoginValues) => {
    loginMutation.mutate(values);
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-surface-950 p-6">
      {/* Ambient gradient mesh */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="aura-drift absolute -top-24 -left-24 h-96 w-96 rounded-full bg-brand-700/30 blur-3xl" />
        <div
          className="aura-drift absolute -bottom-32 -right-24 h-96 w-96 rounded-full bg-info/20 blur-3xl"
          style={{ animationDelay: "-4s" }}
        />
        <div
          className="aura-drift absolute top-1/3 left-1/2 h-72 w-72 -translate-x-1/2 rounded-full bg-brand-500/10 blur-3xl"
          style={{ animationDelay: "-8s" }}
        />
      </div>

      {/* Login panel */}
      <div className="relative w-full max-w-md">
        <div className="overflow-hidden rounded-2xl border border-surface-800 bg-surface-900/80 shadow-2xl backdrop-blur-xl">
          {/* Brand header band */}
          <div className="flex flex-col items-center gap-3 border-b border-surface-800 bg-gradient-to-b from-brand-900/40 to-transparent px-8 py-8">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-brand-600 shadow-lg shadow-brand-900/50">
              <Radar className="h-6 w-6 text-white" />
            </div>
            <div className="text-center">
              <h1 className="text-xl font-bold text-surface-50">
                IPAM MultiCloud
              </h1>
              <p className="mt-1 text-xs text-surface-400">
                Sign in to your security console
              </p>
            </div>
          </div>

          {/* Form */}
          <form
            onSubmit={handleSubmit(onSubmit)}
            className="space-y-4 px-8 py-7"
            noValidate
          >
            <Input
              label="Username"
              placeholder="your.username"
              autoComplete="username"
              error={errors.username?.message}
              {...register("username")}
            />
            <Input
              label="Password"
              type="password"
              placeholder="••••••••"
              autoComplete="current-password"
              error={errors.password?.message}
              {...register("password")}
            />

            {loginMutation.error && (
              <div className="flex items-start gap-2 rounded-lg border border-danger/30 bg-danger/10 p-3">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-danger" />
                <p className="text-xs text-danger">
                  {loginMutation.error.message}
                </p>
              </div>
            )}

            <Button
              type="submit"
              size="lg"
              className="w-full"
              disabled={loginMutation.isPending}
            >
              {loginMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Signing in...
                </>
              ) : (
                <>
                  <LogIn className="mr-2 h-4 w-4" />
                  Sign in
                </>
              )}
            </Button>

            <p className="flex items-center justify-center gap-1.5 pt-1 text-center text-xs text-surface-400">
              <Lock className="h-3 w-3" />
              Credentials are encrypted in transit
            </p>
          </form>

          {/* Footer */}
          <div className="border-t border-surface-800 px-8 py-4 text-center">
            <p className="text-xs text-surface-400">
              Need an account?{" "}
              <Link
                to="/register"
                className="font-medium text-brand-300 hover:text-brand-200"
              >
                Register
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
