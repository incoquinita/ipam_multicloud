import { BrowserRouter, Routes, Route, Navigate, Outlet } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Layout } from "./components/layout/Layout";
import { Toaster } from "./components/ui/Toaster";
import { useAuthStore } from "./stores/authStore";
import { Dashboard } from "./routes/Dashboard";
import { Scans } from "./routes/Scans";
import { ScanResults } from "./routes/ScanResults";
import { Targets } from "./routes/Targets";
import { Credentials } from "./routes/Credentials";
import { Settings } from "./routes/Settings";
import { Login } from "./routes/Login";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 2,
      refetchOnWindowFocus: false,
    },
  },
});

/** Guard that redirects unauthenticated users to the login page. */
function ProtectedRoute() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return <Outlet />;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          {/* Public route — no layout, no auth required */}
          <Route path="/login" element={<Login />} />

          {/* Protected routes — wrapped in the auth guard */}
          <Route element={<ProtectedRoute />}>
            <Route element={<Layout />}>
              <Route path="/" element={<Dashboard />} />
              <Route path="/scans" element={<Scans />} />
              <Route path="/scans/:id/results" element={<ScanResults />} />
              <Route path="/targets" element={<Targets />} />
              <Route path="/credentials" element={<Credentials />} />
              <Route path="/settings" element={<Settings />} />
            </Route>
          </Route>

          {/* Fallback — unknown paths return to the dashboard */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
      <Toaster />
    </QueryClientProvider>
  );
}
