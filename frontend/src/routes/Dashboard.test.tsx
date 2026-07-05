import { describe, it, expect, beforeEach, vi } from "vitest";
import { screen } from "@testing-library/react";

import { renderWithProviders } from "@/test/utils";
import { Dashboard } from "@/routes/Dashboard";
import { api } from "@/lib/api";
import type { DashboardStats } from "@/types/analytics";

vi.mock("@/lib/api", () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}));

const mockedApi = api as unknown as {
  get: ReturnType<typeof vi.fn>;
};

const MOCK_STATS: DashboardStats = {
  total_targets: 12,
  total_scans: 30,
  active_scans: 2,
  completed_scans: 27,
  total_open_ports: 34,
  critical_findings: 5,
  high_findings: 9,
  medium_findings: 14,
  low_findings: 6,
  total_ips: 48,
  scans_last_7_days: 18,
};

/**
 * Route each API path to a sensible mock response. The Dashboard mounts
 * several widgets that each drive their own query; routing by path keeps
 * a single mock in control of every one.
 */
function routeApi(path: string): unknown {
  if (path.startsWith("/scans/stats")) return MOCK_STATS;
  // The other dashboard widgets receive empty payloads so they render
  // their empty states without masking the KPI assertions.
  if (path.startsWith("/analytics/timeline")) return { items: [] };
  if (path.startsWith("/analytics/port-distribution")) return { items: [] };
  if (path.startsWith("/scans")) return { items: [] };
  if (path.startsWith("/cloud-providers")) return { items: [] };
  return { items: [] };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockedApi.get.mockImplementation((path: string) =>
    Promise.resolve(routeApi(path)),
  );
});

describe("Dashboard", () => {
  it("renders the page header", () => {
    renderWithProviders(<Dashboard />);
    expect(
      screen.getByRole("heading", { name: /dashboard/i }),
    ).toBeInTheDocument();
  });

  it("renders the four KPI cards with the stat values", async () => {
    renderWithProviders(<Dashboard />);

    // Wait for the stats query to resolve — "12" is the Total Targets
    // value, which only appears once the async fetch lands.
    expect(await screen.findByText("12")).toBeInTheDocument();

    // Each KpiCard pairs a title with its value; assert the pairs land
    // together so a misaligned card cannot pass.
    expect(screen.getByText("Total Targets")).toBeInTheDocument();
    expect(screen.getByText("Open Ports Found")).toBeInTheDocument();
    expect(screen.getByText("34")).toBeInTheDocument();
    expect(screen.getByText("Active Scans")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText("Critical Findings")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
  });

  it("fetches the dashboard stats from the scans/stats endpoint", async () => {
    renderWithProviders(<Dashboard />);

    await screen.findByText("12");
    expect(mockedApi.get).toHaveBeenCalledWith("/scans/stats");
  });

  it("renders zero values before stats load", () => {
    // A pending promise keeps the query in `loading` so KpiCards fall
    // back to their `?? 0` defaults. The executor returns undefined and
    // never resolves.
    mockedApi.get.mockImplementation(() => new Promise<unknown>(() => undefined));
    renderWithProviders(<Dashboard />);

    // All four KPI cards show 0 while stats are still loading — the
    // child widgets render "Loading..." text, so the only "0" elements
    // are the four KPI value spans.
    expect(screen.getAllByText("0")).toHaveLength(4);
  });
});
