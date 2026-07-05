import { describe, it, expect, beforeEach, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";

import { renderWithProviders } from "@/test/utils";
import { PortDistribution } from "@/components/dashboard/PortDistribution";
import { api } from "@/lib/api";

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

const MOCK_ITEMS = [
  { port: 22, service_name: "SSH", count: 12, critical_count: 0 },
  { port: 80, service_name: "HTTP", count: 8, critical_count: 1 },
  { port: 443, service_name: "HTTPS", count: 5, critical_count: 0 },
  { port: 3389, service_name: "RDP", count: 3, critical_count: 2 },
];

beforeEach(() => {
  vi.clearAllMocks();
});

describe("PortDistribution", () => {
  it("renders the card title and a port-count badge with mock data", async () => {
    mockedApi.get.mockResolvedValue({ items: MOCK_ITEMS });

    renderWithProviders(<PortDistribution />);

    expect(screen.getByText("Port Distribution")).toBeInTheDocument();
    // The badge summarises how many ports are charted.
    expect(await screen.findByText("4 ports")).toBeInTheDocument();
  });

  it("renders a bar chart (SVG) for the port findings", async () => {
    mockedApi.get.mockResolvedValue({ items: MOCK_ITEMS });

    const { container } = renderWithProviders(<PortDistribution />);

    // Wait for the query to resolve — the badge appears once data lands.
    await screen.findByText("4 ports");

    // ResponsiveContainer measures its host via ResizeObserver (stubbed
    // in setup) and re-renders with real dimensions; the bar layer
    // mounts on that second pass, so wait for it.
    await waitFor(() => {
      expect(container.querySelector(".recharts-bar")).toBeTruthy();
    });

    // Recharts renders the bar chart as an inline <svg> inside the card.
    const svg = container.querySelector("svg");
    expect(svg).toBeInTheDocument();
    // The empty state must not be shown once data is present.
    expect(screen.queryByText(/no port findings yet/i)).not.toBeInTheDocument();
  });

  it("shows the empty state when no port findings exist", async () => {
    mockedApi.get.mockResolvedValue({ items: [] });

    renderWithProviders(<PortDistribution />);

    expect(
      await screen.findByText(/no port findings yet/i),
    ).toBeInTheDocument();
    // No port-count badge when there is nothing to chart.
    expect(screen.queryByText(/ports$/)).not.toBeInTheDocument();
  });
});
