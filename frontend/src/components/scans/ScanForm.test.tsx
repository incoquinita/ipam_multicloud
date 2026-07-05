import { describe, it, expect, beforeEach, vi } from "vitest";
import userEvent from "@testing-library/user-event";
import { screen, waitFor, within } from "@testing-library/react";

import { renderWithProviders } from "@/test/utils";
import { ScanForm } from "@/components/scans/ScanForm";
import { api } from "@/lib/api";

// Mock the API client at the boundary — hooks delegate to it, so a single
// mock controls every query/mutation the form drives.
vi.mock("@/lib/api", () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}));

// `@/lib/api` is mocked, so the imported `api` is the mock instance.
const mockedApi = api as unknown as {
  get: ReturnType<typeof vi.fn>;
  post: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
  vi.clearAllMocks();
  // Default: no cloud providers configured (manual mode is the focus).
  mockedApi.get.mockResolvedValue({ items: [] });
  mockedApi.post.mockResolvedValue({});
});

// ── Form validation ────────────────────────────────────────────────

describe("ScanForm validation", () => {
  it("shows an IP/CIDR error when submitting with an empty manual target", async () => {
    const user = userEvent.setup();
    renderWithProviders(<ScanForm />);

    await user.click(screen.getByRole("button", { name: /start scan/i }));

    // The zod refine guards manual mode with an IP/CIDR regex.
    expect(
      await screen.findByText(/enter a valid ip or cidr/i),
    ).toBeInTheDocument();
    // The API mutation must not fire on an invalid form.
    expect(mockedApi.post).not.toHaveBeenCalled();
  });

  it("starts a scan when the manual target is a valid IP", async () => {
    const user = userEvent.setup();
    const onSuccess = vi.fn();
    renderWithProviders(<ScanForm onSuccess={onSuccess} />);

    await user.type(
      screen.getByPlaceholderText("192.168.1.1 or 10.0.0.0/24"),
      "10.0.0.1",
    );
    await user.click(screen.getByRole("button", { name: /start scan/i }));

    // The mutation fires the API call, then the form's onSuccess prop.
    await waitFor(() =>
      expect(mockedApi.post).toHaveBeenCalledWith("/scans", expect.anything()),
    );
    await waitFor(() => expect(onSuccess).toHaveBeenCalled());
  });
});

// ── Profile selection updates the port preview ─────────────────────

describe("ScanForm profile preview", () => {
  it("renders the quick-profile port chips by default", () => {
    renderWithProviders(<ScanForm />);

    // Quick profile scans 22, 23, 80, 443, 3389, 8080, 8443, 21, 445, 3306.
    const preview = screen.getByText(/ports to scan/i).parentElement!;
    expect(within(preview).getByText("22")).toBeInTheDocument();
    expect(within(preview).getByText("3306")).toBeInTheDocument();
  });

  it("updates the preview chips when the standard profile is selected", async () => {
    const user = userEvent.setup();
    renderWithProviders(<ScanForm />);

    // Port 25 (SMTP) is in the standard profile but NOT the quick profile.
    expect(screen.queryByText("25")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /^standard$/i }));

    expect(screen.getByText("25")).toBeInTheDocument();
    // Standard description appears under the segmented control.
    expect(screen.getByText(/standard — top 38 admin ports/i)).toBeInTheDocument();
  });

  it("shows the range summary for the thorough profile", async () => {
    const user = userEvent.setup();
    renderWithProviders(<ScanForm />);

    await user.click(screen.getByRole("button", { name: /^thorough$/i }));

    expect(
      screen.getByText(/ports 1–1024 plus the admin ports/i),
    ).toBeInTheDocument();
  });
});

// ── Custom port selection ──────────────────────────────────────────

describe("ScanForm custom ports", () => {
  it("adds a selected port checkbox to the preview", async () => {
    const user = userEvent.setup();
    renderWithProviders(<ScanForm />);

    await user.click(screen.getByRole("button", { name: /^custom$/i }));

    // No preview chips yet — custom mode starts with no selected ports.
    expect(screen.queryByText(/ports to scan/i)).not.toBeInTheDocument();

    // The first checkbox in the Management category is SSH (port 22).
    const checkboxes = screen.getAllByRole("checkbox");
    const sshCheckbox = checkboxes[0];
    if (!sshCheckbox) throw new Error("Expected at least one port checkbox");
    await user.click(sshCheckbox);

    // Scope to the preview panel so the chip "22" is not confused with
    // the "22" shown beside the SSH checkbox label.
    const previewHeader = await screen.findByText(/ports to scan/i);
    const preview = previewHeader.closest("div")!;
    expect(within(preview).getByText("22")).toBeInTheDocument();
  });

  it("includes additional custom ports typed into the input", async () => {
    const user = userEvent.setup();
    renderWithProviders(<ScanForm />);

    await user.click(screen.getByRole("button", { name: /^custom$/i }));

    await user.type(
      screen.getByPlaceholderText("e.g. 8888, 9000, 5601"),
      "8888",
    );

    // The custom-ports input is registered with react-hook-form; preview
    // recomputes from parseCustomPorts on every render.
    expect(screen.getByText("8888")).toBeInTheDocument();
  });
});

// ── Toggle switches ────────────────────────────────────────────────

describe("ScanForm toggle options", () => {
  it("renders all three option rows", () => {
    renderWithProviders(<ScanForm />);

    expect(screen.getByText("Banner grabbing")).toBeInTheDocument();
    expect(screen.getByText("HTTP analysis")).toBeInTheDocument();
    expect(screen.getByText("Rate-limit probing")).toBeInTheDocument();
  });

  it("disables the rate-limit switch when HTTP analysis is turned off", async () => {
    const user = userEvent.setup();
    renderWithProviders(<ScanForm />);

    // Each ToggleRow pairs a title paragraph with a sibling Switch; scope
    // to the row so we target the exact switch by its label.
    const httpRow = screen.getByText("HTTP analysis").closest("div")!
      .parentElement!;
    const httpSwitch = within(httpRow).getByRole("switch");

    const rateRow = screen.getByText("Rate-limit probing").closest("div")!
      .parentElement!;
    const rateLimitSwitch = within(rateRow).getByRole("switch");

    // Rate-limit probing is enabled while HTTP analysis is on (default).
    expect(httpSwitch).toBeEnabled();
    expect(rateLimitSwitch).toBeEnabled();

    await user.click(httpSwitch);

    // Toggling HTTP analysis off disables the dependent rate-limit switch.
    expect(httpSwitch).not.toBeChecked();
    expect(rateLimitSwitch).toBeDisabled();
  });
});
