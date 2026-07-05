import { describe, it, expect, beforeEach, vi } from "vitest";
import userEvent from "@testing-library/user-event";
import { screen } from "@testing-library/react";

import { renderWithProviders } from "@/test/utils";
import { Login } from "@/routes/Login";
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
  post: ReturnType<typeof vi.fn>;
};

const TOKEN_RESPONSE = {
  access_token: "access-token-abc",
  refresh_token: "refresh-token-xyz",
  token_type: "bearer",
  expires_in: 3600,
};

const AUTH_USER = {
  id: "user-1",
  email: "admin@example.com",
  username: "admin",
  is_active: true,
  is_superuser: false,
};

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");
  mockedApi.get.mockResolvedValue(AUTH_USER);
  mockedApi.post.mockResolvedValue(TOKEN_RESPONSE);
});

describe("Login validation", () => {
  it("shows errors for both fields when submitting an empty form", async () => {
    const user = userEvent.setup();
    renderWithProviders(<Login />);

    await user.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByText("Enter your username")).toBeInTheDocument();
    expect(screen.getByText("Enter your password")).toBeInTheDocument();
    expect(mockedApi.post).not.toHaveBeenCalled();
  });

  it("requires both username and password", async () => {
    const user = userEvent.setup();
    renderWithProviders(<Login />);

    await user.type(screen.getByPlaceholderText("your.username"), "admin");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    // Password still empty → only the password error shows, no API call.
    expect(await screen.findByText("Enter your password")).toBeInTheDocument();
    expect(mockedApi.post).not.toHaveBeenCalled();
  });
});

describe("Login submission", () => {
  it("calls the login API with the entered credentials", async () => {
    const user = userEvent.setup();
    renderWithProviders(<Login />);

    await user.type(screen.getByPlaceholderText("your.username"), "admin");
    await user.type(screen.getByPlaceholderText("••••••••"), "s3cret");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    expect(mockedApi.post).toHaveBeenCalledWith("/auth/login", {
      username: "admin",
      password: "s3cret",
    });
    // The token response triggers /auth/me to fetch the user profile.
    expect(mockedApi.get).toHaveBeenCalledWith("/auth/me");
    // Tokens are persisted for the API client's Authorization header.
    expect(localStorage.getItem("access_token")).toBe("access-token-abc");
  });

  it("shows the error message when the API rejects the login", async () => {
    mockedApi.post.mockRejectedValue(new Error("Invalid credentials"));
    const user = userEvent.setup();
    renderWithProviders(<Login />);

    await user.type(screen.getByPlaceholderText("your.username"), "admin");
    await user.type(screen.getByPlaceholderText("••••••••"), "wrong");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByText("Invalid credentials")).toBeInTheDocument();
    // No tokens persisted on a failed login.
    expect(localStorage.getItem("access_token")).toBeNull();
  });
});
