import type { ReactElement } from "react";
import { render, type RenderOptions } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

/**
 * Build a fresh QueryClient for each test.
 *
 * Retries are disabled so a rejected query fails fast (no retry delays),
 * and `staleTime: Infinity` keeps queries from refetching mid-test —
 * deterministic render output is more valuable than live freshness here.
 */
function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: Infinity, refetchOnWindowFocus: false },
      mutations: { retry: false },
    },
  });
}

interface ProvidersProps {
  client: QueryClient;
  initialEntries?: string[];
  children: ReactElement;
}

/** Wrap children with the TanStack Query client and a Memory router. */
function Providers({ client, initialEntries = ["/"], children }: ProvidersProps) {
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={initialEntries}>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

interface RenderWithProvidersOptions extends Omit<RenderOptions, "wrapper"> {
  initialEntries?: string[];
}

/**
 * Render a React element wrapped in every provider the app's components
 * expect (TanStack Query + React Router), returning the Testing Library
 * helpers plus the per-test QueryClient for direct cache access.
 */
export function renderWithProviders(
  ui: ReactElement,
  { initialEntries, ...options }: RenderWithProvidersOptions = {},
) {
  const client = makeQueryClient();
  const result = render(ui, {
    wrapper: ({ children }) => (
      <Providers client={client} initialEntries={initialEntries}>
        {children as ReactElement}
      </Providers>
    ),
    ...options,
  });
  return { ...result, client };
}

export { render } from "@testing-library/react";
export * from "@testing-library/react";
