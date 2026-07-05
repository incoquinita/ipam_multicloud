import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

// Recharts' ResponsiveContainer measures its host element via
// ResizeObserver; jsdom does not implement it. The stub invokes the
// callback synchronously with a fixed size so charts render their SVG
// content instead of staying at a zero-width placeholder.
class ResizeObserverStub {
  private callback: ResizeObserverCallback;

  constructor(callback: ResizeObserverCallback) {
    this.callback = callback;
  }

  observe(target: Element): void {
    this.callback(
      [
        {
          target,
          contentRect: { width: 500, height: 300, top: 0, left: 0, bottom: 0, right: 0 },
        } as unknown as ResizeObserverEntry,
      ],
      this as unknown as ResizeObserver,
    );
  }

  unobserve(): void {}
  disconnect(): void {}
}
vi.stubGlobal("ResizeObserver", ResizeObserverStub);

// jsdom lacks matchMedia, which some UI primitives consult for reduced-
// motion preferences. Provide a no-op implementation so imports succeed.
vi.stubGlobal(
  "matchMedia",
  (query: string): MediaQueryList => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  }),
);

// Unmount every component after each test so the DOM stays pristine
// between cases (React Testing Library's recommended teardown).
afterEach(() => {
  cleanup();
});
