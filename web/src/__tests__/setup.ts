import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

// One teardown for every file: unmount before restoring globals (vitest runs
// afterEach LIFO), otherwise a late effect can fire a real fetch after the
// stub is gone. @testing-library/react only auto-cleans with global afterEach,
// which vitest does not provide without `globals: true`.
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
