import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// DOM tests for the admin SPA. The Worker suite runs separately in the workerd
// pool (root vitest.config.ts) and is scoped to test/** so it never picks these up.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "happy-dom",
    include: ["src/**/*.{spec,test}.{ts,tsx}"],
    setupFiles: ["src/__tests__/setup.ts"],
  },
});
