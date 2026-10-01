import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: {
    // Dev loop against `wrangler dev` (see README). changeOrigin is off on
    // purpose: the proxied request keeps Host localhost:5173, matching the
    // browser's Origin, so the admin mutation guard accepts it while the
    // hostname stays loopback for the DEV_ACCESS_EMAIL bypass.
    proxy: {
      "/api": { target: "http://localhost:8787", changeOrigin: false },
    },
  },
});
