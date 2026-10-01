import path from "node:path";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

const TEST_DNS_API_TOKEN = "test-only-token";
const TEST_ENVELOPE_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
// Wrangler checks secrets before Miniflare applies the test bindings below.
process.env.CF_DNS_API_TOKEN ??= TEST_DNS_API_TOKEN;
process.env.ENVELOPE_KEY ??= TEST_ENVELOPE_KEY;

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(import.meta.dirname, "migrations"));
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          // Test-only binding so the setup file can apply migrations.
          bindings: {
            TEST_MIGRATIONS: migrations,
            CF_DNS_API_TOKEN: TEST_DNS_API_TOKEN,
            ENVELOPE_KEY: TEST_ENVELOPE_KEY,
          },
        },
      }),
    ],
    test: {
      setupFiles: ["./test/apply-migrations.ts"],
    },
  };
});
