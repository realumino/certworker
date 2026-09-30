import { applyD1Migrations } from "cloudflare:test";
import { env } from "cloudflare:workers";

// Setup files run outside per-test-file storage isolation and may run multiple
// times; applyD1Migrations only applies what is not yet recorded.
await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
