import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

describe("D1 schema", () => {
  it("has all M0 tables", async () => {
    const { results } = await env.DB.prepare(
      `SELECT name FROM sqlite_master
        WHERE type = 'table'
          AND name NOT LIKE 'sqlite_%'
          AND name NOT LIKE 'd1_%'
          AND substr(name, 1, 1) <> '_'
        ORDER BY name`,
    ).all<{ name: string }>();
    expect(results.map((r) => r.name)).toEqual([
      "acme_accounts",
      "api_keys",
      "audit_log",
      "certificates",
      "challenge_records",
      "domains",
      "issue_runs",
      "pull_events",
    ]);
  });

  it("has the two partial unique indexes", async () => {
    const { results } = await env.DB.prepare(
      `SELECT name FROM sqlite_master
        WHERE type = 'index' AND name IN ('idx_cert_current', 'idx_run_active')`,
    ).all();
    expect(results).toHaveLength(2);
  });
});
