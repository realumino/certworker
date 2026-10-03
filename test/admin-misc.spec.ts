import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { listAuditHandler } from "../src/admin/audit";
import { createAdminDependencies, type AdminDependencies } from "../src/admin/deps";
import { getOverviewHandler } from "../src/admin/overview";
import { listPullsHandler } from "../src/admin/pulls";
import { finishIssueRun, insertAuditLog } from "../src/store/d1";
import { readJson } from "./support/fake-fetch";
import { seedApiKey, seedCertificate, seedPullEvent } from "./support/admin";
import { seedDomain, seedIssueRun } from "./support/fixtures";

const makeDeps = (): AdminDependencies => createAdminDependencies(env, "admin@example.com");

describe("admin overview", () => {
  it("reports zeros on an empty database", async () => {
    const response = await getOverviewHandler(makeDeps(), new Request("https://certworker.example.org/api/overview"));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      domains: { active: 0, paused: 0, deleted: 0, total: 0 },
      certificates: { current: 0, expiring_within_30_days: 0, next_expiry: null },
      runs: { queued: 0, running: 0, failed_last_24h: 0, latest_failure: null },
      keys: { active: 0, revoked: 0, last_used_at: null },
    });
  });

  it("aggregates domains, certificates, runs, and keys", async () => {
    const activeDomain = await seedDomain(env.DB);
    await seedDomain(env.DB, { name: "paused.example.com", status: "paused" });
    const soonExpiry = new Date(Date.now() + 20 * 24 * 60 * 60 * 1000).toISOString();
    await seedCertificate(env.DB, env.CERTS, activeDomain.id, env.ENVELOPE_KEY, {
      domainName: activeDomain.name,
      notAfter: soonExpiry,
    });
    const { runId } = await seedIssueRun(env.DB, activeDomain.id);
    await finishIssueRun(env.DB, runId, activeDomain.id, { status: "failed", error: "boom" });
    await seedApiKey(env.DB, { label: "node-1" });

    const response = await getOverviewHandler(makeDeps(), new Request("https://certworker.example.org/api/overview"));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      domains: { active: 1, paused: 1, deleted: 0, total: 2 },
      certificates: { current: 1, expiring_within_30_days: 1, next_expiry: soonExpiry },
      runs: {
        queued: 0,
        running: 0,
        failed_last_24h: 1,
        latest_failure: {
          id: runId,
          domain_id: activeDomain.id,
          error: "boom",
          finished_at: expect.any(String),
        },
      },
      keys: { active: 1, revoked: 0, last_used_at: null },
    });
  });
});

describe("admin pulls listing", () => {
  it("lists pull events with key labels and domain names, with filters", async () => {
    const key = await seedApiKey(env.DB, { label: "node-1" });
    const otherKey = await seedApiKey(env.DB, { label: "node-2" });
    const domain = await seedDomain(env.DB);
    const otherDomain = await seedDomain(env.DB, { name: "two.example.com" });
    await seedPullEvent(env.DB, key.id, domain.id);
    await seedPullEvent(env.DB, otherKey.id, otherDomain.id);
    const deps = makeDeps();

    const all = await listPullsHandler(deps, new Request("https://certworker.example.org/api/pulls"));
    expect(all.status).toBe(200);
    const allBody = await readJson<Array<Record<string, unknown>>>(all);
    expect(allBody).toHaveLength(2);
    expect(allBody[0]).toMatchObject({
      api_key_label: expect.any(String),
      domain_name: expect.any(String),
      ip: "203.0.113.10",
      user_agent: "certworker-agent/1.0",
      status: 200,
    });

    const byKey = await listPullsHandler(deps, new Request(`https://certworker.example.org/api/pulls?api_key_id=${key.id}`));
    const byKeyBody = await readJson<Array<Record<string, unknown>>>(byKey);
    expect(byKeyBody).toHaveLength(1);
    expect(byKeyBody[0].api_key_label).toBe("node-1");

    const byDomain = await listPullsHandler(deps, new Request(`https://certworker.example.org/api/pulls?domain_id=${otherDomain.id}`));
    const byDomainBody = await readJson<Array<Record<string, unknown>>>(byDomain);
    expect(byDomainBody).toHaveLength(1);
    expect(byDomainBody[0].domain_name).toBe("two.example.com");
  });

  it("validates pagination", async () => {
    const tooHigh = await listPullsHandler(makeDeps(), new Request("https://certworker.example.org/api/pulls?limit=999"));
    expect(tooHigh.status).toBe(400);

    const notANumber = await listPullsHandler(makeDeps(), new Request("https://certworker.example.org/api/pulls?limit=abc"));
    expect(notANumber.status).toBe(400);

    const negative = await listPullsHandler(makeDeps(), new Request("https://certworker.example.org/api/pulls?offset=-1"));
    expect(negative.status).toBe(400);
  });
});

describe("admin audit listing", () => {
  it("lists entries with parsed metadata and filters by action", async () => {
    await insertAuditLog(env.DB, { actor: "a@example.com", action: "domain.create", target: "d1", meta: { name: "one.example.com" } });
    await insertAuditLog(env.DB, { actor: "a@example.com", action: "key.create", target: "k1" });
    const deps = makeDeps();

    const all = await listAuditHandler(deps, new Request("https://certworker.example.org/api/audit"));
    expect(all.status).toBe(200);
    const allBody = await readJson<Array<Record<string, unknown>>>(all);
    expect(allBody).toHaveLength(2);
    expect(allBody.map((row) => row.action).sort()).toEqual(["domain.create", "key.create"]);
    expect(allBody[0]).toMatchObject({ actor: "a@example.com", target: expect.anything() });

    const filtered = await listAuditHandler(deps, new Request("https://certworker.example.org/api/audit?action=domain.create"));
    const filteredBody = await readJson<Array<Record<string, unknown>>>(filtered);
    expect(filteredBody).toHaveLength(1);
    expect(filteredBody[0]).toMatchObject({ action: "domain.create", target: "d1", meta: { name: "one.example.com" } });
  });
});
