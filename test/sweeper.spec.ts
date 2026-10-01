import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
  sweep,
  sweepStaleChallengeRecords,
  sweepUnpurgedCertificates,
  type SweeperDependencies,
} from "../src/issue/sweeper";
import { createTxtRecord } from "../src/dns/cloudflare";
import { getCertificate, getDomain, insertChallengeRecord, listPendingChallengeRecords, type DomainRow } from "../src/store/d1";
import { createScriptedFetch, jsonResponse } from "./support/fake-fetch";
import { MockCloudflareDns } from "./support/mock-dns";
import { seedCertificate } from "./support/admin";
import { seedDomain, seedIssueRun } from "./support/fixtures";

const NOW = new Date("2026-01-02T00:00:00.000Z");

function makeSetup() {
  const dns = new MockCloudflareDns();
  const { fetch, requests } = createScriptedFetch(async (request) => {
    const response = await dns.handle(request);
    if (response) return response;
    throw new Error(`No offline mock for ${request.request.method} ${request.url.href}`);
  });
  return { dns, fetch, requests };
}

function sweeperDeps(fetcher: typeof fetch): SweeperDependencies {
  return { db: env.DB, bucket: env.CERTS, dnsApiToken: "test-token", fetcher, now: () => NOW };
}

describe("certificate sweeper", () => {
  it("purges superseded and revoked prefixes and leaves current rows alone", async () => {
    const domain = await seedDomain(env.DB, { name: "sweep-certs.example.com" });
    const current = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
    });
    const superseded = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
      status: "superseded",
    });
    const revoked = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
      status: "revoked",
    });
    // Already-purged rows are not listed again.
    await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
      status: "superseded",
      purgedAt: "2025-12-01T00:00:00.000Z",
      storeArtifacts: false,
    });

    await expect(sweepUnpurgedCertificates(sweeperDeps(makeSetup().fetch))).resolves.toEqual({
      purged: 2,
      failed: 0,
    });
    expect((await env.CERTS.list({ prefix: `${superseded.r2_prefix}/` })).objects).toHaveLength(0);
    expect((await env.CERTS.list({ prefix: `${revoked.r2_prefix}/` })).objects).toHaveLength(0);
    expect((await env.CERTS.list({ prefix: `${current.r2_prefix}/` })).objects).toHaveLength(4);
    await expect(getCertificate(env.DB, superseded.id)).resolves.toMatchObject({ purged_at: expect.any(String) });
    await expect(getCertificate(env.DB, current.id)).resolves.toMatchObject({ purged_at: null, status: "current" });
  });
});

describe("stale challenge-record sweeper", () => {
  async function seedChallengeRow(
    domain: DomainRow,
    runId: string,
    recordId: string,
    name: string,
    createdAt: string,
  ): Promise<string> {
    const id = crypto.randomUUID();
    await insertChallengeRecord(env.DB, {
      id,
      run_id: runId,
      zone_id: domain.zone_id,
      cf_record_id: recordId,
      name,
      value: `value-for-${name}`,
    });
    await env.DB.prepare("UPDATE challenge_records SET created_at = ? WHERE id = ?").bind(createdAt, id).run();
    return id;
  }

  it("deletes records older than 24h and marks them, keeping fresh ones", async () => {
    const { dns, fetch } = makeSetup();
    const domain = await seedDomain(env.DB, { name: "sweep-txt.example.com" });
    const { runId } = await seedIssueRun(env.DB, domain.id);
    const staleId = await createTxtRecord({
      apiToken: "test-token",
      zoneId: domain.zone_id,
      name: `_acme-challenge.stale.example.com`,
      value: "stale",
      fetch,
    });
    const freshId = await createTxtRecord({
      apiToken: "test-token",
      zoneId: domain.zone_id,
      name: `_acme-challenge.fresh.example.com`,
      value: "fresh",
      fetch,
    });
    await seedChallengeRow(domain, runId, staleId, "_acme-challenge.stale.example.com", new Date(NOW.getTime() - 25 * 3600_000).toISOString());
    await seedChallengeRow(domain, runId, freshId, "_acme-challenge.fresh.example.com", new Date(NOW.getTime() - 1 * 3600_000).toISOString());

    await expect(sweepStaleChallengeRecords(sweeperDeps(fetch))).resolves.toEqual({ deleted: 1, failed: 0 });
    expect(dns.records.map(({ id }) => id)).toEqual([freshId]);
    expect(await listPendingChallengeRecords(env.DB, runId)).toHaveLength(1);
  });

  it("counts a 404 from the DNS API as deleted", async () => {
    const { fetch } = makeSetup();
    const domain = await seedDomain(env.DB, { name: "sweep-gone.example.com" });
    const { runId } = await seedIssueRun(env.DB, domain.id);
    const rowId = await seedChallengeRow(domain, runId, "gone-record-id", "_acme-challenge.gone.example.com", new Date(NOW.getTime() - 48 * 3600_000).toISOString());

    await expect(sweepStaleChallengeRecords(sweeperDeps(fetch))).resolves.toEqual({ deleted: 1, failed: 0 });
    const pending = await env.DB.prepare("SELECT deleted_at FROM challenge_records WHERE id = ?")
      .bind(rowId)
      .first<{ deleted_at: string | null }>();
    expect(pending?.deleted_at).not.toBeNull();
  });

  it("keeps the row and reports failures when the DNS API errors", async () => {
    const domain = await seedDomain(env.DB, { name: "sweep-broken.example.com" });
    const { runId } = await seedIssueRun(env.DB, domain.id);
    const rowId = await seedChallengeRow(domain, runId, crypto.randomUUID(), "_acme-challenge.broken.example.com", new Date(NOW.getTime() - 48 * 3600_000).toISOString());
    const { fetch } = createScriptedFetch(() => jsonResponse({ success: false, errors: [{ message: "boom" }] }, { status: 500 }));

    await expect(sweepStaleChallengeRecords(sweeperDeps(fetch))).resolves.toEqual({ deleted: 0, failed: 1 });
    const pending = await env.DB.prepare("SELECT deleted_at FROM challenge_records WHERE id = ?")
      .bind(rowId)
      .first<{ deleted_at: string | null }>();
    expect(pending?.deleted_at).toBeNull();
    // Test hygiene: this file shares one D1 database, so leave no stale rows
    // behind for later tests in the file.
    await env.DB.prepare("UPDATE challenge_records SET deleted_at = ? WHERE id = ?").bind(NOW.toISOString(), rowId).run();
  });
});

describe("combined sweep", () => {
  it("runs both passes and aggregates the counts", async () => {
    const domain = await seedDomain(env.DB, { name: "sweep-all.example.com" });
    await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
      status: "superseded",
    });
    const { fetch } = makeSetup();

    await expect(sweep(sweeperDeps(fetch))).resolves.toEqual({
      certificatesPurged: 1,
      certificateFailures: 0,
      challengesDeleted: 0,
      challengeFailures: 0,
    });
  });
});
