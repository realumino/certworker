import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { createScriptedFetch } from "./support/fake-fetch";
import { seedDomain, seedIssueRun } from "./support/fixtures";
import { MockAcme, type MockAcmeOptions } from "./support/mock-acme";
import { MockCloudflareDns } from "./support/mock-dns";
import {
  acceptChallenges,
  awaitAuthorizations,
  cleanupFailedArtifacts,
  cleanupTxtRecords,
  createIssueDependencies,
  createLeafKeyAndCsr,
  createOrder,
  ensureAcmeAccount,
  finalizeAndStore,
  issueErrorMessage,
  loadIssue,
  publishTxtChallenges,
  purgePreviousCertificate,
  waitForPropagation,
} from "../src/issue/steps";
import {
  getCertificate,
  getCurrentCertificate,
  getIssueRun,
  finishIssueRun,
  listPendingChallengeRecords,
  type CertificateRow,
} from "../src/store/d1";
import { certificatePrefix } from "../src/store/r2";

describe("issuance workflow steps", () => {
  it("removes a key prefix when issuance fails before the certificate is committed in D1", async () => {
    const domain = await seedDomain(env.DB, { includeWildcard: false });
    const { runId } = await seedIssueRun(env.DB, domain.id);
    const { deps } = makeDependencies({});
    const loaded = await loadIssue(deps, runId, domain.id);
    const leaf = await createLeafKeyAndCsr(deps, runId, loaded.domain, loaded.identifiers);

    expect((await env.CERTS.list({ prefix: `${leaf.r2Prefix}/` })).objects).toHaveLength(1);
    await expect(cleanupFailedArtifacts(deps, domain.name, runId)).resolves.toEqual({ deleted: true });
    expect((await env.CERTS.list({ prefix: `${leaf.r2Prefix}/` })).objects).toHaveLength(0);
  });

  it("issues, persists, activates, purges the previous prefix, and cleans TXT records", async () => {
    const domain = await seedDomain(env.DB);
    const { runId } = await seedIssueRun(env.DB, domain.id);
    const oldCertId = crypto.randomUUID();
    const oldPrefix = certificatePrefix(domain.name, oldCertId);
    const oldCert = previousCertificate(domain.id, oldCertId, oldPrefix);
    await env.DB.prepare(
      `INSERT INTO certificates (
         id, domain_id, env, serial, fingerprint_sha256, sans_json, not_before, not_after,
         issued_at, r2_prefix, status, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'current', ?)`,
    ).bind(
      oldCert.id,
      oldCert.domain_id,
      oldCert.env,
      oldCert.serial,
      oldCert.fingerprint_sha256,
      oldCert.sans_json,
      oldCert.not_before,
      oldCert.not_after,
      oldCert.issued_at,
      oldCert.r2_prefix,
      oldCert.created_at,
    ).run();
    await env.CERTS.put(`${oldPrefix}/cert.pem`, "old certificate");
    await env.CERTS.put(`${oldPrefix}/privkey.pem.enc`, new Uint8Array([1, 2, 3]));

    const { deps, dns, requests } = makeDependencies({});
    const loaded = await loadIssue(deps, runId, domain.id);
    expect(loaded.previousCertificate?.id).toBe(oldCertId);
    expect(loaded.identifiers.map(({ value }) => value)).toEqual([domain.name, `*.${domain.name}`]);

    const account = await ensureAcmeAccount(deps);
    const order = await createOrder(deps, account, loaded.identifiers);
    const published = await publishTxtChallenges(deps, runId, loaded.domain, account, order.authorizations);
    expect(published.targets).toHaveLength(1);
    expect(published.targets[0].values).toHaveLength(2);
    expect(dns.records).toHaveLength(2);

    await waitForPropagation(deps, published);
    await acceptChallenges(deps, account, published);
    await awaitAuthorizations(deps, account, published);
    const leaf = await createLeafKeyAndCsr(deps, runId, loaded.domain, loaded.identifiers);
    const issued = await finalizeAndStore(deps, loaded.domain, loaded.identifiers, account, order, leaf);
    const purge = await purgePreviousCertificate(deps, loaded.previousCertificate);
    const cleanup = await cleanupTxtRecords(deps, runId);
    await finishIssueRun(env.DB, runId, domain.id, { status: "succeeded" });

    const current = await getCurrentCertificate(env.DB, domain.id);
    expect(current).toMatchObject({ id: runId, status: "current", env: "staging" });
    expect(JSON.parse(current?.sans_json ?? "[]")).toEqual(loaded.identifiers.map(({ value }) => value));
    expect(issued).toMatchObject({ certificateId: runId, sans: loaded.identifiers.map(({ value }) => value) });
    expect(await getCertificate(env.DB, oldCertId)).toMatchObject({ status: "superseded", purged_at: expect.any(String) });
    expect((await env.CERTS.list({ prefix: `${oldPrefix}/` })).objects).toHaveLength(0);

    const artifacts = await env.CERTS.list({ prefix: `${issued.r2Prefix}/` });
    expect(artifacts.objects.map(({ key }) => key.split("/").at(-1)).sort()).toEqual([
      "cert.pem",
      "chain.pem",
      "fullchain.pem",
      "meta.json",
      "privkey.pem.enc",
    ]);
    expect(await env.CERTS.get(`${issued.r2Prefix}/cert.pem`)).not.toBeNull();
    expect(await env.CERTS.get(`${issued.r2Prefix}/fullchain.pem`)).not.toBeNull();
    const encryptedKey = await (await env.CERTS.get(`${issued.r2Prefix}/privkey.pem.enc`))?.text();
    expect(encryptedKey ?? "").not.toContain("BEGIN PRIVATE KEY");
    expect(await env.CERTS.get("acme/staging/account.json")).not.toBeNull();
    expect(await env.CERTS.get("acme/staging/account-key.pem.enc")).not.toBeNull();
    expect(purge).toEqual({ purged: true });
    expect(cleanup.deleted).toBe(2);
    expect(dns.records).toHaveLength(0);
    expect(await listPendingChallengeRecords(env.DB, runId)).toEqual([]);
    expect(await getIssueRun(env.DB, runId)).toMatchObject({ status: "succeeded" });
    expect(requests.some(({ url }) => url.origin === "https://dns.google")).toBe(true);
  });

  it("preserves an invalid authorization problem and cleans published TXT records", async () => {
    const domain = await seedDomain(env.DB, { includeWildcard: false });
    const { runId } = await seedIssueRun(env.DB, domain.id);
    const { deps, dns } = makeDependencies({ invalidAuthorization: true });
    const loaded = await loadIssue(deps, runId, domain.id);
    const account = await ensureAcmeAccount(deps);
    const order = await createOrder(deps, account, loaded.identifiers);
    const published = await publishTxtChallenges(deps, runId, loaded.domain, account, order.authorizations);
    await waitForPropagation(deps, published);
    await acceptChallenges(deps, account, published);

    let failure: unknown;
    try {
      await awaitAuthorizations(deps, account, published);
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(Error);
    const error = issueErrorMessage(failure);
    expect(error).toContain('"type":"urn:ietf:params:acme:error:unauthorized"');
    expect(error).toContain("mock authorization rejected");

    await cleanupTxtRecords(deps, runId);
    await finishIssueRun(env.DB, runId, domain.id, { status: "failed", error });

    expect((await getIssueRun(env.DB, runId))?.error).toBe(error);
    expect(await getCurrentCertificate(env.DB, domain.id)).toBeNull();
    expect(dns.records).toHaveLength(0);
    expect(await listPendingChallengeRecords(env.DB, runId)).toEqual([]);
  });
});

function makeDependencies(options: MockAcmeOptions): {
  deps: ReturnType<typeof createIssueDependencies>;
  dns: MockCloudflareDns;
  requests: ReturnType<typeof createScriptedFetch>["requests"];
} {
  const acme = new MockAcme(options);
  const dns = new MockCloudflareDns();
  const scripted = createScriptedFetch(async (request) => {
    const acmeResponse = await acme.handle(request);
    if (acmeResponse) return acmeResponse;
    const dnsResponse = await dns.handle(request);
    if (dnsResponse) return dnsResponse;
    throw new Error(`No offline mock for ${request.request.method} ${request.url.href}`);
  });
  return {
    deps: createIssueDependencies(env, {
      fetcher: scripted.fetch,
      timings: {
        dnsTimeoutMs: 1_000,
        dnsPollIntervalMs: 1,
        dnsSettleMs: 0,
        dnsRequestTimeoutMs: 100,
        acmeTimeoutMs: 1_000,
        acmePollIntervalMs: 1,
        acmeRequestTimeoutMs: 1_000,
      },
    }),
    dns,
    requests: scripted.requests,
  };
}

function previousCertificate(domainId: string, id: string, prefix: string): CertificateRow {
  const now = new Date().toISOString();
  return {
    id,
    domain_id: domainId,
    env: "staging",
    serial: "old-serial",
    fingerprint_sha256: "a".repeat(64),
    sans_json: '["example.com"]',
    not_before: now,
    not_after: new Date(Date.now() + 30 * 24 * 60 * 60_000).toISOString(),
    issued_at: now,
    r2_prefix: prefix,
    status: "current",
    purged_at: null,
    created_at: now,
  };
}
