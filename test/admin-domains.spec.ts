import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { createAdminDependencies, type AdminDependencies } from "../src/admin/deps";
import {
  createDomainHandler,
  deleteDomainHandler,
  getDomainHandler,
  issueDomainHandler,
  listDomainsHandler,
  listZonesHandler,
  updateDomainHandler,
} from "../src/admin/domains";
import { getDomain, getIssueRun, listAuditLog } from "../src/store/d1";
import { createIssueDependencies, ensureAcmeAccount } from "../src/issue/steps";
import { createScriptedFetch, jsonResponse, readJson, type CapturedRequest } from "./support/fake-fetch";
import { MockAcme, createSelfSignedCertificatePem, type MockAcmeOptions } from "./support/mock-acme";
import { seedCertificate } from "./support/admin";
import { seedDomain, seedIssueRun } from "./support/fixtures";
import type { IssuePayload } from "../src/issue/types";

const ACTOR = "admin@example.com";

function makeDeps(fetcher?: typeof fetch, issuance?: unknown): AdminDependencies {
  return createAdminDependencies(env, ACTOR, {
    fetcher,
    ...(issuance ? { issuance: issuance as AdminDependencies["issuance"] } : {}),
  });
}

function zoneApi(zones: Array<{ id: string; name: string; status?: string }>): {
  fetch: typeof fetch;
  requests: CapturedRequest[];
} {
  return createScriptedFetch(({ url, request }) => {
    if (url.pathname === "/client/v4/zones" && request.method === "GET") {
      const name = url.searchParams.get("name");
      const result = name === null ? zones : zones.filter((zone) => zone.name.toLowerCase() === name.toLowerCase());
      return jsonResponse({ success: true, result });
    }
    const byId = url.pathname.match(/^\/client\/v4\/zones\/([^/]+)$/);
    if (byId && request.method === "GET") {
      const zone = zones.find((entry) => entry.id === byId[1]);
      if (!zone) return jsonResponse({ success: false, errors: [{ message: "not found" }] }, { status: 404 });
      return jsonResponse({ success: true, result: zone });
    }
    return jsonResponse({ success: false, errors: [{ message: "unexpected request" }] }, { status: 500 });
  });
}

function jsonRequest(path: string, body: unknown, method = "POST"): Request {
  return new Request(`https://ssl.example.com${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** D1 state persists across tests within a file; unique names keep tests independent. */
function uniqueBase(): string {
  return `d${crypto.randomUUID().slice(0, 8)}.example.com`;
}

describe("admin domains — create", () => {
  it("creates a domain and resolves the zone from the DNS token", async () => {
    const base = uniqueBase();
    const { fetch, requests } = zoneApi([{ id: "zone-1", name: "example.com", status: "active" }]);
    const deps = makeDeps(fetch);

    const response = await createDomainHandler(deps, jsonRequest("/api/domains", { name: base.toUpperCase() }));

    expect(response.status).toBe(201);
    const body = await readJson<Record<string, unknown>>(response);
    expect(body).toMatchObject({
      name: base,
      zone_id: "zone-1",
      include_wildcard: true,
      status: "active",
      renew_before_days: 30,
      current_certificate: null,
    });
    expect(requests.some(({ url }) => url.searchParams.get("name") === base)).toBe(true);

    const audits = (await listAuditLog(env.DB, { limit: 50, offset: 0 })).filter((row) => row.target === body.id);
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({ actor: ACTOR, action: "domain.create" });
    expect(JSON.parse(audits[0].meta_json ?? "{}")).toEqual({
      name: base,
      zone_id: "zone-1",
      include_wildcard: true,
    });
  });

  it("forces include_wildcard off for wildcard-only input", async () => {
    const base = uniqueBase();
    const { fetch } = zoneApi([{ id: "zone-1", name: "example.com" }]);
    const response = await createDomainHandler(makeDeps(fetch), jsonRequest("/api/domains", { name: `*.${base}` }));
    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({ name: `*.${base}`, include_wildcard: false });
  });

  it("honors an explicit zone_id after validating it", async () => {
    const base = uniqueBase();
    const { fetch, requests } = zoneApi([{ id: "zone-1", name: "example.com" }]);
    const response = await createDomainHandler(
      makeDeps(fetch),
      jsonRequest("/api/domains", { name: `sub.${base}`, zone_id: "zone-1", include_wildcard: false }),
    );
    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({ name: `sub.${base}`, zone_id: "zone-1", include_wildcard: false });
    expect(requests.some(({ url }) => url.pathname === "/client/v4/zones/zone-1")).toBe(true);
  });

  it("rejects invalid DNS names", async () => {
    const { fetch } = zoneApi([]);
    const deps = makeDeps(fetch);
    for (const name of ["under_score.example.com", "203.0.113.10", "x.*", "*x.com", "*.*.example.com"]) {
      const response = await createDomainHandler(deps, jsonRequest("/api/domains", { name }));
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: "invalid_domain_name" });
    }
  });

  it("rejects names whose zone is unreachable with the DNS token", async () => {
    const { fetch } = zoneApi([{ id: "zone-1", name: "other.com" }]);
    const response = await createDomainHandler(makeDeps(fetch), jsonRequest("/api/domains", { name: uniqueBase() }));
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "zone_not_found" });
  });

  it("rejects a zone_id that does not contain the name", async () => {
    const { fetch } = zoneApi([{ id: "zone-1", name: "other.com" }]);
    const response = await createDomainHandler(
      makeDeps(fetch),
      jsonRequest("/api/domains", { name: uniqueBase(), zone_id: "zone-1" }),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "zone_mismatch" });
  });

  it("rejects unknown and malformed fields", async () => {
    const { fetch } = zoneApi([]);
    const deps = makeDeps(fetch);
    const unknown = await createDomainHandler(deps, jsonRequest("/api/domains", { name: "example.com", force: true }));
    expect(unknown.status).toBe(400);

    const badDays = await createDomainHandler(deps, jsonRequest("/api/domains", { name: "example.com", renew_before_days: 0 }));
    expect(badDays.status).toBe(400);

    const badWildcard = await createDomainHandler(deps, jsonRequest("/api/domains", { name: "example.com", include_wildcard: "yes" }));
    expect(badWildcard.status).toBe(400);
  });

  it("rejects duplicate names and wildcard overlaps", async () => {
    const base = uniqueBase();
    const { fetch } = zoneApi([{ id: "zone-1", name: "example.com" }]);
    const deps = makeDeps(fetch);
    await seedDomain(env.DB, { name: base });

    const duplicate = await createDomainHandler(deps, jsonRequest("/api/domains", { name: base, include_wildcard: false }));
    expect(duplicate.status).toBe(409);
    expect(await duplicate.json()).toMatchObject({ error: "domain_exists" });

    const overlap = await createDomainHandler(deps, jsonRequest("/api/domains", { name: `*.${base}` }));
    expect(overlap.status).toBe(409);
    expect(await overlap.json()).toMatchObject({ error: "wildcard_overlap" });
  });

  it("rejects enabling the wildcard when a wildcard-only row exists", async () => {
    const base = uniqueBase();
    const { fetch } = zoneApi([{ id: "zone-1", name: "example.com" }]);
    const deps = makeDeps(fetch);
    await seedDomain(env.DB, { name: `*.${base}` });

    const apexWithWildcard = await createDomainHandler(deps, jsonRequest("/api/domains", { name: base }));
    expect(apexWithWildcard.status).toBe(409);
    expect(await apexWithWildcard.json()).toMatchObject({ error: "wildcard_overlap" });

    const apexWithoutWildcard = await createDomainHandler(
      deps,
      jsonRequest("/api/domains", { name: base, include_wildcard: false }),
    );
    expect(apexWithoutWildcard.status).toBe(201);
  });
});

describe("admin domains — list, get, update, delete", () => {
  it("lists domains with their current certificate and hides deleted rows", async () => {
    const deps = makeDeps();
    const domain = await seedDomain(env.DB, { name: "one.example.com" });
    await seedDomain(env.DB, { name: "two.example.com", status: "paused" });
    const deleted = await seedDomain(env.DB, { name: "three.example.com", status: "deleted" });
    await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, { domainName: domain.name, sans: ["one.example.com"] });

    const response = await listDomainsHandler(deps, new Request("https://ssl.example.com/api/domains"));
    expect(response.status).toBe(200);
    const body = await readJson<Array<Record<string, unknown>>>(response);
    // Earlier tests in this file created other domains; this test owns exactly three rows.
    const names = body.map((row) => String(row.name));
    expect(names).toContain("one.example.com");
    expect(names).toContain("two.example.com");
    expect(names).not.toContain("three.example.com");

    const one = body.find((row) => row.name === "one.example.com");
    expect(one?.current_certificate).toMatchObject({
      serial: "0011aa22bb33cc44dd55ee66ff778899",
      sans: ["one.example.com"],
    });
    const two = body.find((row) => row.name === "two.example.com");
    expect(two?.current_certificate).toBeNull();

    const withDeleted = await listDomainsHandler(deps, new Request("https://ssl.example.com/api/domains?status=deleted"));
    const deletedNames = (await readJson<Array<Record<string, unknown>>>(withDeleted)).map((row) => String(row.name));
    expect(deletedNames).toContain(deleted.name);
  });

  it("returns a single domain or 404", async () => {
    const deps = makeDeps();
    const domain = await seedDomain(env.DB);
    const found = await getDomainHandler(deps, new Request("https://ssl.example.com/api/domains/x"), { id: domain.id });
    expect(found.status).toBe(200);
    expect(((await found.json()) as { id: string }).id).toBe(domain.id);

    const missing = await getDomainHandler(deps, new Request("https://ssl.example.com/api/domains/x"), { id: crypto.randomUUID() });
    expect(missing.status).toBe(404);
  });

  it("patches settings and audits the change", async () => {
    const deps = makeDeps();
    const domain = await seedDomain(env.DB);

    const response = await updateDomainHandler(
      deps,
      jsonRequest(`/api/domains/${domain.id}`, { renew_before_days: 45, status: "paused" }, "PATCH"),
      { id: domain.id },
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ renew_before_days: 45, status: "paused", include_wildcard: true });

    const audits = (await listAuditLog(env.DB, { limit: 50, offset: 0 })).filter((row) => row.target === domain.id);
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({ action: "domain.update" });
    expect(JSON.parse(audits[0].meta_json ?? "{}")).toEqual({
      changes: {
        renew_before_days: { from: 30, to: 45 },
        status: { from: "active", to: "paused" },
      },
    });
  });

  it("rejects invalid patches", async () => {
    const deps = makeDeps();
    const domain = await seedDomain(env.DB);
    const wildcardRow = await seedDomain(env.DB, { name: `*.${uniqueBase()}` });

    const empty = await updateDomainHandler(deps, jsonRequest(`/api/domains/${domain.id}`, {}, "PATCH"), { id: domain.id });
    expect(empty.status).toBe(400);

    const badStatus = await updateDomainHandler(deps, jsonRequest(`/api/domains/${domain.id}`, { status: "deleted" }, "PATCH"), { id: domain.id });
    expect(badStatus.status).toBe(400);
    expect(await badStatus.json()).toMatchObject({ error: "invalid_status" });

    const onWildcard = await updateDomainHandler(deps, jsonRequest(`/api/domains/${wildcardRow.id}`, { include_wildcard: true }, "PATCH"), { id: wildcardRow.id });
    expect(onWildcard.status).toBe(400);

    const missing = await updateDomainHandler(deps, jsonRequest(`/api/domains/${crypto.randomUUID()}`, { status: "paused" }, "PATCH"), { id: crypto.randomUUID() });
    expect(missing.status).toBe(404);
  });

  it("soft-deletes a domain, is idempotent, and audits once", async () => {
    const deps = makeDeps();
    const domain = await seedDomain(env.DB);

    const first = await deleteDomainHandler(deps, new Request("https://ssl.example.com/api/domains/x", { method: "DELETE" }), { id: domain.id });
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({ status: "deleted" });

    const second = await deleteDomainHandler(deps, new Request("https://ssl.example.com/api/domains/x", { method: "DELETE" }), { id: domain.id });
    expect(second.status).toBe(200);

    const audits = (await listAuditLog(env.DB, { limit: 50, offset: 0 })).filter((row) => row.target === domain.id);
    expect(audits.map(({ action }) => action)).toEqual(["domain.delete"]);
  });

  it("refuses to delete a domain with an active issue run", async () => {
    const deps = makeDeps();
    const domain = await seedDomain(env.DB);
    await seedIssueRun(env.DB, domain.id);

    const response = await deleteDomainHandler(deps, new Request("https://ssl.example.com/api/domains/x", { method: "DELETE" }), { id: domain.id });
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ error: "run_in_progress" });
  });
});

describe("admin domains — manual issue", () => {
  function fakeIssuance() {
    const created: Array<{ id: string; params: IssuePayload }> = [];
    return {
      created,
      issuance: {
        async create(options: { id: string; params: IssuePayload }): Promise<unknown> {
          created.push(options);
          return { id: options.id };
        },
      },
    };
  }

  it("starts a queued manual run and audits it", async () => {
    const { created, issuance } = fakeIssuance();
    const deps = makeDeps(undefined, issuance);
    const domain = await seedDomain(env.DB);

    const response = await issueDomainHandler(deps, new Request("https://ssl.example.com/api/domains/x/issue", { method: "POST" }), { id: domain.id });

    expect(response.status).toBe(202);
    const body = await readJson<{ run_id: string; workflow_id: string }>(response);
    expect(body.run_id).toBeTruthy();
    expect(body.workflow_id).toBe(`manual-${body.run_id}`);
    expect(created).toEqual([{ id: body.workflow_id, params: { runId: body.run_id, domainId: domain.id } }]);
    expect(await getIssueRun(env.DB, body.run_id)).toMatchObject({ status: "queued", trigger: "manual" });

    const audits = (await listAuditLog(env.DB, { limit: 50, offset: 0 })).filter((row) => row.target === domain.id);
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({ action: "domain.issue" });
    expect(JSON.parse(audits[0].meta_json ?? "{}")).toEqual({ run_id: body.run_id, workflow_id: body.workflow_id });
  });

  it("maps domain and run conflicts to API errors", async () => {
    const { issuance } = fakeIssuance();
    const deps = makeDeps(undefined, issuance);
    const paused = await seedDomain(env.DB, { status: "paused" });
    const pausedResponse = await issueDomainHandler(deps, new Request("https://ssl.example.com/x/issue", { method: "POST" }), { id: paused.id });
    expect(pausedResponse.status).toBe(409);
    expect(await pausedResponse.json()).toMatchObject({ error: "domain_not_active" });

    const active = await seedDomain(env.DB);
    await seedIssueRun(env.DB, active.id);
    const busy = await issueDomainHandler(deps, new Request("https://ssl.example.com/x/issue", { method: "POST" }), { id: active.id });
    expect(busy.status).toBe(409);
    expect(await busy.json()).toMatchObject({ error: "run_in_progress" });

    const missing = await issueDomainHandler(deps, new Request("https://ssl.example.com/x/issue", { method: "POST" }), { id: crypto.randomUUID() });
    expect(missing.status).toBe(404);
  });

  it("records the failed run when workflow creation fails", async () => {
    const issuance = {
      async create(): Promise<unknown> {
        throw new Error("workflow binding unavailable");
      },
    };
    const deps = makeDeps(undefined, issuance);
    const domain = await seedDomain(env.DB);

    const response = await issueDomainHandler(deps, new Request("https://ssl.example.com/x/issue", { method: "POST" }), { id: domain.id });
    expect(response.status).toBe(502);
    expect(await response.json()).toMatchObject({ error: "upstream_error" });

    const { results } = await env.DB.prepare("SELECT status, error FROM issue_runs WHERE domain_id = ?").bind(domain.id).all();
    expect(results[0]).toMatchObject({ status: "failed", error: "workflow binding unavailable" });
  });
});

describe("admin zones", () => {
  it("lists the zones visible to the DNS token", async () => {
    const { fetch } = zoneApi([
      { id: "zone-1", name: "example.com", status: "active" },
      { id: "zone-2", name: "example.org", status: "pending" },
    ]);
    const response = await listZonesHandler(makeDeps(fetch));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual([
      { id: "zone-1", name: "example.com", status: "active" },
      { id: "zone-2", name: "example.org", status: "pending" },
    ]);
  });

  it("maps Cloudflare API failures to upstream_error", async () => {
    const { fetch } = createScriptedFetch(() => jsonResponse({ success: false, errors: [{ message: "nope" }] }, { status: 403 }));
    const response = await listZonesHandler(makeDeps(fetch));
    expect(response.status).toBe(502);
    expect(await response.json()).toMatchObject({ error: "upstream_error" });
  });
});

describe("admin domains — delete with revocation (M7)", () => {
  function acmeFetch(options: MockAcmeOptions = {}) {
    const acme = new MockAcme(options);
    const { fetch } = createScriptedFetch(async (request) => {
      const response = await acme.handle(request);
      if (response) return response;
      throw new Error(`No offline mock for ${request.request.method} ${request.url.href}`);
    });
    return { acme, fetch };
  }

  async function ensureAccount(fetcher: typeof fetch): Promise<void> {
    await ensureAcmeAccount(createIssueDependencies(env, { fetcher }));
  }

  function deleteRequest(): Request {
    return new Request("https://ssl.example.com/api/domains/x", { method: "DELETE" });
  }

  async function certificateRows(domainId: string): Promise<Array<Record<string, unknown>>> {
    const { results } = await env.DB.prepare(
      "SELECT id, status, purged_at, r2_prefix FROM certificates WHERE domain_id = ?",
    ).bind(domainId).all();
    return results;
  }

  it("revokes the current certificate, purges its artifacts, then soft-deletes", async () => {
    const { acme, fetch } = acmeFetch();
    await ensureAccount(fetch);
    const domain = await seedDomain(env.DB, { name: "delete-revoke.example.com" });
    const certPem = await createSelfSignedCertificatePem(domain.name);
    const certificate = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
      certPem,
    });

    const response = await deleteDomainHandler(makeDeps(fetch), deleteRequest(), { id: domain.id });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ status: "deleted" });

    expect(acme.revokedCertificates).toHaveLength(1);
    const rows = await certificateRows(domain.id);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ status: "revoked", purged_at: expect.any(String) });
    expect((await env.CERTS.list({ prefix: `${certificate.r2_prefix}/` })).objects).toHaveLength(0);
    expect(await getDomain(env.DB, domain.id)).toMatchObject({ status: "deleted" });

    const audits = (await listAuditLog(env.DB, { limit: 50, offset: 0 })).filter((row) => row.target === domain.id);
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({ action: "domain.delete" });
    expect(JSON.parse(audits[0].meta_json ?? "{}")).toEqual({ name: domain.name, revoke: "revoked" });
  });

  it("fails the delete with 502 when revocation is rejected by the CA", async () => {
    const { fetch } = acmeFetch({ revokeFails: true });
    await ensureAccount(fetch);
    const domain = await seedDomain(env.DB, { name: "delete-blocked.example.com" });
    const certPem = await createSelfSignedCertificatePem(domain.name);
    const certificate = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
      certPem,
    });

    const response = await deleteDomainHandler(makeDeps(fetch), deleteRequest(), { id: domain.id });
    expect(response.status).toBe(502);
    expect(await response.json()).toMatchObject({
      error: "upstream_error",
      message: expect.stringContaining("mock revocation rejected"),
    });
    expect(await getDomain(env.DB, domain.id)).toMatchObject({ status: "active" });
    expect(await certificateRows(domain.id)).toMatchObject([{ status: "current", purged_at: null }]);
    expect((await env.CERTS.list({ prefix: `${certificate.r2_prefix}/` })).objects).toHaveLength(4);
  });

  it("records already_revoked when the CA answers that the certificate is revoked", async () => {
    const { acme, fetch } = acmeFetch({ alreadyRevoked: true });
    await ensureAccount(fetch);
    const domain = await seedDomain(env.DB, { name: "delete-already.example.com" });
    const certPem = await createSelfSignedCertificatePem(domain.name);
    const certificate = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
      certPem,
    });

    const response = await deleteDomainHandler(makeDeps(fetch), deleteRequest(), { id: domain.id });
    expect(response.status).toBe(200);
    expect(await getDomain(env.DB, domain.id)).toMatchObject({ status: "deleted" });
    // The mock counts only successful revocations; alreadyRevoked is not one.
    expect(acme.revokedCertificates).toHaveLength(0);
    const rows = await certificateRows(domain.id);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ status: "revoked", purged_at: expect.any(String) });
    expect((await env.CERTS.list({ prefix: `${certificate.r2_prefix}/` })).objects).toHaveLength(0);

    const audits = (await listAuditLog(env.DB, { limit: 50, offset: 0 })).filter((row) => row.target === domain.id);
    expect(JSON.parse(audits[0].meta_json ?? "{}")).toEqual({ name: domain.name, revoke: "already_revoked" });
  });

  it("deletes when revocation is impossible because artifacts are gone", async () => {
    const { acme, fetch } = acmeFetch();
    await ensureAccount(fetch);
    const domain = await seedDomain(env.DB, { name: "delete-gone.example.com" });
    await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
      storeArtifacts: false,
    });

    const response = await deleteDomainHandler(makeDeps(fetch), deleteRequest(), { id: domain.id });
    expect(response.status).toBe(200);
    expect(await getDomain(env.DB, domain.id)).toMatchObject({ status: "deleted" });
    expect(acme.revokedCertificates).toHaveLength(0);

    const audits = (await listAuditLog(env.DB, { limit: 50, offset: 0 })).filter((row) => row.target === domain.id);
    expect(JSON.parse(audits[0].meta_json ?? "{}")).toEqual({ name: domain.name, revoke: "artifacts_missing" });
  });
});
