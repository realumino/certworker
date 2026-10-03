import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { createAdminDependencies, type AdminDependencies } from "../src/admin/deps";
import {
  downloadCertificateHandler,
  getCertificateHandler,
  listCertificatesHandler,
  revokeCertificateHandler,
} from "../src/admin/certificates";
import { createIssueDependencies, ensureAcmeAccount } from "../src/issue/steps";
import { listAuditLog } from "../src/store/d1";
import { seedCertificate } from "./support/admin";
import { createScriptedFetch, readJson } from "./support/fake-fetch";
import { MockAcme, createSelfSignedCertificatePem } from "./support/mock-acme";
import { seedDomain } from "./support/fixtures";

const makeDeps = (fetcher?: typeof fetch): AdminDependencies =>
  createAdminDependencies(env, "admin@example.com", fetcher ? { fetcher } : {});

describe("admin certificates — list and detail", () => {
  it("lists certificates with domain names and filters", async () => {
    const domain = await seedDomain(env.DB);
    const current = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, { domainName: domain.name });
    const superseded = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
      status: "superseded",
    });
    const otherDomain = await seedDomain(env.DB, { name: "other.example.com" });
    await seedCertificate(env.DB, env.CERTS, otherDomain.id, env.ENVELOPE_KEY, { domainName: otherDomain.name });

    const response = await listCertificatesHandler(makeDeps(), new Request("https://certworker.example.org/api/certificates"));
    expect(response.status).toBe(200);
    const body = await readJson<Array<Record<string, unknown>>>(response);
    expect(body).toHaveLength(3);
    expect(body.find((row) => row.id === current.id)).toMatchObject({
      domain_name: domain.name,
      env: "staging",
      status: "current",
      sans: ["example.com", "*.example.com"],
      purged_at: null,
    });

    const byStatus = await listCertificatesHandler(
      makeDeps(),
      new Request("https://certworker.example.org/api/certificates?status=superseded"),
    );
    const byStatusBody = await readJson<Array<Record<string, unknown>>>(byStatus);
    expect(byStatusBody).toHaveLength(1);
    expect(byStatusBody[0].id).toBe(superseded.id);

    const byDomain = await listCertificatesHandler(
      makeDeps(),
      new Request(`https://certworker.example.org/api/certificates?domain_id=${domain.id}`),
    );
    expect(await byDomain.json()).toHaveLength(2);
  });

  it("rejects an invalid status filter", async () => {
    const response = await listCertificatesHandler(
      makeDeps(),
      new Request("https://certworker.example.org/api/certificates?status=bogus"),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_status" });
  });

  it("returns detail or 404", async () => {
    const domain = await seedDomain(env.DB);
    const cert = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, { domainName: domain.name });
    const deps = makeDeps();

    const found = await getCertificateHandler(deps, new Request("https://certworker.example.org/api/certificates/x"), { id: cert.id });
    expect(found.status).toBe(200);
    expect(await found.json()).toMatchObject({ id: cert.id, domain_name: domain.name });

    const missing = await getCertificateHandler(deps, new Request("https://certworker.example.org/api/certificates/x"), { id: crypto.randomUUID() });
    expect(missing.status).toBe(404);
    expect(await missing.json()).toMatchObject({ error: "not_found" });
  });
});

describe("admin certificates — download", () => {
  it("returns PEM artifacts verbatim with download headers", async () => {
    const domain = await seedDomain(env.DB);
    const cert = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, { domainName: domain.name });
    const deps = makeDeps();

    const expected: Record<string, string> = {
      cert: `LEAF PEM for ${cert.id}\n`,
      chain: `CHAIN PEM for ${cert.id}\n`,
      fullchain: `FULLCHAIN PEM for ${cert.id}\n`,
    };
    for (const [file, pem] of Object.entries(expected)) {
      const response = await downloadCertificateHandler(
        deps,
        new Request(`https://certworker.example.org/api/certificates/${cert.id}/download?file=${file}`),
        { id: cert.id },
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toContain("application/x-pem-file");
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("content-disposition")).toContain(`${domain.name}-${file}.pem`);
      expect(await response.text()).toBe(pem);
    }
  });

  it("decrypts the private key with the envelope key", async () => {
    const domain = await seedDomain(env.DB);
    const cert = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
      privateKeyPem: "-----BEGIN PRIVATE KEY-----\ntest-key\n-----END PRIVATE KEY-----\n",
    });

    const response = await downloadCertificateHandler(
      makeDeps(),
      new Request(`https://certworker.example.org/api/certificates/${cert.id}/download?file=key`),
      { id: cert.id },
    );
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("-----BEGIN PRIVATE KEY-----\ntest-key\n-----END PRIVATE KEY-----\n");
    expect(response.headers.get("content-disposition")).toContain("privkey.pem");
  });

  it("builds a combined bundle of fullchain and private key", async () => {
    const domain = await seedDomain(env.DB);
    const cert = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, { domainName: domain.name });

    const response = await downloadCertificateHandler(
      makeDeps(),
      new Request(`https://certworker.example.org/api/certificates/${cert.id}/download?file=bundle`),
      { id: cert.id },
    );
    expect(response.status).toBe(200);
    expect(await response.text()).toBe(`FULLCHAIN PEM for ${cert.id}\nPRIVATE KEY for ${cert.id}\n`);
    expect(response.headers.get("content-disposition")).toContain("bundle.pem");
  });

  it("uses a wildcard-safe filename", async () => {
    const domain = await seedDomain(env.DB, { name: "*.wild.example.com" });
    const cert = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, { domainName: domain.name });

    const response = await downloadCertificateHandler(
      makeDeps(),
      new Request(`https://certworker.example.org/api/certificates/${cert.id}/download?file=key`),
      { id: cert.id },
    );
    expect(response.headers.get("content-disposition")).toContain("wildcard.wild.example.com-privkey.pem");
  });

  it("answers 400 for an unknown file and 404 for missing or purged artifacts", async () => {
    const deps = makeDeps();
    const domain = await seedDomain(env.DB);

    const badFile = await downloadCertificateHandler(
      deps,
      new Request(`https://certworker.example.org/api/certificates/x/download?file=weird`),
      { id: crypto.randomUUID() },
    );
    expect(badFile.status).toBe(400);
    expect(await badFile.json()).toMatchObject({ error: "invalid_file" });

    const missingId = await downloadCertificateHandler(
      deps,
      new Request(`https://certworker.example.org/api/certificates/${crypto.randomUUID()}/download?file=fullchain`),
      { id: crypto.randomUUID() },
    );
    expect(missingId.status).toBe(404);

    const noArtifacts = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
      storeArtifacts: false,
    });
    const missingObject = await downloadCertificateHandler(
      deps,
      new Request(`https://certworker.example.org/api/certificates/${noArtifacts.id}/download?file=cert`),
      { id: noArtifacts.id },
    );
    expect(missingObject.status).toBe(404);
    expect(await missingObject.json()).toMatchObject({ error: "certificate_artifacts_missing" });

    const purged = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
      status: "superseded",
      purgedAt: new Date().toISOString(),
    });
    const purgedResponse = await downloadCertificateHandler(
      deps,
      new Request(`https://certworker.example.org/api/certificates/${purged.id}/download?file=fullchain`),
      { id: purged.id },
    );
    expect(purgedResponse.status).toBe(404);
    expect(await purgedResponse.json()).toMatchObject({ error: "certificate_artifacts_missing" });
  });
});

describe("admin certificates — revoke", () => {
  function acmeFetch() {
    const acme = new MockAcme();
    const { fetch, requests } = createScriptedFetch(async (request) => {
      const response = await acme.handle(request);
      if (response) return response;
      throw new Error(`No offline mock for ${request.request.method} ${request.url.href}`);
    });
    return { acme, fetch, requests };
  }

  async function ensureAccount(fetcher: typeof fetch): Promise<void> {
    await ensureAcmeAccount(createIssueDependencies(env, { fetcher }));
  }

  function revokeRequest(id: string): Request {
    return new Request(`https://certworker.example.org/api/certificates/${id}/revoke`, {
      method: "POST",
      headers: {
        "Origin": "https://certworker.example.org",
        "Sec-Fetch-Site": "same-origin",
        "Content-Type": "application/json",
      },
    });
  }

  async function seedRevocableCertificate(name: string) {
    const domain = await seedDomain(env.DB, { name });
    const certPem = await createSelfSignedCertificatePem(domain.name);
    const certificate = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
      certPem,
    });
    return { domain, certPem, certificate };
  }

  it("revokes at the CA, purges R2, flips D1, and audits", async () => {
    const { acme, fetch } = acmeFetch();
    await ensureAccount(fetch);
    const { domain, certificate } = await seedRevocableCertificate("revoke-admin.example.com");

    const response = await revokeCertificateHandler(makeDeps(fetch), revokeRequest(certificate.id), { id: certificate.id });
    expect(response.status).toBe(200);
    const body = await readJson<{ certificate: Record<string, unknown>; status: string; purged: boolean }>(response);
    expect(body).toMatchObject({ status: "revoked", purged: true });
    expect(body.certificate).toMatchObject({ id: certificate.id, status: "revoked", purged_at: expect.any(String) });

    expect(acme.revokedCertificates).toHaveLength(1);
    expect((await env.CERTS.list({ prefix: `${certificate.r2_prefix}/` })).objects).toHaveLength(0);
    await expect(
      getCertificateHandler(
        makeDeps(),
        new Request("https://certworker.example.org/api/certificates/x"),
        { id: certificate.id },
      ),
    ).resolves.toMatchObject({ status: 200 });

    const audits = (await listAuditLog(env.DB, { limit: 50, offset: 0 })).filter(
      ({ action }) => action === "certificate.revoke",
    );
    expect(audits).toHaveLength(1);
    expect(JSON.parse(audits[0].meta_json ?? "{}")).toMatchObject({
      domain_id: domain.id,
      serial: certificate.serial,
      ca_status: "revoked",
      purged: true,
    });
  });

  it("is idempotent: a repeat call skips the CA and still answers 200", async () => {
    const { acme, fetch } = acmeFetch();
    await ensureAccount(fetch);
    const { certificate } = await seedRevocableCertificate("revoke-twice.example.com");

    const first = await revokeCertificateHandler(makeDeps(fetch), revokeRequest(certificate.id), { id: certificate.id });
    expect(first.status).toBe(200);
    const second = await revokeCertificateHandler(makeDeps(fetch), revokeRequest(certificate.id), { id: certificate.id });
    expect(second.status).toBe(200);
    expect(await second.json()).toMatchObject({ status: "already_revoked", purged: true });
    expect(acme.revokedCertificates).toHaveLength(1);
  });

  it("answers 502 with the LE error payload and leaves the row untouched on CA failure", async () => {
    const acme = new MockAcme({ revokeFails: true });
    const { fetch } = createScriptedFetch(async (request) => {
      const response = await acme.handle(request);
      if (response) return response;
      throw new Error(`No offline mock for ${request.request.method} ${request.url.href}`);
    });
    await ensureAccount(fetch);
    const { certificate } = await seedRevocableCertificate("revoke-fail.example.com");

    const response = await revokeCertificateHandler(makeDeps(fetch), revokeRequest(certificate.id), { id: certificate.id });
    expect(response.status).toBe(502);
    expect(await response.json()).toMatchObject({ error: "upstream_error", message: expect.stringContaining("mock revocation rejected") });
    await expect(env.DB.prepare("SELECT status, purged_at FROM certificates WHERE id = ?").bind(certificate.id).first())
      .resolves.toMatchObject({ status: "current", purged_at: null });
    expect((await env.CERTS.list({ prefix: `${certificate.r2_prefix}/` })).objects).toHaveLength(4);
    expect(acme.revokedCertificates).toHaveLength(0);
  });

  it("answers 409 when the stored PEMs are gone", async () => {
    const { acme, fetch } = acmeFetch();
    await ensureAccount(fetch);
    const domain = await seedDomain(env.DB, { name: "revoke-gone.example.com" });
    const certificate = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
      storeArtifacts: false,
    });

    const response = await revokeCertificateHandler(makeDeps(fetch), revokeRequest(certificate.id), { id: certificate.id });
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ error: "certificate_artifacts_missing" });
    expect(acme.revokedCertificates).toHaveLength(0);
  });

  it("answers 404 for an unknown certificate", async () => {
    const response = await revokeCertificateHandler(
      makeDeps(),
      revokeRequest(crypto.randomUUID()),
      { id: crypto.randomUUID() },
    );
    expect(response.status).toBe(404);
    expect(await response.json()).toMatchObject({ error: "not_found" });
  });
});
