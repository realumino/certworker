import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { createAdminDependencies, type AdminDependencies } from "../src/admin/deps";
import { downloadCertificateHandler, getCertificateHandler, listCertificatesHandler } from "../src/admin/certificates";
import { seedCertificate } from "./support/admin";
import { readJson } from "./support/fake-fetch";
import { seedDomain } from "./support/fixtures";

const makeDeps = (): AdminDependencies => createAdminDependencies(env, "admin@example.com");

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

    const response = await listCertificatesHandler(makeDeps(), new Request("https://ssl.example.com/api/certificates"));
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
      new Request("https://ssl.example.com/api/certificates?status=superseded"),
    );
    const byStatusBody = await readJson<Array<Record<string, unknown>>>(byStatus);
    expect(byStatusBody).toHaveLength(1);
    expect(byStatusBody[0].id).toBe(superseded.id);

    const byDomain = await listCertificatesHandler(
      makeDeps(),
      new Request(`https://ssl.example.com/api/certificates?domain_id=${domain.id}`),
    );
    expect(await byDomain.json()).toHaveLength(2);
  });

  it("rejects an invalid status filter", async () => {
    const response = await listCertificatesHandler(
      makeDeps(),
      new Request("https://ssl.example.com/api/certificates?status=bogus"),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_status" });
  });

  it("returns detail or 404", async () => {
    const domain = await seedDomain(env.DB);
    const cert = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, { domainName: domain.name });
    const deps = makeDeps();

    const found = await getCertificateHandler(deps, new Request("https://ssl.example.com/api/certificates/x"), { id: cert.id });
    expect(found.status).toBe(200);
    expect(await found.json()).toMatchObject({ id: cert.id, domain_name: domain.name });

    const missing = await getCertificateHandler(deps, new Request("https://ssl.example.com/api/certificates/x"), { id: crypto.randomUUID() });
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
        new Request(`https://ssl.example.com/api/certificates/${cert.id}/download?file=${file}`),
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
      new Request(`https://ssl.example.com/api/certificates/${cert.id}/download?file=key`),
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
      new Request(`https://ssl.example.com/api/certificates/${cert.id}/download?file=bundle`),
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
      new Request(`https://ssl.example.com/api/certificates/${cert.id}/download?file=key`),
      { id: cert.id },
    );
    expect(response.headers.get("content-disposition")).toContain("wildcard.wild.example.com-privkey.pem");
  });

  it("answers 400 for an unknown file and 404 for missing or purged artifacts", async () => {
    const deps = makeDeps();
    const domain = await seedDomain(env.DB);

    const badFile = await downloadCertificateHandler(
      deps,
      new Request(`https://ssl.example.com/api/certificates/x/download?file=weird`),
      { id: crypto.randomUUID() },
    );
    expect(badFile.status).toBe(400);
    expect(await badFile.json()).toMatchObject({ error: "invalid_file" });

    const missingId = await downloadCertificateHandler(
      deps,
      new Request(`https://ssl.example.com/api/certificates/${crypto.randomUUID()}/download?file=fullchain`),
      { id: crypto.randomUUID() },
    );
    expect(missingId.status).toBe(404);

    const noArtifacts = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
      domainName: domain.name,
      storeArtifacts: false,
    });
    const missingObject = await downloadCertificateHandler(
      deps,
      new Request(`https://ssl.example.com/api/certificates/${noArtifacts.id}/download?file=cert`),
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
      new Request(`https://ssl.example.com/api/certificates/${purged.id}/download?file=fullchain`),
      { id: purged.id },
    );
    expect(purgedResponse.status).toBe(404);
    expect(await purgedResponse.json()).toMatchObject({ error: "certificate_artifacts_missing" });
  });
});
