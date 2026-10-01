import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { CertificateArtifactsMissingError, revokeStoredCertificate } from "../src/issue/revoke";
import { createIssueDependencies, ensureAcmeAccount, type IssueDependencies } from "../src/issue/steps";
import { getCertificate } from "../src/store/d1";
import { b64uDecode } from "../src/crypto/base64url";
import { pemToDer } from "../src/crypto/pem";
import { createScriptedFetch } from "./support/fake-fetch";
import { MockAcme, createSelfSignedCertificatePem, type MockAcmeOptions } from "./support/mock-acme";
import { seedCertificate } from "./support/admin";
import { seedDomain } from "./support/fixtures";

function makeSetup(options: MockAcmeOptions = {}): { acme: MockAcme; deps: IssueDependencies } {
  const acme = new MockAcme(options);
  const { fetch } = createScriptedFetch(async (request) => {
    const acmeResponse = await acme.handle(request);
    if (acmeResponse) return acmeResponse;
    throw new Error(`No offline mock for ${request.request.method} ${request.url.href}`);
  });
  const deps = createIssueDependencies(env, {
    fetcher: fetch,
    timings: { acmeRequestTimeoutMs: 1_000 },
  });
  return { acme, deps };
}

async function seedRevocableCertificate(name: string, options: { storeArtifacts?: boolean } = {}) {
  const domain = await seedDomain(env.DB, { name });
  const certPem = await createSelfSignedCertificatePem(domain.name);
  const certificate = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
    domainName: domain.name,
    certPem,
    ...options,
  });
  return { domain, certPem, certificate };
}

describe("certificate revocation core", () => {
  it("revokes at the CA with the account key, flips D1, and purges R2", async () => {
    const { acme, deps } = makeSetup();
    await ensureAcmeAccount(deps);
    const { certPem, certificate } = await seedRevocableCertificate("revoke.example.com");

    await expect(revokeStoredCertificate(deps, certificate)).resolves.toEqual({
      status: "revoked",
      purged: true,
    });

    expect(acme.revokedCertificates).toHaveLength(1);
    expect(b64uDecode(acme.revokedCertificates[0])).toEqual(pemToDer(certPem, "CERTIFICATE"));
    await expect(getCertificate(env.DB, certificate.id)).resolves.toMatchObject({
      status: "revoked",
      purged_at: expect.any(String),
    });
    expect((await env.CERTS.list({ prefix: `${certificate.r2_prefix}/` })).objects).toHaveLength(0);
  });

  it("treats an alreadyRevoked CA answer as success", async () => {
    const { acme, deps } = makeSetup({ alreadyRevoked: true });
    await ensureAcmeAccount(deps);
    const { certificate } = await seedRevocableCertificate("twice.example.com");

    await expect(revokeStoredCertificate(deps, certificate)).resolves.toEqual({
      status: "already_revoked",
      purged: true,
    });
    await expect(getCertificate(env.DB, certificate.id)).resolves.toMatchObject({
      status: "revoked",
      purged_at: expect.any(String),
    });
    expect((await env.CERTS.list({ prefix: `${certificate.r2_prefix}/` })).objects).toHaveLength(0);
  });

  it("leaves D1 and R2 untouched when the CA rejects the revocation", async () => {
    const { acme, deps } = makeSetup({ revokeFails: true });
    await ensureAcmeAccount(deps);
    const { certificate } = await seedRevocableCertificate("rejected.example.com");

    await expect(revokeStoredCertificate(deps, certificate)).rejects.toMatchObject({
      name: "AcmeError",
      detail: "mock revocation rejected",
    });
    await expect(getCertificate(env.DB, certificate.id)).resolves.toMatchObject({
      status: "current",
      purged_at: null,
    });
    expect((await env.CERTS.list({ prefix: `${certificate.r2_prefix}/` })).objects).toHaveLength(4);
    expect(acme.revokedCertificates).toHaveLength(0);
  });

  it("refuses to revoke without stored artifacts", async () => {
    const { acme, deps } = makeSetup();
    await ensureAcmeAccount(deps);
    const noArtifacts = await seedRevocableCertificate("vanished.example.com", { storeArtifacts: false });
    const purgedRow = await seedRevocableCertificate("purged.example.com", {
      storeArtifacts: false,
    });
    const purgedRowWithStamp = await seedCertificate(env.DB, env.CERTS, purgedRow.domain.id, env.ENVELOPE_KEY, {
      domainName: purgedRow.domain.name,
      status: "superseded",
      purgedAt: new Date().toISOString(),
      storeArtifacts: false,
    });

    for (const certificate of [noArtifacts.certificate, purgedRowWithStamp]) {
      await expect(revokeStoredCertificate(deps, certificate)).rejects.toBeInstanceOf(CertificateArtifactsMissingError);
    }
    expect(acme.revokedCertificates).toHaveLength(0);
  });

  it("re-revoking a revoked row skips the CA call and only re-runs the purge", async () => {
    const { acme, deps } = makeSetup();
    await ensureAcmeAccount(deps);
    const { certificate } = await seedRevocableCertificate("repeat.example.com");

    await expect(revokeStoredCertificate(deps, certificate)).resolves.toEqual({ status: "revoked", purged: true });
    const refreshed = await getCertificate(env.DB, certificate.id);
    await expect(revokeStoredCertificate(deps, refreshed!)).resolves.toEqual({
      status: "already_revoked",
      purged: true,
    });
    expect(acme.revokedCertificates).toHaveLength(1);
    expect((await env.CERTS.list({ prefix: `${certificate.r2_prefix}/` })).objects).toHaveLength(0);
  });
});
