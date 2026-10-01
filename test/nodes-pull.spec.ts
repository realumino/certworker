import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { handlePullApi } from "../src/nodes/router";
import { certificatePrivateKeyKey } from "../src/store/r2";
import { getApiKey, listPullEvents } from "../src/store/d1";
import { readJson } from "./support/fake-fetch";
import { seedApiKey, seedCertificate } from "./support/admin";
import { seedDomain } from "./support/fixtures";
import { bearerToken, collectingContext, pullRequest, stubLimiter } from "./support/nodes";

const SECRET = "a".repeat(43);

async function pull(path: string, token?: string, init: RequestInit = {}) {
  const { ctx, settled, promises } = collectingContext();
  const response = await handlePullApi(pullRequest(path, token, init), env, ctx, {
    limiter: stubLimiter(),
  });
  await settled();
  return { response, promises };
}

async function seedDomainWithCert(options: { name?: string; status?: "active" | "paused" } = {}) {
  const domain = await seedDomain(env.DB, { name: options.name, status: options.status });
  const certificate = await seedCertificate(env.DB, env.CERTS, domain.id, env.ENVELOPE_KEY, {
    domainName: domain.name,
  });
  return { domain, certificate };
}

describe("GET /v1/me", () => {
  it("reports the key with its scope", async () => {
    const key = await seedApiKey(env.DB, { label: "node-a", secret: SECRET, allowedDomains: ["example.com"] });
    const { response } = await pull("/v1/me", bearerToken(key.id, SECRET));
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    await expect(readJson(response)).resolves.toEqual({
      id: key.id,
      label: "node-a",
      allowed_domains: ["example.com"],
    });
  });

  it("reports an unrestricted key as null allowed_domains", async () => {
    const key = await seedApiKey(env.DB, { label: "node-b", secret: SECRET });
    const { response } = await pull("/v1/me", bearerToken(key.id, SECRET));
    await expect(readJson(response)).resolves.toMatchObject({ allowed_domains: null });
  });
});

describe("GET /v1/domains", () => {
  it("lists scoped domains with current certificate metadata, without PEMs", async () => {
    const { domain, certificate } = await seedDomainWithCert({ name: "one.example.com" });
    const other = await seedDomain(env.DB, { name: "two.example.com" });
    await seedCertificate(env.DB, env.CERTS, other.id, env.ENVELOPE_KEY, { domainName: other.name });
    await seedDomain(env.DB, { name: "gone.example.com", status: "deleted" });

    const key = await seedApiKey(env.DB, { secret: SECRET });
    const { response } = await pull("/v1/domains", bearerToken(key.id, SECRET));
    expect(response.status).toBe(200);
    const body = await readJson<{ domains: Array<Record<string, unknown>> }>(response);
    expect(body.domains).toHaveLength(2);
    expect(body.domains[0]).toEqual({
      name: domain.name,
      status: "active",
      certificate: {
        id: certificate.id,
        serial: certificate.serial,
        fingerprint_sha256: certificate.fingerprint_sha256,
        sans: JSON.parse(certificate.sans_json),
        not_before: certificate.not_before,
        not_after: certificate.not_after,
        etag: `"${certificate.serial}-${certificate.fingerprint_sha256}"`,
      },
    });
    expect(JSON.stringify(body)).not.toContain("PEM");
  });

  it("excludes out-of-scope domains and reports certificate-less rows", async () => {
    const inScope = await seedDomain(env.DB, { name: "mine.example.com" });
    await seedDomain(env.DB, { name: "theirs.example.com" });
    const key = await seedApiKey(env.DB, { secret: SECRET, allowedDomains: ["mine.example.com"] });

    const { response } = await pull("/v1/domains", bearerToken(key.id, SECRET));
    const body = await readJson<{ domains: Array<Record<string, unknown>> }>(response);
    expect(body.domains).toHaveLength(1);
    expect(body.domains[0]).toMatchObject({ name: inScope.name, certificate: null });
  });
});

describe("GET /v1/domains/:name/cert", () => {
  it("returns the manifest with the decrypted private key", async () => {
    const { domain, certificate } = await seedDomainWithCert({ name: "pull.example.com" });
    const key = await seedApiKey(env.DB, { secret: SECRET });

    const { response } = await pull(`/v1/domains/${domain.name}/cert`, bearerToken(key.id, SECRET));
    expect(response.status).toBe(200);
    expect(response.headers.get("etag"))
      .toBe(`"${certificate.serial}-${certificate.fingerprint_sha256}"`);
    const body = await readJson<Record<string, unknown>>(response);
    expect(body).toMatchObject({
      domain: domain.name,
      serial: certificate.serial,
      fullchain_pem: `FULLCHAIN PEM for ${certificate.id}\n`,
      private_key_pem: `PRIVATE KEY for ${certificate.id}\n`,
    });
  });

  it("answers a repeat with If-None-Match from metadata alone (304, no decrypt)", async () => {
    const { domain, certificate } = await seedDomainWithCert({ name: "etag.example.com" });
    const key = await seedApiKey(env.DB, { secret: SECRET });
    const token = bearerToken(key.id, SECRET);
    const etag = `"${certificate.serial}-${certificate.fingerprint_sha256}"`;

    // Remove the R2 artifacts: a 304 must not depend on R2 reads or decryption.
    await env.CERTS.delete(`${certificate.r2_prefix}/cert.pem`);
    await env.CERTS.delete(`${certificate.r2_prefix}/chain.pem`);
    await env.CERTS.delete(`${certificate.r2_prefix}/fullchain.pem`);
    await env.CERTS.delete(certificatePrivateKeyKey(certificate.r2_prefix));

    const conditional = await pull(`/v1/domains/${domain.name}/cert`, token, { headers: { "If-None-Match": etag } });
    expect(conditional.response.status).toBe(304);
    expect(conditional.response.headers.get("etag")).toBe(etag);
    expect(await conditional.response.text()).toBe("");

    const unconditional = await pull(`/v1/domains/${domain.name}/cert`, token);
    expect(unconditional.response.status).toBe(404);
    await expect(readJson(unconditional.response)).resolves.toMatchObject({ error: "certificate_artifacts_missing" });
  });

  it("accepts weak validators, unquoted etags, lists, and *", async () => {
    const { domain, certificate } = await seedDomainWithCert({ name: "weak.example.com" });
    const key = await seedApiKey(env.DB, { secret: SECRET });
    const token = bearerToken(key.id, SECRET);
    const etag = `"${certificate.serial}-${certificate.fingerprint_sha256}"`;
    const bare = etag.replaceAll("\"", "");

    for (const header of [etag, `W/${etag}`, bare, `W/${bare}, ${etag}`, "*"]) {
      const { response } = await pull(`/v1/domains/${domain.name}/cert`, token, { headers: { "If-None-Match": header } });
      expect(response.status).toBe(304);
    }
    const different = await pull(`/v1/domains/${domain.name}/cert`, token, {
      headers: { "If-None-Match": '"0000-ffff"' },
    });
    expect(different.response.status).toBe(200);
  });
});

describe("GET /v1/domains/:name/files/:file", () => {
  it("returns raw PEMs for cert, chain, fullchain, and key", async () => {
    const { domain, certificate } = await seedDomainWithCert({ name: "files.example.com" });
    const key = await seedApiKey(env.DB, { secret: SECRET });
    const token = bearerToken(key.id, SECRET);

    const fullchain = await pull(`/v1/domains/${domain.name}/files/fullchain`, token);
    expect(fullchain.response.status).toBe(200);
    expect(fullchain.response.headers.get("content-type")).toBe("application/x-pem-file");
    expect(await fullchain.response.text()).toBe(`FULLCHAIN PEM for ${certificate.id}\n`);

    const keyPem = await pull(`/v1/domains/${domain.name}/files/key`, token);
    expect(await keyPem.response.text()).toBe(`PRIVATE KEY for ${certificate.id}\n`);
  });

  it("rejects unknown files and answers 304 conditionally", async () => {
    const { domain, certificate } = await seedDomainWithCert({ name: "files2.example.com" });
    const key = await seedApiKey(env.DB, { secret: SECRET });
    const token = bearerToken(key.id, SECRET);

    const invalid = await pull(`/v1/domains/${domain.name}/files/bundle`, token);
    expect(invalid.response.status).toBe(400);

    const conditional = await pull(`/v1/domains/${domain.name}/files/cert`, token, {
      headers: { "If-None-Match": `"${certificate.serial}-${certificate.fingerprint_sha256}"` },
    });
    expect(conditional.response.status).toBe(304);
  });
});

describe("pull authorization and errors", () => {
  it("rejects missing, malformed, unknown, and revoked keys before anything else", async () => {
    const { domain } = await seedDomainWithCert({ name: "authz.example.com" });
    const key = await seedApiKey(env.DB, { secret: SECRET });

    expect((await pull(`/v1/domains/${domain.name}/cert`)).response.status).toBe(401);
    expect((await pull(`/v1/domains/${domain.name}/cert`, "garbage")).response.status).toBe(401);
    expect((await pull(`/v1/domains/${domain.name}/cert`, bearerToken(crypto.randomUUID(), SECRET))).response.status).toBe(401);

    await env.DB.prepare("UPDATE api_keys SET status = 'revoked', revoked_at = ? WHERE id = ?")
      .bind(new Date().toISOString(), key.id).run();
    expect((await pull(`/v1/domains/${domain.name}/cert`, bearerToken(key.id, SECRET))).response.status).toBe(401);
  });

  it("403s out-of-scope domains and 404s unknown or deleted ones", async () => {
    await seedDomainWithCert({ name: "scoped.example.com" });
    const deleted = await seedDomain(env.DB, { name: "deleted.example.com", status: "deleted" });
    const key = await seedApiKey(env.DB, { secret: SECRET, allowedDomains: ["other.example.com"] });
    const token = bearerToken(key.id, SECRET);

    const forbidden = await pull("/v1/domains/scoped.example.com/cert", token);
    expect(forbidden.response.status).toBe(403);
    await expect(readJson(forbidden.response)).resolves.toMatchObject({ error: "forbidden_domain" });

    const unknown = await pull("/v1/domains/unknown.example.com/cert", token);
    expect(unknown.response.status).toBe(404);

    const gone = await pull(`/v1/domains/${deleted.name}/cert`, token);
    expect(gone.response.status).toBe(404);

    const invalid = await pull("/v1/domains/bad_name!/cert", token);
    expect(invalid.response.status).toBe(400);
  });

  it("404s a domain with no current certificate", async () => {
    const domain = await seedDomain(env.DB, { name: "empty.example.com" });
    const key = await seedApiKey(env.DB, { secret: SECRET });
    const { response } = await pull(`/v1/domains/${domain.name}/cert`, bearerToken(key.id, SECRET));
    expect(response.status).toBe(404);
    await expect(readJson(response)).resolves.toMatchObject({ error: "certificate_missing" });
  });
});

describe("pull observability", () => {
  it("records pull events with status, ip, and user agent; updates last_used_at", async () => {
    const { domain, certificate } = await seedDomainWithCert({ name: "events.example.com" });
    const key = await seedApiKey(env.DB, { secret: SECRET });
    const token = bearerToken(key.id, SECRET);

    await pull(`/v1/domains/${domain.name}/cert`, token);
    let events = await listPullEvents(env.DB, { apiKeyId: key.id, limit: 10, offset: 0 });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      api_key_id: key.id,
      domain_id: domain.id,
      certificate_id: certificate.id,
      ip: "203.0.113.10",
      user_agent: "ssl-cert-pull/1.0",
      status: 200,
    });
    const firstUsedAt = (await getApiKey(env.DB, key.id))?.last_used_at;
    expect(firstUsedAt).not.toBeNull();

    // An immediate second pull is throttled: event logged, timestamp not bumped.
    await pull(`/v1/domains/${domain.name}/cert`, token);
    events = await listPullEvents(env.DB, { apiKeyId: key.id, limit: 10, offset: 0 });
    expect(events).toHaveLength(2);
    expect((await getApiKey(env.DB, key.id))?.last_used_at).toBe(firstUsedAt);
  });

  it("logs 200, 304, and 403 outcomes; 404-for-unknown-domain writes nothing", async () => {
    const { domain, certificate } = await seedDomainWithCert({ name: "statuses.example.com" });
    const key = await seedApiKey(env.DB, { secret: SECRET });
    const token = bearerToken(key.id, SECRET);
    const etag = `"${certificate.serial}-${certificate.fingerprint_sha256}"`;

    await pull(`/v1/domains/${domain.name}/cert`, token);
    await pull(`/v1/domains/${domain.name}/cert`, token, { headers: { "If-None-Match": etag } });

    const scoped = await seedApiKey(env.DB, { secret: SECRET, allowedDomains: ["other.example.com"] });
    await pull(`/v1/domains/${domain.name}/cert`, bearerToken(scoped.id, SECRET));

    const statuses = (await listPullEvents(env.DB, { domainId: domain.id, limit: 10, offset: 0 }))
      .map((row) => row.status).sort();
    expect(statuses).toEqual([200, 304, 403]);

    // Unknown domain writes nothing (no domain_id to attribute).
    await pull("/v1/domains/unknown.example.com/cert", token);
    expect(await listPullEvents(env.DB, { apiKeyId: key.id, limit: 10, offset: 0 })).toHaveLength(2);
  });
});

describe("rate limiting", () => {
  it("returns 429 when the limiter rejects the key", async () => {
    const key = await seedApiKey(env.DB, { secret: SECRET });
    const { ctx, settled } = collectingContext();
    const response = await handlePullApi(pullRequest("/v1/me", bearerToken(key.id, SECRET)), env, ctx, {
      limiter: stubLimiter(false),
    });
    await settled();
    expect(response.status).toBe(429);
    await expect(readJson(response)).resolves.toMatchObject({ error: "rate_limited" });
    expect(response.headers.get("retry-after")).toBe("60");
  });

  it("charges the limiter to the authenticated key", async () => {
    const key = await seedApiKey(env.DB, { secret: SECRET });
    const { ctx, settled } = collectingContext();
    const limiter = stubLimiter();
    await handlePullApi(pullRequest("/v1/me", bearerToken(key.id, SECRET)), env, ctx, { limiter });
    await settled();
    expect(limiter.limit).toHaveBeenCalledWith({ key: `pull:${key.id}` });
  });
});
