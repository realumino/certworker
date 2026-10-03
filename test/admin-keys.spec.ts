import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { createAdminDependencies, type AdminDependencies } from "../src/admin/deps";
import {
  createKeyHandler,
  listKeysHandler,
  revokeKeyHandler,
  rotateKeyHandler,
  updateKeyHandler,
} from "../src/admin/keys";
import { sha256Hex } from "../src/crypto/keys";
import { getApiKey, listAuditLog } from "../src/store/d1";
import { seedDomain } from "./support/fixtures";
import { readJson } from "./support/fake-fetch";
import { seedApiKey } from "./support/admin";

const makeDeps = (): AdminDependencies => createAdminDependencies(env, "admin@example.com");

function jsonRequest(body: unknown, method = "POST"): Request {
  return new Request("https://certworker.example.org/api/keys", {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

function keyRequest(id: string, path: string, method = "POST", body?: unknown): Request {
  return new Request(`https://certworker.example.org/api/keys/${id}${path}`, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

describe("admin API keys — create", () => {
  it("stores only the secret hash and shows the token once", async () => {
    const response = await createKeyHandler(makeDeps(), jsonRequest({ label: "node-1" }));
    expect(response.status).toBe(201);

    const body = await readJson<{ token: string; key: Record<string, unknown> }>(response);
    const token = body.token;
    const withoutPrefix = token.replace(/^cw_/, "");
    const [id, secret] = withoutPrefix.split(".");
    expect(body.key).toMatchObject({ id, label: "node-1", status: "active", allowed_domains: null });
    expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const row = await getApiKey(env.DB, id);
    expect(row).not.toBeNull();
    expect(row?.key_hash).toBe(await sha256Hex(secret));
    expect(row?.key_hint).toBe(`cw_${id}…${secret.slice(-4)}`);
    expect(row?.allowed_domains_json).toBeNull();

    const listed = await listKeysHandler(makeDeps(), new Request("https://certworker.example.org/api/keys"));
    const listedBody = JSON.stringify(await listed.json());
    expect(listedBody).not.toContain(secret);
    expect(listedBody).not.toContain("key_hash");

    const audits = (await listAuditLog(env.DB, { limit: 50, offset: 0 })).filter((row) => row.target === id);
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({ actor: "admin@example.com", action: "key.create", target: id });
    expect(JSON.parse(audits[0].meta_json ?? "{}")).toEqual({ label: "node-1", allowed_domains: null });
  });

  it("stores a normalized, enumerated scope", async () => {
    const deps = makeDeps();
    await seedDomain(env.DB, { name: "example.com" });
    await seedDomain(env.DB, { name: "*.wild.example.com", status: "paused" });

    const response = await createKeyHandler(
      deps,
      jsonRequest({ label: "node-1", allowed_domains: ["Example.COM.", "*.WILD.example.com", "Example.COM"] }),
    );
    expect(response.status).toBe(201);
    await expect(readJson(response)).resolves.toMatchObject({
      key: { allowed_domains: ["*.wild.example.com", "example.com"] },
    });
  });

  it("stores a deny-all scope as an empty array", async () => {
    const response = await createKeyHandler(makeDeps(), jsonRequest({ label: "node-1", allowed_domains: [] }));
    expect(response.status).toBe(201);
    const body = await readJson<{ token: string; key: Record<string, unknown> }>(response);
    const [id] = body.token.replace(/^cw_/, "").split(".");
    expect(body.key).toMatchObject({ id, label: "node-1", allowed_domains: [] });

    expect(await getApiKey(env.DB, id)).toMatchObject({ allowed_domains_json: JSON.stringify([]) });
    const audits = (await listAuditLog(env.DB, { limit: 50, offset: 0 })).filter((row) => row.target === id);
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({ actor: "admin@example.com", action: "key.create", target: id });
    expect(JSON.parse(audits[0].meta_json ?? "{}")).toEqual({ label: "node-1", allowed_domains: [] });
  });

  it("rejects invalid, unknown, and deleted scope entries", async () => {
    const deps = makeDeps();
    await seedDomain(env.DB, { name: "reject.example.com" });
    await seedDomain(env.DB, { name: "*.wild.reject.example.com", status: "paused" });
    await seedDomain(env.DB, { name: "live.reject.example.com" });
    await seedDomain(env.DB, { name: "gone.reject.example.com", status: "deleted" });

    const cases: unknown[] = [
      { label: "k", allowed_domains: "reject.example.com" },
      { label: "k", allowed_domains: [123] },
      { label: "k", allowed_domains: [""] },
      { label: "k", allowed_domains: ["bad_name!"] },
      { label: "k", allowed_domains: ["unknown.example.com"] },
      { label: "k", allowed_domains: ["gone.reject.example.com"] },
    ];
    for (const body of cases) {
      const response = await createKeyHandler(deps, jsonRequest(body));
      expect(response.status, JSON.stringify(body)).toBe(400);
      expect(await response.json()).toMatchObject({ error: "invalid_request" });
    }

    const missingMessage = await createKeyHandler(
      deps,
      jsonRequest({ label: "k", allowed_domains: ["live.reject.example.com", "unknown.example.com"] }),
    );
    expect(await missingMessage.json()).toMatchObject({
      message: "Unknown or deleted domains: unknown.example.com",
    });
  });

  it("validates the label and rejects unknown fields", async () => {
    const deps = makeDeps();

    const missing = await createKeyHandler(deps, jsonRequest({}));
    expect(missing.status).toBe(400);

    const tooLong = await createKeyHandler(deps, jsonRequest({ label: "x".repeat(65) }));
    expect(tooLong.status).toBe(400);

    const controlChars = await createKeyHandler(deps, jsonRequest({ label: "node\u00001" }));
    expect(controlChars.status).toBe(400);

    const unknownField = await createKeyHandler(deps, jsonRequest({ label: "node-1", bogus: true }));
    expect(unknownField.status).toBe(400);
    expect(await unknownField.json()).toMatchObject({ error: "invalid_request" });
  });
});

describe("admin API keys — update scope", () => {
  it("replaces the scope in both directions and audits the change", async () => {
    const deps = makeDeps();
    const domain = await seedDomain(env.DB, { name: "scope.example.com" });
    const seeded = await seedApiKey(env.DB, { label: "node-1", allowedDomains: ["scope.example.com"] });

    const clear = await updateKeyHandler(deps, keyRequest(seeded.id, "", "PATCH", { allowed_domains: null }), { id: seeded.id });
    expect(clear.status).toBe(200);
    await expect(readJson(clear)).resolves.toMatchObject({ key: { id: seeded.id, allowed_domains: null } });
    expect(await getApiKey(env.DB, seeded.id)).toMatchObject({ allowed_domains_json: null });

    const scope = await updateKeyHandler(
      deps,
      keyRequest(seeded.id, "", "PATCH", { allowed_domains: ["Scope.example.com"] }),
      { id: seeded.id },
    );
    expect(scope.status).toBe(200);
    await expect(readJson(scope)).resolves.toMatchObject({ key: { allowed_domains: ["scope.example.com"] } });
    expect(await getApiKey(env.DB, seeded.id))
      .toMatchObject({ allowed_domains_json: JSON.stringify(["scope.example.com"]) });
    expect(domain.name).toBe("scope.example.com");

    const audits = (await listAuditLog(env.DB, { limit: 50, offset: 0 })).filter((row) => row.target === seeded.id);
    // One audit per PATCH: the clear, then the re-scope (newest first).
    expect(audits.map(({ action }) => action)).toEqual(["key.update", "key.update"]);
    expect(JSON.parse(audits[0].meta_json ?? "{}")).toEqual({ allowed_domains: ["scope.example.com"] });
    expect(JSON.parse(audits[1].meta_json ?? "{}")).toEqual({ allowed_domains: null });
  });

  it("denies all domains by patching an empty array", async () => {
    const deps = makeDeps();
    await seedDomain(env.DB, { name: "none.example.com" });
    const seeded = await seedApiKey(env.DB, { label: "node-1", allowedDomains: ["none.example.com"] });

    const denied = await updateKeyHandler(
      deps,
      keyRequest(seeded.id, "", "PATCH", { allowed_domains: [] }),
      { id: seeded.id },
    );
    expect(denied.status).toBe(200);
    await expect(readJson(denied)).resolves.toMatchObject({ key: { allowed_domains: [] } });
    expect(await getApiKey(env.DB, seeded.id))
      .toMatchObject({ allowed_domains_json: JSON.stringify([]) });

    const audits = (await listAuditLog(env.DB, { limit: 50, offset: 0 })).filter((row) => row.target === seeded.id);
    expect(audits[0]).toMatchObject({ action: "key.update", target: seeded.id });
    expect(JSON.parse(audits[0].meta_json ?? "{}")).toEqual({ allowed_domains: [] });

    // Restoring "all domains" flips the stored column back to NULL.
    const restored = await updateKeyHandler(
      deps,
      keyRequest(seeded.id, "", "PATCH", { allowed_domains: null }),
      { id: seeded.id },
    );
    expect(restored.status).toBe(200);
    expect(await getApiKey(env.DB, seeded.id)).toMatchObject({ allowed_domains_json: null });
  });

  it("answers 400 for a missing field and 404 for an unknown key", async () => {
    const deps = makeDeps();
    const seeded = await seedApiKey(env.DB, { label: "node-1" });

    const missing = await updateKeyHandler(deps, keyRequest(seeded.id, "", "PATCH", {}), { id: seeded.id });
    expect(missing.status).toBe(400);

    const unknownField = await updateKeyHandler(
      deps,
      keyRequest(seeded.id, "", "PATCH", { allowed_domains: null, bogus: 1 }),
      { id: seeded.id },
    );
    expect(unknownField.status).toBe(400);

    const missingId = crypto.randomUUID();
    const unknown = await updateKeyHandler(
      deps,
      keyRequest(missingId, "", "PATCH", { allowed_domains: null }),
      { id: missingId },
    );
    expect(unknown.status).toBe(404);
  });
});

describe("admin API keys — revoke", () => {
  it("revokes immediately and is idempotent, auditing only the transition", async () => {
    const deps = makeDeps();
    const seeded = await seedApiKey(env.DB, { label: "node-1" });

    const first = await revokeKeyHandler(deps, keyRequest(seeded.id, "/revoke"), { id: seeded.id });
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({ key: { id: seeded.id, status: "revoked" } });

    const second = await revokeKeyHandler(deps, keyRequest(seeded.id, "/revoke"), { id: seeded.id });
    expect(second.status).toBe(200);
    expect(await second.json()).toMatchObject({ key: { status: "revoked" } });

    const audits = (await listAuditLog(env.DB, { limit: 50, offset: 0 })).filter((row) => row.target === seeded.id);
    expect(audits.map(({ action }) => action)).toEqual(["key.revoke"]);

    const missing = await revokeKeyHandler(deps, keyRequest(crypto.randomUUID(), "/revoke"), { id: crypto.randomUUID() });
    expect(missing.status).toBe(404);
  });
});

describe("admin API keys — rotate", () => {
  it("creates a replacement with the same label and revokes the old key", async () => {
    const deps = makeDeps();
    const seeded = await seedApiKey(env.DB, { label: "node-1" });

    const response = await rotateKeyHandler(deps, keyRequest(seeded.id, "/rotate"), { id: seeded.id });
    expect(response.status).toBe(201);

    const body = await readJson<{ token: string; key: Record<string, unknown> }>(response);
    const newId = body.token.replace(/^cw_/, "").split(".")[0];
    expect(body.key).toMatchObject({ id: newId, label: "node-1", status: "active" });
    expect(newId).not.toBe(seeded.id);

    expect(await getApiKey(env.DB, seeded.id)).toMatchObject({ status: "revoked", revoked_at: expect.any(String) });

    const audits = (await listAuditLog(env.DB, { limit: 50, offset: 0 })).filter((row) => row.target === seeded.id);
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({ action: "key.rotate", target: seeded.id });
    expect(JSON.parse(audits[0].meta_json ?? "{}")).toEqual({
      new_key_id: newId,
      label: "node-1",
      allowed_domains: null,
    });
  });

  it("carries the domain scope over to the replacement key", async () => {
    const deps = makeDeps();
    await seedDomain(env.DB, { name: "rotate.example.com" });
    const seeded = await seedApiKey(env.DB, { label: "node-1", allowedDomains: ["rotate.example.com"] });

    const response = await rotateKeyHandler(deps, keyRequest(seeded.id, "/rotate"), { id: seeded.id });
    expect(response.status).toBe(201);

    const body = await readJson<{ token: string; key: { id: string } }>(response);
    const newId = body.token.replace(/^cw_/, "").split(".")[0];
    expect(body.key).toMatchObject({ allowed_domains: ["rotate.example.com"] });
    expect(await getApiKey(env.DB, newId)).toMatchObject({
      allowed_domains_json: JSON.stringify(["rotate.example.com"]),
    });
  });

  it("answers 404 for an unknown key", async () => {
    const response = await rotateKeyHandler(makeDeps(), keyRequest(crypto.randomUUID(), "/rotate"), { id: crypto.randomUUID() });
    expect(response.status).toBe(404);
  });
});
