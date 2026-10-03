import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { createAdminDependencies, type AdminDependencies } from "../src/admin/deps";
import { createKeyHandler, listKeysHandler, revokeKeyHandler, rotateKeyHandler } from "../src/admin/keys";
import { sha256Hex } from "../src/crypto/keys";
import { getApiKey, listAuditLog } from "../src/store/d1";
import { readJson } from "./support/fake-fetch";
import { seedApiKey } from "./support/admin";

const makeDeps = (): AdminDependencies => createAdminDependencies(env, "admin@example.com");

function jsonRequest(body: unknown, method = "POST"): Request {
  return new Request("https://ssl.example.com/api/keys", {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

function keyRequest(id: string, path: string, method = "POST"): Request {
  return new Request(`https://ssl.example.com/api/keys/${id}${path}`, { method });
}

describe("admin API keys — create", () => {
  it("stores only the secret hash and shows the token once", async () => {
    const response = await createKeyHandler(makeDeps(), jsonRequest({ label: "node-1" }));
    expect(response.status).toBe(201);

    const body = await readJson<{ token: string; key: Record<string, unknown> }>(response);
    const token = body.token;
    const withoutPrefix = token.replace(/^cw_/, "");
    const [id, secret] = withoutPrefix.split(".");
    expect(body.key).toMatchObject({ id, label: "node-1", status: "active" });
    expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const row = await getApiKey(env.DB, id);
    expect(row).not.toBeNull();
    expect(row?.key_hash).toBe(await sha256Hex(secret));
    expect(row?.key_hint).toBe(`cw_${id}…${secret.slice(-4)}`);
    expect(row?.allowed_domains_json).toBeNull();

    const listed = await listKeysHandler(makeDeps(), new Request("https://ssl.example.com/api/keys"));
    const listedBody = JSON.stringify(await listed.json());
    expect(listedBody).not.toContain(secret);
    expect(listedBody).not.toContain("key_hash");

    const audits = (await listAuditLog(env.DB, { limit: 50, offset: 0 })).filter((row) => row.target === id);
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({ actor: "admin@example.com", action: "key.create", target: id });
    expect(JSON.parse(audits[0].meta_json ?? "{}")).toEqual({ label: "node-1" });
  });

  it("validates the label and rejects unknown fields", async () => {
    const deps = makeDeps();

    const missing = await createKeyHandler(deps, jsonRequest({}));
    expect(missing.status).toBe(400);

    const tooLong = await createKeyHandler(deps, jsonRequest({ label: "x".repeat(65) }));
    expect(tooLong.status).toBe(400);

    const controlChars = await createKeyHandler(deps, jsonRequest({ label: "node\u00001" }));
    expect(controlChars.status).toBe(400);

    const unknownField = await createKeyHandler(deps, jsonRequest({ label: "node-1", allowed_domains: ["example.com"] }));
    expect(unknownField.status).toBe(400);
    expect(await unknownField.json()).toMatchObject({ error: "invalid_request" });
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
    expect(JSON.parse(audits[0].meta_json ?? "{}")).toEqual({ new_key_id: newId, label: "node-1" });
  });

  it("answers 404 for an unknown key", async () => {
    const response = await rotateKeyHandler(makeDeps(), keyRequest(crypto.randomUUID(), "/rotate"), { id: crypto.randomUUID() });
    expect(response.status).toBe(404);
  });
});
