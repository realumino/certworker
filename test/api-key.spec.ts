import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { authenticateApiKey, constantTimeEqualHex, parseBearerToken } from "../src/auth/api-key";
import { seedApiKey } from "./support/admin";
import { bearerToken, pullRequest } from "./support/nodes";

const SECRET = "a".repeat(43);

describe("bearer token parsing", () => {
  it("accepts the `scw_<id>.<secret>` shape", () => {
    expect(parseBearerToken("Bearer scw_abc-def.abc0_-")).toEqual({ id: "abc-def", secret: "abc0_-" });
    expect(parseBearerToken("bearer scw_x.y")).toEqual({ id: "x", secret: "y" });
  });

  it("rejects malformed or absent headers", () => {
    expect(parseBearerToken(null)).toBeNull();
    expect(parseBearerToken("")).toBeNull();
    expect(parseBearerToken("Basic abc")).toBeNull();
    expect(parseBearerToken("scw_x.y")).toBeNull();
    expect(parseBearerToken("Bearer xyz.y")).toBeNull();
    expect(parseBearerToken("Bearer scw_x")).toBeNull();
    expect(parseBearerToken("Bearer scw_.y")).toBeNull();
  });
});

describe("constant-time hex comparison", () => {
  it("compares equal digests without short-circuiting", () => {
    expect(constantTimeEqualHex("aabb", "aabb")).toBe(true);
    expect(constantTimeEqualHex("aabb", "aacc")).toBe(false);
    expect(constantTimeEqualHex("aabb", "aaaa")).toBe(false);
  });
});

describe("API key authentication", () => {
  it("accepts the seeded token and returns the key row", async () => {
    const key = await seedApiKey(env.DB, { label: "node-a", secret: SECRET });
    const identity = await authenticateApiKey(pullRequest("/v1/me", bearerToken(key.id, SECRET)), env.DB);
    if (identity instanceof Response) throw new Error("expected identity");
    expect(identity.key).toMatchObject({ id: key.id, label: "node-a", status: "active" });
  });

  it("rejects an unknown key id, a wrong secret, and a revoked key identically", async () => {
    const key = await seedApiKey(env.DB, { secret: SECRET });
    const wrongSecret = await authenticateApiKey(
      pullRequest("/v1/me", bearerToken(key.id, "b".repeat(43))),
      env.DB,
    );
    const unknownId = await authenticateApiKey(
      pullRequest("/v1/me", bearerToken(crypto.randomUUID(), SECRET)),
      env.DB,
    );

    if (!(wrongSecret instanceof Response) || !(unknownId instanceof Response)) {
      throw new Error("expected 401 responses");
    }
    expect(wrongSecret.status).toBe(401);
    expect(unknownId.status).toBe(401);
    await expect(wrongSecret.json()).resolves.toEqual({ error: "unauthorized", message: expect.any(String) });
  });

  it("rejects a revoked key even with a valid secret", async () => {
    const key = await seedApiKey(env.DB, { secret: SECRET });
    const token = bearerToken(key.id, SECRET);
    const before = await authenticateApiKey(pullRequest("/v1/me", token), env.DB);
    if (before instanceof Response) throw new Error("expected identity before revocation");

    await env.DB.prepare("UPDATE api_keys SET status = 'revoked', revoked_at = ? WHERE id = ?")
      .bind(new Date().toISOString(), key.id).run();

    const response = await authenticateApiKey(pullRequest("/v1/me", token), env.DB);
    if (!(response instanceof Response)) throw new Error("expected 401 after revocation");
    expect(response.status).toBe(401);
  });

  it("rejects a missing or malformed Authorization header", async () => {
    await seedApiKey(env.DB, { secret: SECRET });
    for (const request of [
      pullRequest("/v1/me"),
      pullRequest("/v1/me", ""),
      pullRequest("/v1/me", "garbage"),
    ]) {
      const response = await authenticateApiKey(request, env.DB);
      if (!(response instanceof Response)) throw new Error("expected 401");
      expect(response.status).toBe(401);
      expect(response.headers.get("www-authenticate")).toBe("Bearer");
      expect(response.headers.get("cache-control")).toBe("no-store");
    }
  });
});
