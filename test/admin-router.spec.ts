import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { handleAdminApi } from "../src/admin/router";
import { accessRequest, adminOptions, createTestAccess, jwksFetcher } from "./support/admin";
import { readJson } from "./support/fake-fetch";

async function authenticatedAccess() {
  const access = await createTestAccess();
  const { fetch } = jwksFetcher(access);
  const token = await access.signToken();
  return { access, fetch, token, options: adminOptions(access, fetch) };
}

describe("admin router", () => {
  it("rejects requests without an Access JWT", async () => {
    const { options } = await authenticatedAccess();
    const response = await handleAdminApi(
      new Request("https://ssl.example.com/api/overview"),
      env,
      options,
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: "unauthorized" });
  });

  it("dispatches an authenticated GET to the matching handler", async () => {
    const { access, token, options } = await authenticatedAccess();
    const response = await handleAdminApi(
      accessRequest("/api/overview", token),
      env,
      options,
    );
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({ domains: {}, certificates: {}, runs: {}, keys: {} });
  });

  it("answers 404 for unknown /api paths", async () => {
    const { access, token, options } = await authenticatedAccess();
    const response = await handleAdminApi(accessRequest("/api/nonsense", token), env, options);
    expect(response.status).toBe(404);
    expect(await response.json()).toMatchObject({ error: "not_found" });
  });

  it("answers 405 with Allow when the method is wrong", async () => {
    const { access, token, options } = await authenticatedAccess();
    const response = await handleAdminApi(
      accessRequest("/api/overview", token, { method: "DELETE" }),
      env,
      options,
    );
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET");
    expect(await response.json()).toMatchObject({ error: "method_not_allowed" });
  });

  it("rejects mutations without a JSON content type", async () => {
    const { access, token, options } = await authenticatedAccess();
    const response = await handleAdminApi(
      new Request("https://ssl.example.com/api/keys", {
        method: "POST",
        headers: {
          "Origin": "https://ssl.example.com",
          "Sec-Fetch-Site": "same-origin",
          "Content-Type": "text/plain",
          "Cf-Access-Jwt-Assertion": token,
        },
        body: "{}",
      }),
      env,
      options,
    );
    expect(response.status).toBe(415);
    expect(await response.json()).toMatchObject({ error: "unsupported_media_type" });
  });

  it("rejects mutations from a cross-origin Origin header", async () => {
    const { access, token, options } = await authenticatedAccess();
    const response = await handleAdminApi(
      accessRequest("/api/keys", token, {
        method: "POST",
        headers: { "Origin": "https://evil.example" },
        body: JSON.stringify({ label: "x" }),
      }),
      env,
      options,
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: "cross_origin_rejected" });
  });

  it("rejects cross-site browser fetches via Sec-Fetch-Site", async () => {
    const { access, token, options } = await authenticatedAccess();
    const response = await handleAdminApi(
      accessRequest("/api/keys", token, {
        method: "POST",
        headers: { "Sec-Fetch-Site": "cross-site" },
        body: JSON.stringify({ label: "x" }),
      }),
      env,
      options,
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: "cross_origin_rejected" });
  });

  it("reaches handlers for same-origin JSON mutations", async () => {
    const { access, token, options } = await authenticatedAccess();
    const response = await handleAdminApi(
      accessRequest("/api/keys", token, {
        method: "POST",
        body: JSON.stringify({ label: "node-1" }),
      }),
      env,
      options,
    );
    expect(response.status).toBe(201);
    const body = await readJson<{ token: string }>(response);
    expect(body.token).toMatch(/^scw_[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/);
  });

  it("allows non-browser clients without Origin/Sec-Fetch-Site", async () => {
    const { access, token, options } = await authenticatedAccess();
    const response = await handleAdminApi(
      new Request("https://ssl.example.com/api/keys", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Cf-Access-Jwt-Assertion": token,
        },
        body: JSON.stringify({ label: "node-2" }),
      }),
      env,
      options,
    );
    expect(response.status).toBe(201);
  });

  it("answers 500 with internal_error when a store call throws", async () => {
    const { access, token, options } = await authenticatedAccess();
    const brokenEnv = {
      ...env,
      DB: {
        prepare(): never {
          throw new Error("db down");
        },
      },
    } as unknown as Env;
    const response = await handleAdminApi(accessRequest("/api/overview", token), brokenEnv, options);
    expect(response.status).toBe(500);
    expect(await response.json()).toMatchObject({ error: "internal_error" });
  });
});
