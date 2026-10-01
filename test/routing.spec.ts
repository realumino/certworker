import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("one-hostname routing", () => {
  it("rejects /api/* without an Access JWT (M0 acceptance)", async () => {
    const res = await SELF.fetch("https://ssl.example.com/api/overview");
    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toContain("application/json");
    await expect(res.json()).resolves.toMatchObject({ error: "unauthorized" });
  });

  it("rejects a malformed Access JWT before handler dispatch (M4 verification)", async () => {
    const res = await SELF.fetch("https://ssl.example.com/api/overview", {
      headers: { "Cf-Access-Jwt-Assertion": "not-a-jwt" },
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("cache-control")).toBe("no-store");
    await expect(res.json()).resolves.toMatchObject({ error: "unauthorized" });
  });

  it("routes /v1/* to the worker and requires an API key (M6)", async () => {
    const res = await SELF.fetch("https://ssl.example.com/v1/me");
    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(res.headers.get("www-authenticate")).toBe("Bearer");
    await expect(res.json()).resolves.toMatchObject({ error: "unauthorized" });
  });

  it("rejects non-GET pull requests", async () => {
    const res = await SELF.fetch("https://ssl.example.com/v1/me", { method: "POST" });
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("GET");
  });

  it("serves the SPA shell at /", async () => {
    const res = await SELF.fetch("https://ssl.example.com/");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
  });

  it("falls back to the SPA shell for client routes", async () => {
    const res = await SELF.fetch("https://ssl.example.com/domains");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
  });
});
