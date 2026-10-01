import { describe, expect, it, vi } from "vitest";
import { ApiError, apiFetch, asApiError, onUnauthorized, query } from "../api/client";
import { installFetchStub, json } from "./support";

describe("api client", () => {
  it("sends mutations as JSON with the headers the mutation guard requires", async () => {
    const stub = installFetchStub({
      "POST /api/keys": () => json({ key: {}, token: "t" }, 201),
    });

    await apiFetch("/api/keys", { method: "POST", body: { label: "web-01" } });

    expect(stub.requests).toEqual([{ method: "POST", path: "/api/keys", body: { label: "web-01" } }]);
  });

  it("maps error bodies onto ApiError", async () => {
    installFetchStub({
      "POST /api/domains": () => json({ error: "domain_exists", message: "A domain row already exists" }, 409),
    });

    await expect(apiFetch("/api/domains", { method: "POST", body: { name: "x" } })).rejects.toMatchObject({
      name: "ApiError",
      status: 409,
      code: "domain_exists",
      message: "A domain row already exists",
    });
  });

  it("notifies the unauthorized listener on 401", async () => {
    const listener = vi.fn();
    onUnauthorized(listener);
    installFetchStub({
      "GET /api/overview": () => json({ error: "unauthorized", message: "Cloudflare Access JWT required" }, 401),
    });

    await expect(apiFetch("/api/overview")).rejects.toBeInstanceOf(ApiError);
    expect(listener).toHaveBeenCalledTimes(1);
    expect(asApiError(new Error("boom"))).toMatchObject({ status: 0, code: "network_error" });
  });

  it("builds query strings, skipping empty values", () => {
    expect(query({ status: "active", domain_id: "", offset: 0, limit: undefined })).toBe("status=active&offset=0");
  });
});
