import { describe, expect, it } from "vitest";
import { CloudflareApiError, createTxtRecord, deleteTxtRecord, findZoneId } from "../src/dns/cloudflare";
import { createScriptedFetch, jsonResponse } from "./support/fake-fetch";

const TOKEN = "test-cloudflare-token";

describe("Cloudflare DNS API", () => {
  it("walks from a host to the longest matching zone suffix", async () => {
    const mock = createScriptedFetch(({ url }) => {
      const candidate = url.searchParams.get("name");
      if (candidate === "www.dev.example.com") return jsonResponse({ success: true, result: [] });
      if (candidate === "dev.example.com") {
        return jsonResponse({ success: true, result: [{ id: "zone-dev", name: "dev.example.com", status: "active" }] });
      }
      throw new Error(`Unexpected zone candidate: ${candidate}`);
    });

    await expect(findZoneId({ apiToken: TOKEN, domain: "www.dev.example.com", fetch: mock.fetch })).resolves.toBe("zone-dev");
    expect(mock.requests.map(({ url }) => url.searchParams.get("name"))).toEqual([
      "www.dev.example.com",
      "dev.example.com",
    ]);
    expect(mock.requests[0].request.headers.get("authorization")).toBe(`Bearer ${TOKEN}`);
  });

  it("creates TXT records and deletes by the returned record ID", async () => {
    const mock = createScriptedFetch(({ request, url, body }) => {
      if (request.method === "POST") {
        expect(url.pathname).toBe("/client/v4/zones/zone-1/dns_records");
        expect(JSON.parse(body)).toEqual({
          type: "TXT",
          name: "_acme-challenge.example.com",
          content: "dns01-value",
          ttl: 60,
        });
        return jsonResponse({
          success: true,
          result: {
            id: "record-1",
            name: "_acme-challenge.example.com",
            content: "dns01-value",
            type: "TXT",
          },
        });
      }
      expect(request.method).toBe("DELETE");
      expect(url.pathname).toBe("/client/v4/zones/zone-1/dns_records/record-1");
      return jsonResponse({ success: true, result: { id: "record-1" } });
    });

    const recordId = await createTxtRecord({
      apiToken: TOKEN,
      zoneId: "zone-1",
      name: "_acme-challenge.example.com",
      value: "dns01-value",
      fetch: mock.fetch,
    });
    await deleteTxtRecord({ apiToken: TOKEN, zoneId: "zone-1", recordId, fetch: mock.fetch });
    expect(mock.requests).toHaveLength(2);
  });

  it("surfaces missing scope and permission guidance", async () => {
    const mock = createScriptedFetch(() => jsonResponse(
      { success: false, errors: [{ code: 9109, message: "Invalid access token" }] },
      { status: 403 },
    ));

    await expect(createTxtRecord({
      apiToken: TOKEN,
      zoneId: "zone-1",
      name: "_acme-challenge.example.com",
      value: "dns01-value",
      fetch: mock.fetch,
    })).rejects.toMatchObject({
      name: "CloudflareApiError",
      status: 403,
      message: expect.stringContaining("Zone:DNS:Edit"),
    } satisfies Partial<CloudflareApiError>);
  });

  it("reports when the scoped token cannot see a matching zone", async () => {
    const mock = createScriptedFetch(() => jsonResponse({ success: true, result: [] }));
    await expect(findZoneId({ apiToken: TOKEN, domain: "www.example.com", fetch: mock.fetch })).rejects.toThrow(
      "Zone:Zone:Read",
    );
  });

  it("treats deletion of an already-removed TXT record as successful cleanup", async () => {
    const mock = createScriptedFetch(() => jsonResponse(
      { success: false, errors: [{ code: 81044, message: "Record does not exist" }] },
      { status: 404 },
    ));

    await expect(deleteTxtRecord({
      apiToken: TOKEN,
      zoneId: "zone-1",
      recordId: "already-deleted",
      fetch: mock.fetch,
    })).resolves.toBeUndefined();
  });
});
