import { describe, expect, it } from "vitest";
import {
  dns01RecordName,
  dns01Value,
  DnsPropagationError,
  normalizeDomainName,
  waitForTxtPropagation,
} from "../src/acme/dns01";
import { createScriptedFetch, jsonResponse } from "./support/fake-fetch";

describe("DNS-01 helpers", () => {
  it("normalizes case, trailing dots, IDNs, and explicit wildcards", () => {
    expect(normalizeDomainName("Example.COM.")).toBe("example.com");
    expect(normalizeDomainName("*.Example.COM")).toBe("*.example.com");
    expect(normalizeDomainName("bücher.example")).toBe("xn--bcher-kva.example");
    expect(dns01RecordName("example.com")).toBe("_acme-challenge.example.com");
    expect(dns01RecordName("*.example.com")).toBe("_acme-challenge.example.com");
  });

  it.each(["192.0.2.1", "example_name.com", "*.foo.*.com", "x.*", "example..com", "https://example.com", "%65xample.com"]) (
    "rejects invalid DNS name %s",
    (name) => {
      expect(() => normalizeDomainName(name)).toThrow("Invalid DNS name");
    },
  );

  it("matches the frozen RFC-shaped DNS-01 vector", async () => {
    await expect(
      dns01Value(
        "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA",
        "7mSnWd3AvG-LuZDrrKbSJPvG4_ZMeo7OXDprlNLObmY",
      ),
    ).resolves.toBe("8rwBNbfyrlRGbmRA-F9guumqV-r990TeaGPbC4HNjAs");
    await expect(dns01Value("invalid=token", "thumbprint")).rejects.toThrow("base64url");
  });
});

describe("DNS-over-HTTPS propagation", () => {
  it("waits until every expected value is visible at both resolvers and remains visible for the settle interval", async () => {
    let now = 0;
    const calls = new Map<string, number>();
    const mock = createScriptedFetch(({ url }) => {
      const count = (calls.get(url.hostname) ?? 0) + 1;
      calls.set(url.hostname, count);
      const answer = count === 1 ? ["value-one"] : ["value-one", "value-two"];
      return jsonResponse({ Answer: answer.map((data) => ({ type: 16, data: `"${data}"` })) });
    });

    await waitForTxtPropagation(
      [{ name: "_acme-challenge.example.com", values: ["value-one", "value-two"] }],
      {
        fetch: mock.fetch,
        resolvers: [
          { name: "resolver-a", url: "https://a.example/dns-query" },
          { name: "resolver-b", url: "https://b.example/resolve" },
        ],
        now: () => now,
        wait: async (ms) => { now += ms; },
        timeoutMs: 10_000,
        pollIntervalMs: 1_000,
        settleMs: 2_000,
      },
    );

    expect(now).toBe(3_000);
    expect(mock.requests).toHaveLength(8);
    expect(mock.requests[0].url.searchParams.get("type")).toBe("TXT");
    expect(mock.requests[0].request.headers.get("accept")).toBe("application/dns-json");
  });

  it("times out with resolver-specific missing values", async () => {
    let now = 0;
    const mock = createScriptedFetch(() => jsonResponse({ Status: 0, Answer: [] }));

    await expect(
      waitForTxtPropagation(
        [{ name: "_acme-challenge.example.com", values: ["expected"] }],
        {
          fetch: mock.fetch,
          resolvers: [{ name: "resolver-a", url: "https://a.example/resolve" }],
          now: () => now,
          wait: async (ms) => { now += ms; },
          timeoutMs: 2_000,
          pollIntervalMs: 1_000,
          settleMs: 0,
        },
      ),
    ).rejects.toMatchObject({
      name: "DnsPropagationError",
      missingByResolver: { "resolver-a": ["_acme-challenge.example.com=expected"] },
    } satisfies Partial<DnsPropagationError>);
  });
});
