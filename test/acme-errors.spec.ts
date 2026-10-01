import { describe, expect, it } from "vitest";
import { AcmeError, isBadNonce, isRateLimited, parseRetryAfter } from "../src/acme/errors";

describe("ACME error classification", () => {
  it("parses delay-seconds and HTTP-date Retry-After values", () => {
    expect(parseRetryAfter("120", 0)).toBe(120);
    expect(parseRetryAfter("Thu, 01 Jan 1970 00:00:02 GMT", 0)).toBe(2);
    expect(parseRetryAfter("Thu, 01 Jan 1970 00:00:00 GMT", 1_500)).toBe(0);
    expect(parseRetryAfter("invalid", 0)).toBeUndefined();
    expect(parseRetryAfter("-1", 0)).toBeUndefined();
  });

  it("keeps problem details and classifies badNonce and rateLimited", () => {
    const badNonce = AcmeError.fromResponse(
      400,
      '{"type":"urn:ietf:params:acme:error:badNonce","detail":"try again","subproblems":[]}',
    );
    const limited = AcmeError.fromResponse(
      429,
      '{"type":"urn:ietf:params:acme:error:rateLimited","detail":"slow down"}',
      120,
    );

    expect(isBadNonce(badNonce)).toBe(true);
    expect(isRateLimited(limited)).toBe(true);
    expect(limited.retryAfterSeconds).toBe(120);
    expect(limited.rawBody).toContain("rateLimited");
    expect(limited.subproblems).toBeUndefined();
  });
});
