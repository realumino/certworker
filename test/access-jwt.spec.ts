import { describe, expect, it } from "vitest";
import { SignJWT, generateSecret } from "jose";
import { ACCESS_JWT_HEADER, verifyAccessRequest, type AccessConfig } from "../src/auth/access";
import { createScriptedFetch, jsonResponse } from "./support/fake-fetch";
import { createTestAccess, jwksFetcher, type TestAccess } from "./support/admin";

function accessConfig(access: TestAccess): AccessConfig {
  return { teamDomain: access.teamDomain, aud: access.aud, devEmail: null };
}

function authedRequest(token: string, url = "https://ssl.example.com/api/overview"): Request {
  return new Request(url, { headers: { [ACCESS_JWT_HEADER]: token } });
}

function rejectIdentity(result: unknown): Response {
  if (!(result instanceof Response)) throw new Error("expected a 401/500 Response");
  return result;
}

describe("Access JWT verification", () => {
  it("accepts a valid token and uses its email as the actor", async () => {
    const access = await createTestAccess({ email: "ada@example.com" });
    const { fetch, requests } = jwksFetcher(access);
    const token = await access.signToken();

    const identity = await verifyAccessRequest(authedRequest(token), accessConfig(access), { fetcher: fetch });
    if (identity instanceof Response) throw new Error(`unexpected rejection: ${identity.status}`);

    expect(identity.actor).toBe("ada@example.com");
    expect(identity.payload.email).toBe("ada@example.com");
    expect(requests).toHaveLength(1);
    expect(requests[0].url.toString()).toBe(`${access.teamDomain}/cdn-cgi/access/certs`);
  });

  it("caches the JWKS for the same fetcher across requests", async () => {
    const access = await createTestAccess();
    const { fetch, requests } = jwksFetcher(access);
    const token = await access.signToken();
    const options = { fetcher: fetch };
    const config = accessConfig(access);

    await verifyAccessRequest(authedRequest(token), config, options);
    await verifyAccessRequest(authedRequest(token), config, options);

    expect(requests).toHaveLength(1);
  });

  it("rejects a missing header", async () => {
    const access = await createTestAccess();
    const { fetch } = jwksFetcher(access);
    const result = await verifyAccessRequest(
      new Request("https://ssl.example.com/api/overview"),
      accessConfig(access),
      { fetcher: fetch },
    );
    const response = await rejectIdentity(result);
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: "unauthorized" });
  });

  it("rejects a malformed token", async () => {
    const access = await createTestAccess();
    const { fetch } = jwksFetcher(access);
    const response = await rejectIdentity(
      await verifyAccessRequest(authedRequest("not-a-jwt"), accessConfig(access), { fetcher: fetch }),
    );
    expect(response.status).toBe(401);
  });

  it("rejects a token from another team domain (issuer)", async () => {
    const access = await createTestAccess();
    const { fetch } = jwksFetcher(access);
    const token = await access.signToken({ issuer: "https://other.cloudflareaccess.com" });
    const response = await rejectIdentity(
      await verifyAccessRequest(authedRequest(token), accessConfig(access), { fetcher: fetch }),
    );
    expect(response.status).toBe(401);
  });

  it("rejects a token for another application (audience)", async () => {
    const access = await createTestAccess();
    const { fetch } = jwksFetcher(access);
    const token = await access.signToken({ audience: "aud-other" });
    const response = await rejectIdentity(
      await verifyAccessRequest(authedRequest(token), accessConfig(access), { fetcher: fetch }),
    );
    expect(response.status).toBe(401);
  });

  it("rejects an expired token", async () => {
    const access = await createTestAccess();
    const { fetch } = jwksFetcher(access);
    const token = await access.signToken({ expiresIn: Math.floor(Date.now() / 1000) - 10 });
    const response = await rejectIdentity(
      await verifyAccessRequest(authedRequest(token), accessConfig(access), { fetcher: fetch }),
    );
    expect(response.status).toBe(401);
  });

  it("rejects a token signed by a key that is not in the JWKS", async () => {
    const served = await createTestAccess();
    const forger = await createTestAccess({ kid: served.jwks.keys[0].kid as string });
    const { fetch } = jwksFetcher(served);
    const token = await forger.signToken();
    const response = await rejectIdentity(
      await verifyAccessRequest(authedRequest(token), accessConfig(served), { fetcher: fetch }),
    );
    expect(response.status).toBe(401);
  });

  it("rejects an HS256-forged token (RS256 pinned)", async () => {
    const access = await createTestAccess();
    const { fetch } = jwksFetcher(access);
    const secret = await generateSecret("HS256");
    const token = await new SignJWT({ email: "attacker@example.com" })
      .setProtectedHeader({ alg: "HS256", kid: "test-access-key" })
      .setIssuer(access.teamDomain)
      .setAudience(access.aud)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(secret);
    const response = await rejectIdentity(
      await verifyAccessRequest(authedRequest(token), accessConfig(access), { fetcher: fetch }),
    );
    expect(response.status).toBe(401);
  });

  it("rejects tokens when the JWKS endpoint fails", async () => {
    const access = await createTestAccess();
    const { fetch } = createScriptedFetch(() => jsonResponse({ error: "unavailable" }, { status: 500 }));
    const token = await access.signToken();
    const response = await rejectIdentity(
      await verifyAccessRequest(authedRequest(token), accessConfig(access), { fetcher: fetch }),
    );
    expect(response.status).toBe(401);
  });

  it("returns access_not_configured when the team domain or AUD is empty", async () => {
    const access = await createTestAccess();
    const token = await access.signToken();

    for (const config of [
      { teamDomain: "  ", aud: access.aud, devEmail: null },
      { teamDomain: access.teamDomain, aud: "", devEmail: null },
    ]) {
      const response = await rejectIdentity(await verifyAccessRequest(authedRequest(token), config));
      expect(response.status).toBe(500);
      expect(await response.json()).toMatchObject({ error: "access_not_configured" });
    }
  });

  describe("loopback dev bypass", () => {
    it("skips verification on loopback hosts when DEV_ACCESS_EMAIL is set", async () => {
      const request = new Request("http://localhost:8787/api/overview");
      const identity = await verifyAccessRequest(request, {
        teamDomain: "",
        aud: "",
        devEmail: "dev@example.com",
      });
      if (identity instanceof Response) throw new Error(`unexpected rejection: ${identity.status}`);
      expect(identity.actor).toBe("dev@example.com");
      expect(identity.payload.dev_bypass).toBe(true);
    });

    it("never bypasses on a non-loopback host", async () => {
      const response = await rejectIdentity(await verifyAccessRequest(
        new Request("https://ssl.example.com/api/overview"),
        { teamDomain: "", aud: "", devEmail: "dev@example.com" },
      ));
      expect(response.status).toBe(401);
    });

    it("never bypasses without DEV_ACCESS_EMAIL", async () => {
      const response = await rejectIdentity(await verifyAccessRequest(
        new Request("http://localhost:8787/api/overview"),
        { teamDomain: "", aud: "", devEmail: null },
      ));
      expect(response.status).toBe(401);
    });
  });
});
