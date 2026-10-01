import { createRemoteJWKSet, customFetch, jwtVerify, type JWTPayload } from "jose";

export const ACCESS_JWT_HEADER = "Cf-Access-Jwt-Assertion";

export interface AccessConfig {
  teamDomain: string;
  aud: string;
  devEmail: string | null;
}

export interface AccessIdentity {
  /** Access email — the actor recorded in the audit log. */
  actor: string;
  payload: JWTPayload;
}

export interface VerifyAccessOptions {
  /** Test seam: fetch implementation used for JWKS retrieval. */
  fetcher?: typeof fetch;
}

type RemoteJwkSet = ReturnType<typeof createRemoteJWKSet>;

/**
 * Cloudflare Access signs application tokens RS256 and publishes its JWKS at
 * `${teamDomain}/cdn-cgi/access/certs`. jose caches fetched keys per resolver
 * instance (10 min, unknown-kid refetch after a 30 s cooldown), so one resolver
 * per JWKS URL is memoized per isolate. Injected fetchers get a per-fetcher
 * cache instead, which keeps tests isolated.
 */
const remoteJwksByUrl = new Map<string, RemoteJwkSet>();
const remoteJwksByFetcher = new WeakMap<typeof fetch, Map<string, RemoteJwkSet>>();

const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]"]);
let devBypassWarned = false;

export function accessConfigFromEnv(
  env: Pick<Env, "ACCESS_TEAM_DOMAIN" | "ACCESS_AUD" | "DEV_ACCESS_EMAIL">,
): AccessConfig {
  return {
    teamDomain: env.ACCESS_TEAM_DOMAIN,
    aud: env.ACCESS_AUD,
    devEmail: env.DEV_ACCESS_EMAIL || null,
  };
}

/**
 * Verify the Access-injected `Cf-Access-Jwt-Assertion` header: signature
 * against the team JWKS, `iss` = team domain, `aud` = application AUD tag,
 * RS256 only. Returns the verified identity, or a 401/500 Response.
 */
export async function verifyAccessRequest(
  request: Request,
  access: AccessConfig,
  options: VerifyAccessOptions = {},
): Promise<AccessIdentity | Response> {
  const devIdentity = devBypassIdentity(request, access.devEmail);
  if (devIdentity) return devIdentity;

  const token = request.headers.get(ACCESS_JWT_HEADER);
  if (!token) {
    return unauthorizedResponse("Cloudflare Access JWT required");
  }

  const teamDomain = access.teamDomain.trim().replace(/\/+$/, "");
  const aud = access.aud.trim();
  if (!teamDomain || !aud) {
    console.error(JSON.stringify({ event: "access.not_configured" }));
    return Response.json(
      { error: "access_not_configured", message: "Cloudflare Access is not configured (ACCESS_TEAM_DOMAIN / ACCESS_AUD)" },
      { status: 500, headers: { "Cache-Control": "no-store" } },
    );
  }

  try {
    const { payload } = await jwtVerify(token, getRemoteJwks(teamDomain, options.fetcher), {
      issuer: teamDomain,
      audience: aud,
      algorithms: ["RS256"],
    });
    return { actor: actorFromPayload(payload), payload };
  } catch (error) {
    console.warn(JSON.stringify({
      event: "access.jwt_rejected",
      reason: error instanceof Error ? error.message : String(error),
    }));
    return unauthorizedResponse("Cloudflare Access JWT invalid or expired");
  }
}

function getRemoteJwks(teamDomain: string, fetcher?: typeof fetch): RemoteJwkSet {
  const url = new URL(`${teamDomain}/cdn-cgi/access/certs`);
  const cacheKey = url.toString();

  if (fetcher === undefined) {
    let jwks = remoteJwksByUrl.get(cacheKey);
    if (!jwks) {
      jwks = createRemoteJWKSet(url);
      remoteJwksByUrl.set(cacheKey, jwks);
    }
    return jwks;
  }

  let byUrl = remoteJwksByFetcher.get(fetcher);
  if (!byUrl) {
    byUrl = new Map();
    remoteJwksByFetcher.set(fetcher, byUrl);
  }
  let jwks = byUrl.get(cacheKey);
  if (!jwks) {
    jwks = createRemoteJWKSet(url, { [customFetch]: (href, init) => fetcher(href, init) });
    byUrl.set(cacheKey, jwks);
  }
  return jwks;
}

/**
 * Local-dev affordance for `wrangler dev`, where no Cloudflare Access sits in
 * front of the Worker: when DEV_ACCESS_EMAIL is set AND the request host is
 * loopback, skip JWT verification and use it as the audit actor. Empty in every
 * deployed environment, and unreachable on a production hostname even if the
 * variable were set there by mistake.
 */
function devBypassIdentity(request: Request, devEmail: string | null): AccessIdentity | null {
  if (!devEmail) return null;
  const hostname = new URL(request.url).hostname;
  if (!LOOPBACK_HOSTNAMES.has(hostname)) return null;

  if (!devBypassWarned) {
    console.warn(JSON.stringify({ event: "access.dev_bypass", email: devEmail }));
    devBypassWarned = true;
  }
  return { actor: devEmail, payload: { email: devEmail, dev_bypass: true } };
}

function actorFromPayload(payload: JWTPayload): string {
  for (const claim of [payload.email, payload.common_name, payload.sub]) {
    if (typeof claim === "string" && claim.length > 0) return claim;
  }
  return "unknown";
}

function unauthorizedResponse(message: string): Response {
  return Response.json(
    { error: "unauthorized", message },
    { status: 401, headers: { "Cache-Control": "no-store" } },
  );
}
