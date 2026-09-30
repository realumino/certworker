export const ACCESS_JWT_HEADER = "Cf-Access-Jwt-Assertion";

/**
 * M0 gate: require the Access-injected JWT header.
 * M4 replaces this with signature/iss/aud verification against the team JWKS (jose).
 */
export function requireAccessJwt(request: Request): Response | null {
  if (!request.headers.has(ACCESS_JWT_HEADER)) {
    return Response.json(
      { error: "unauthorized", message: "Cloudflare Access JWT required" },
      { status: 401, headers: { "Cache-Control": "no-store" } },
    );
  }
  return null;
}
