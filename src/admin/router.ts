import { requireAccessJwt } from "../auth/access";

/** Admin API — Access app A + Worker-side JWT verification. Handlers land in M4. */
export async function handleAdminApi(request: Request, _env: Env): Promise<Response> {
  const denied = requireAccessJwt(request);
  if (denied) return denied;

  // TODO(M4): verify JWT signature (JWKS at env.ACCESS_TEAM_DOMAIN), iss + aud;
  // then dispatch /overview, /domains, /certificates, /runs, /keys, /pulls, /audit.
  return Response.json(
    { error: "not_implemented", milestone: "M4" },
    { status: 501, headers: { "Cache-Control": "no-store" } },
  );
}
