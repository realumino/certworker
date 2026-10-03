import { sha256Hex } from "../crypto/keys";
import { getApiKey, type ApiKeyRow } from "../store/d1";

export interface ApiKeyIdentity {
  key: ApiKeyRow;
}

const BEARER_TOKEN = /^Bearer\s+cw_([A-Za-z0-9-]+)\.([A-Za-z0-9_-]+)$/i;

export function parseBearerToken(header: string | null): { id: string; secret: string } | null {
  const match = BEARER_TOKEN.exec((header ?? "").trim());
  if (!match) return null;
  return { id: match[1], secret: match[2] };
}

/**
 * Compare two same-length hex digests without early exit. Web Crypto has no
 * timing-safe compare; both inputs are always 64-character SHA-256 hex strings,
 * so a length difference is not a meaningful oracle.
 */
export function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) {
    diff |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return diff === 0;
}

/**
 * Verify a node's bearer token: parse `cw_<id>.<secret>`, look up the key by
 * its embedded id, hash the secret, and compare to the stored hash in constant
 * time. Unknown, revoked, or mismatched keys all produce the same 401.
 */
export async function authenticateApiKey(
  request: Request,
  db: D1Database,
): Promise<ApiKeyIdentity | Response> {
  const parsed = parseBearerToken(request.headers.get("Authorization"));
  if (!parsed) return unauthorizedResponse();

  const row = await getApiKey(db, parsed.id);
  if (!row || row.status !== "active") return unauthorizedResponse();

  const hash = await sha256Hex(parsed.secret);
  if (!constantTimeEqualHex(hash, row.key_hash)) return unauthorizedResponse();

  return { key: row };
}

export function unauthorizedResponse(): Response {
  return Response.json(
    { error: "unauthorized", message: "A valid node API key is required (Authorization: Bearer cw_<id>.<secret>)" },
    { status: 401, headers: { "Cache-Control": "no-store", "WWW-Authenticate": "Bearer" } },
  );
}
