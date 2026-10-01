import { b64uEncode } from "../crypto/base64url";
import { sha256Hex } from "../crypto/keys";
import { createApiKey, getApiKey, listApiKeys, revokeApiKey, type ApiKeyRow } from "../store/d1";
import { recordAudit } from "./audit";
import type { AdminDependencies } from "./deps";
import {
  errorResponse,
  jsonResponse,
  parseJsonBody,
  parsePagination,
  rejectUnknownFields,
  requireString,
} from "./http";

const SECRET_BYTES = 32;
const LABEL_MAX_LENGTH = 64;

export async function listKeysHandler(deps: AdminDependencies, request: Request): Promise<Response> {
  const pagination = parsePagination(new URL(request.url));
  if (pagination instanceof Response) return pagination;
  const rows = await listApiKeys(deps.db, pagination);
  return jsonResponse(rows.map(keyJson));
}

export async function createKeyHandler(deps: AdminDependencies, request: Request): Promise<Response> {
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;

  const unknown = rejectUnknownFields(body, ["label"]);
  if (unknown) return unknown;

  const label = validLabel(body);
  if (label instanceof Response) return label;

  const { row, token } = await generateKeyRecord(deps, label);
  await recordAudit(deps, "key.create", row.id, { label });
  return jsonResponse({ key: keyJson(row), token }, 201);
}

export async function revokeKeyHandler(
  deps: AdminDependencies,
  _request: Request,
  params: Record<string, string>,
): Promise<Response> {
  const row = await getApiKey(deps.db, params.id);
  if (!row) return errorResponse(404, "not_found", "API key not found");

  if (await revokeApiKey(deps.db, row.id)) {
    await recordAudit(deps, "key.revoke", row.id, { label: row.label });
  }
  const updated = await getApiKey(deps.db, row.id);
  return jsonResponse({ key: keyJson(updated ?? row) });
}

export async function rotateKeyHandler(
  deps: AdminDependencies,
  _request: Request,
  params: Record<string, string>,
): Promise<Response> {
  const current = await getApiKey(deps.db, params.id);
  if (!current) return errorResponse(404, "not_found", "API key not found");

  const { row, token } = await generateKeyRecord(deps, current.label);
  await revokeApiKey(deps.db, current.id); // no-op when already revoked
  await recordAudit(deps, "key.rotate", current.id, { new_key_id: row.id, label: current.label });
  return jsonResponse({ key: keyJson(row), token }, 201);
}

function validLabel(body: Record<string, unknown>): string | Response {
  const label = requireString(body, "label");
  if (label instanceof Response) return label;
  if (label.length > LABEL_MAX_LENGTH) {
    return errorResponse(400, "invalid_request", `label must be at most ${LABEL_MAX_LENGTH} characters`);
  }
  if (/[\u0000-\u001f\u007f]/.test(label)) {
    return errorResponse(400, "invalid_request", "label must not contain control characters");
  }
  return label;
}

/**
 * Generate a `scw_<id>.<secret>` token. Only the SHA-256 hex of the secret is
 * stored; the plaintext token is returned exactly once to the caller.
 */
async function generateKeyRecord(deps: AdminDependencies, label: string): Promise<{ row: ApiKeyRow; token: string }> {
  const id = crypto.randomUUID();
  const secret = b64uEncode(crypto.getRandomValues(new Uint8Array(SECRET_BYTES)));
  await createApiKey(deps.db, {
    id,
    label,
    key_hash: await sha256Hex(secret),
    key_hint: `scw_${id}…${secret.slice(-4)}`,
    allowed_domains_json: null,
  });
  const row = await getApiKey(deps.db, id);
  if (!row) throw new Error(`API key ${id} is missing right after creation`);
  return { row, token: `scw_${id}.${secret}` };
}

function keyJson(row: ApiKeyRow): Record<string, unknown> {
  return {
    id: row.id,
    label: row.label,
    key_hint: row.key_hint,
    status: row.status,
    created_at: row.created_at,
    last_used_at: row.last_used_at,
    revoked_at: row.revoked_at,
  };
}
