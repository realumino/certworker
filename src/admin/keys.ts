import { normalizeDomainName } from "../acme/dns01";
import { b64uEncode } from "../crypto/base64url";
import { sha256Hex } from "../crypto/keys";
import { createApiKey, findDomainByName, getApiKey, listApiKeys, revokeApiKey, updateApiKeyAllowedDomains, type ApiKeyRow } from "../store/d1";
import { recordAudit } from "./audit";
import type { AdminDependencies } from "./deps";
import {
  errorResponse,
  jsonResponse,
  parseJsonArray,
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

  const unknown = rejectUnknownFields(body, ["label", "allowed_domains"]);
  if (unknown) return unknown;

  const label = validLabel(body);
  if (label instanceof Response) return label;

  const scope = body.allowed_domains === undefined
    ? null
    : await validateAllowedDomains(deps, body.allowed_domains);
  if (scope instanceof Response) return scope;

  const { row, token } = await generateKeyRecord(deps, label, scope);
  await recordAudit(deps, "key.create", row.id, { label, allowed_domains: scope });
  return jsonResponse({ key: keyJson(row), token }, 201);
}

export async function updateKeyHandler(
  deps: AdminDependencies,
  request: Request,
  params: Record<string, string>,
): Promise<Response> {
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;

  const unknown = rejectUnknownFields(body, ["allowed_domains"]);
  if (unknown) return unknown;

  const current = await getApiKey(deps.db, params.id);
  if (!current) return errorResponse(404, "not_found", "API key not found");

  if (!("allowed_domains" in body)) {
    return errorResponse(400, "invalid_request", "allowed_domains is required (null for all domains)");
  }
  const scope = await validateAllowedDomains(deps, body.allowed_domains);
  if (scope instanceof Response) return scope;

  await updateApiKeyAllowedDomains(deps.db, current.id, scope === null ? null : JSON.stringify(scope));
  await recordAudit(deps, "key.update", current.id, { allowed_domains: scope });
  const updated = await getApiKey(deps.db, current.id);
  return jsonResponse({ key: keyJson(updated ?? current) });
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

  const { row, token } = await generateKeyRecord(deps, current.label, scopeFromRow(current));
  await revokeApiKey(deps.db, current.id); // no-op when already revoked
  await recordAudit(deps, "key.rotate", current.id, {
    new_key_id: row.id,
    label: current.label,
    allowed_domains: scopeFromRow(current),
  });
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

/** Parsed scope of a stored row: `null` = all domains; invalid JSON fails closed to `[]`. */
function scopeFromRow(row: ApiKeyRow): string[] | null {
  return row.allowed_domains_json === null ? null : parseJsonArray(row.allowed_domains_json);
}

/**
 * Validate the `allowed_domains` request field. `null` = all domains; otherwise
 * a non-empty array of names that must each normalize and resolve to a
 * non-deleted domain row. Returned names are unique and sorted.
 */
async function validateAllowedDomains(
  deps: AdminDependencies,
  value: unknown,
): Promise<string[] | null | Response> {
  if (value === null) return null;
  if (!Array.isArray(value)) {
    return errorResponse(400, "invalid_request", "allowed_domains must be null (all domains) or an array of domain names");
  }
  if (value.length === 0) {
    return errorResponse(400, "invalid_request", "allowed_domains must be null (all domains) or a non-empty array");
  }

  const names: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || item.trim().length === 0) {
      return errorResponse(400, "invalid_request", "allowed_domains entries must be non-empty strings");
    }
    try {
      names.push(normalizeDomainName(item));
    } catch {
      return errorResponse(400, "invalid_request", `${item} is not a valid domain name`);
    }
  }
  names.sort();

  const missing: string[] = [];
  for (const name of new Set(names)) {
    const domain = await findDomainByName(deps.db, name);
    if (!domain || domain.status === "deleted") missing.push(name);
  }
  if (missing.length > 0) {
    return errorResponse(400, "invalid_request", `Unknown or deleted domains: ${missing.join(", ")}`);
  }
  // names are sorted; collapse duplicates that normalize to the same name.
  return [...new Set(names)];
}

/**
 * Generate a `cw_<id>.<secret>` token. Only the SHA-256 hex of the secret is
 * stored; the plaintext token is returned exactly once to the caller.
 */
async function generateKeyRecord(
  deps: AdminDependencies,
  label: string,
  allowedDomains: string[] | null,
): Promise<{ row: ApiKeyRow; token: string }> {
  const id = crypto.randomUUID();
  const secret = b64uEncode(crypto.getRandomValues(new Uint8Array(SECRET_BYTES)));
  await createApiKey(deps.db, {
    id,
    label,
    key_hash: await sha256Hex(secret),
    key_hint: `cw_${id}…${secret.slice(-4)}`,
    allowed_domains_json: allowedDomains === null ? null : JSON.stringify(allowedDomains),
  });
  const row = await getApiKey(deps.db, id);
  if (!row) throw new Error(`API key ${id} is missing right after creation`);
  return { row, token: `cw_${id}.${secret}` };
}

function keyJson(row: ApiKeyRow): Record<string, unknown> {
  return {
    id: row.id,
    label: row.label,
    key_hint: row.key_hint,
    allowed_domains: scopeFromRow(row),
    status: row.status,
    created_at: row.created_at,
    last_used_at: row.last_used_at,
    revoked_at: row.revoked_at,
  };
}
