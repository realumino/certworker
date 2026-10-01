import { insertAuditLog, listAuditLog, type AuditLogRow } from "../store/d1";
import type { AdminDependencies } from "./deps";
import { jsonResponse, parseJsonValue, parsePagination } from "./http";

/**
 * Append-only audit trail for every admin mutation. Written after the mutation
 * itself: if this insert fails, the router returns 500 even though the mutation
 * applied, so a silently unaudited change never goes unnoticed.
 */
export async function recordAudit(
  deps: AdminDependencies,
  action: string,
  target: string | null,
  meta?: unknown,
): Promise<void> {
  await insertAuditLog(deps.db, { actor: deps.actor, action, target, meta });
}

export async function listAuditHandler(deps: AdminDependencies, request: Request): Promise<Response> {
  const url = new URL(request.url);
  const pagination = parsePagination(url);
  if (pagination instanceof Response) return pagination;

  const action = url.searchParams.get("action") ?? undefined;
  const rows = await listAuditLog(deps.db, { action, limit: pagination.limit, offset: pagination.offset });
  return jsonResponse(rows.map(auditJson));
}

function auditJson(row: AuditLogRow): Record<string, unknown> {
  return {
    id: row.id,
    actor: row.actor,
    action: row.action,
    target: row.target,
    meta: parseJsonValue(row.meta_json),
    created_at: row.created_at,
  };
}
