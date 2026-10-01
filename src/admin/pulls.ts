import { listPullEvents, type PullEventWithNamesRow } from "../store/d1";
import type { AdminDependencies } from "./deps";
import { jsonResponse, parsePagination } from "./http";

export async function listPullsHandler(deps: AdminDependencies, request: Request): Promise<Response> {
  const url = new URL(request.url);
  const pagination = parsePagination(url);
  if (pagination instanceof Response) return pagination;

  const rows = await listPullEvents(deps.db, {
    apiKeyId: url.searchParams.get("api_key_id") ?? undefined,
    domainId: url.searchParams.get("domain_id") ?? undefined,
    ...pagination,
  });
  return jsonResponse(rows.map(pullJson));
}

function pullJson(row: PullEventWithNamesRow): Record<string, unknown> {
  return {
    id: row.id,
    api_key_id: row.api_key_id,
    api_key_label: row.api_key_label,
    domain_id: row.domain_id,
    domain_name: row.domain_name,
    certificate_id: row.certificate_id,
    ip: row.ip,
    user_agent: row.user_agent,
    status: row.status,
    created_at: row.created_at,
  };
}
