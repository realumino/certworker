import {
  getIssueRunWithDomain,
  listIssueRuns,
  type IssueRunRow,
  type IssueRunStatus,
  type IssueRunWithDomainRow,
} from "../store/d1";
import type { AdminDependencies } from "./deps";
import { errorResponse, jsonResponse, parseJsonValue, parsePagination } from "./http";

const RUN_STATUSES: readonly IssueRunStatus[] = ["queued", "running", "succeeded", "failed"];

export async function listRunsHandler(deps: AdminDependencies, request: Request): Promise<Response> {
  const url = new URL(request.url);
  const pagination = parsePagination(url);
  if (pagination instanceof Response) return pagination;

  const statusParam = url.searchParams.get("status");
  if (statusParam !== null && !RUN_STATUSES.includes(statusParam as IssueRunStatus)) {
    return errorResponse(400, "invalid_status", `status must be one of: ${RUN_STATUSES.join(", ")}`);
  }

  const rows = await listIssueRuns(deps.db, {
    domainId: url.searchParams.get("domain_id") ?? undefined,
    status: (statusParam as IssueRunStatus) ?? undefined,
    ...pagination,
  });
  return jsonResponse(rows.map(runJson));
}

export async function getRunHandler(
  deps: AdminDependencies,
  _request: Request,
  params: Record<string, string>,
): Promise<Response> {
  const row = await getIssueRunWithDomain(deps.db, params.id);
  if (!row) return errorResponse(404, "not_found", "Issue run not found");
  return jsonResponse(runJson(row));
}

function runJson(row: IssueRunRow & Partial<IssueRunWithDomainRow>): Record<string, unknown> {
  const steps = parseJsonValue(row.steps_json);
  return {
    id: row.id,
    domain_id: row.domain_id,
    ...(row.domain_name !== undefined ? { domain_name: row.domain_name } : {}),
    workflow_id: row.workflow_id,
    trigger: row.trigger,
    status: row.status,
    phase: row.phase,
    error: row.error,
    started_at: row.started_at,
    finished_at: row.finished_at,
    steps: Array.isArray(steps) ? steps : [],
  };
}
