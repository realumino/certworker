import type { IssueTrigger } from "../../src/issue/types";
import { createIssueRun, type DomainRow } from "../../src/store/d1";

export async function seedDomain(
  db: D1Database,
  options: {
    name?: string;
    status?: DomainRow["status"];
    includeWildcard?: boolean;
    zoneId?: string;
    renewBeforeDays?: number;
  } = {},
): Promise<DomainRow> {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const domain: DomainRow = {
    id,
    name: options.name ?? `test-${id.slice(0, 8)}.example.com`,
    zone_id: options.zoneId ?? "zone-test",
    include_wildcard: options.includeWildcard === false ? 0 : 1,
    key_type: "ecdsa_p256",
    renew_before_days: options.renewBeforeDays ?? 30,
    preferred_chain: null,
    status: options.status ?? "active",
    last_error: null,
    created_at: now,
    updated_at: now,
  };
  await db.prepare(
    `INSERT INTO domains (
       id, name, zone_id, include_wildcard, key_type, renew_before_days,
       preferred_chain, status, last_error, created_at, updated_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    domain.id,
    domain.name,
    domain.zone_id,
    domain.include_wildcard,
    domain.key_type,
    domain.renew_before_days,
    domain.preferred_chain,
    domain.status,
    domain.last_error,
    domain.created_at,
    domain.updated_at,
  ).run();
  return domain;
}

export async function seedIssueRun(
  db: D1Database,
  domainId: string,
  trigger: IssueTrigger = "manual",
): Promise<{ runId: string; workflowId: string }> {
  const runId = crypto.randomUUID();
  const workflowId = `${trigger}-${runId}`;
  await createIssueRun(db, {
    id: runId,
    domain_id: domainId,
    workflow_id: workflowId,
    trigger,
  });
  return { runId, workflowId };
}
