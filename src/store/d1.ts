import type { AcmeEnvironment, IssueTrigger } from "../issue/types";

export type DomainStatus = "active" | "paused" | "deleted";
export type IssueRunStatus = "queued" | "running" | "succeeded" | "failed";
export type CertificateStatus = "current" | "superseded" | "revoked";

export interface DomainRow {
  id: string;
  name: string;
  zone_id: string;
  include_wildcard: number;
  key_type: string;
  renew_before_days: number;
  preferred_chain: string | null;
  status: DomainStatus;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

export interface CertificateRow {
  id: string;
  domain_id: string;
  env: AcmeEnvironment;
  serial: string;
  fingerprint_sha256: string;
  sans_json: string;
  not_before: string;
  not_after: string;
  issued_at: string;
  r2_prefix: string;
  status: CertificateStatus;
  purged_at: string | null;
  created_at: string;
}

export interface IssueRunRow {
  id: string;
  domain_id: string;
  workflow_id: string;
  trigger: IssueTrigger;
  status: IssueRunStatus;
  phase: string | null;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
  steps_json: string | null;
}

export interface AcmeAccountRow {
  id: string;
  env: AcmeEnvironment;
  directory_url: string;
  account_url: string;
  key_r2_key: string;
  created_at: string;
}

export interface ChallengeRecordRow {
  id: string;
  run_id: string;
  zone_id: string;
  cf_record_id: string;
  name: string;
  value: string;
  created_at: string;
  deleted_at: string | null;
}

export type ApiKeyStatus = "active" | "revoked";

export interface ApiKeyRow {
  id: string;
  label: string;
  key_hash: string;                     // SHA-256 hex of the secret part
  key_hint: string;                     // scw_<id>…<last4>
  allowed_domains_json: string | null;  // NULL = all domains
  status: ApiKeyStatus;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface PullEventRow {
  id: string;
  api_key_id: string;
  domain_id: string;
  certificate_id: string | null;
  ip: string | null;
  user_agent: string | null;
  status: number;
  created_at: string;
}

export interface AuditLogRow {
  id: string;
  actor: string;
  action: string;
  target: string | null;
  meta_json: string | null;
  created_at: string;
}

export class ActiveIssueRunError extends Error {
  constructor(domainId: string) {
    super(`An issue run is already active for domain ${domainId}`);
    this.name = "ActiveIssueRunError";
  }
}

export class DomainNameConflictError extends Error {
  constructor(name: string) {
    super(`A domain row already exists for ${name}`);
    this.name = "DomainNameConflictError";
  }
}

export async function getDomain(db: D1Database, id: string): Promise<DomainRow | null> {
  return db.prepare("SELECT * FROM domains WHERE id = ?").bind(id).first<DomainRow>();
}

export async function getCurrentCertificate(db: D1Database, domainId: string): Promise<CertificateRow | null> {
  return db.prepare(
    "SELECT * FROM certificates WHERE domain_id = ? AND status = 'current'",
  ).bind(domainId).first<CertificateRow>();
}

export async function getCertificate(db: D1Database, id: string): Promise<CertificateRow | null> {
  return db.prepare("SELECT * FROM certificates WHERE id = ?").bind(id).first<CertificateRow>();
}

export async function createIssueRun(
  db: D1Database,
  run: Pick<IssueRunRow, "id" | "domain_id" | "workflow_id" | "trigger">,
): Promise<void> {
  try {
    await db.prepare(
      `INSERT INTO issue_runs (id, domain_id, workflow_id, trigger, status)
       VALUES (?, ?, ?, ?, 'queued')`,
    ).bind(run.id, run.domain_id, run.workflow_id, run.trigger).run();
  } catch (error) {
    if (error instanceof Error && /idx_run_active|issue_runs\.domain_id/.test(error.message)) {
      throw new ActiveIssueRunError(run.domain_id);
    }
    throw error;
  }
}

export async function getIssueRun(db: D1Database, id: string): Promise<IssueRunRow | null> {
  return db.prepare("SELECT * FROM issue_runs WHERE id = ?").bind(id).first<IssueRunRow>();
}

/** Idempotency check for date-scoped cron workflow IDs (`renew-<domainId>-<date>`). */
export async function findIssueRunByWorkflowId(db: D1Database, workflowId: string): Promise<IssueRunRow | null> {
  return db.prepare("SELECT * FROM issue_runs WHERE workflow_id = ? ORDER BY rowid DESC LIMIT 1")
    .bind(workflowId)
    .first<IssueRunRow>();
}

export async function recordRunPhase(db: D1Database, runId: string, phase: string): Promise<void> {
  const row = await db.prepare("SELECT steps_json FROM issue_runs WHERE id = ?")
    .bind(runId)
    .first<{ steps_json: string | null }>();
  if (!row) throw new Error(`Issue run ${runId} does not exist`);

  const steps = parseSteps(row.steps_json);
  steps.push({ phase, at: new Date().toISOString() });
  const result = await db.prepare(
    `UPDATE issue_runs
        SET status = CASE WHEN status = 'queued' THEN 'running' ELSE status END,
            phase = ?,
            started_at = COALESCE(started_at, ?),
            steps_json = ?
      WHERE id = ? AND status IN ('queued', 'running')`,
  ).bind(phase, new Date().toISOString(), JSON.stringify(steps), runId).run();

  if (result.meta.changes !== 1) throw new Error(`Issue run ${runId} is no longer active`);
}

export async function finishIssueRun(
  db: D1Database,
  runId: string,
  domainId: string,
  outcome: { status: "succeeded" } | { status: "failed"; error: string },
): Promise<void> {
  const existing = await getIssueRun(db, runId);
  if (!existing) throw new Error(`Issue run ${runId} does not exist`);
  if (existing.finished_at !== null) {
    if (existing.status === outcome.status) return;
    throw new Error(`Issue run ${runId} already finished as ${existing.status}`);
  }

  const finishedAt = new Date().toISOString();
  const phase = outcome.status === "succeeded" ? "complete" : "failed";
  const steps = parseSteps(existing.steps_json);
  steps.push({ phase, at: finishedAt });
  const error = outcome.status === "failed" ? outcome.error : null;
  const results = await db.batch([
    db.prepare(
      `UPDATE issue_runs
          SET status = ?, phase = ?, error = ?, finished_at = ?, steps_json = ?
        WHERE id = ? AND finished_at IS NULL`,
    ).bind(outcome.status, phase, error, finishedAt, JSON.stringify(steps), runId),
    db.prepare("UPDATE domains SET last_error = ?, updated_at = ? WHERE id = ?")
      .bind(error, finishedAt, domainId),
  ]);

  if (results[0].meta.changes !== 1) throw new Error(`Issue run ${runId} could not be finalized`);
}

export async function getAcmeAccount(db: D1Database, environment: AcmeEnvironment): Promise<AcmeAccountRow | null> {
  return db.prepare("SELECT * FROM acme_accounts WHERE env = ?")
    .bind(environment)
    .first<AcmeAccountRow>();
}

export async function saveAcmeAccount(
  db: D1Database,
  account: Omit<AcmeAccountRow, "created_at">,
): Promise<void> {
  await db.prepare(
    `INSERT INTO acme_accounts (id, env, directory_url, account_url, key_r2_key, created_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(env) DO UPDATE SET
       directory_url = excluded.directory_url,
       account_url = excluded.account_url,
       key_r2_key = excluded.key_r2_key`,
  ).bind(
    account.id,
    account.env,
    account.directory_url,
    account.account_url,
    account.key_r2_key,
    new Date().toISOString(),
  ).run();
}

export async function insertChallengeRecord(
  db: D1Database,
  record: Pick<ChallengeRecordRow, "id" | "run_id" | "zone_id" | "cf_record_id" | "name" | "value">,
): Promise<void> {
  await db.prepare(
    `INSERT INTO challenge_records (id, run_id, zone_id, cf_record_id, name, value, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    record.id,
    record.run_id,
    record.zone_id,
    record.cf_record_id,
    record.name,
    record.value,
    new Date().toISOString(),
  ).run();
}

export async function listPendingChallengeRecords(
  db: D1Database,
  runId: string,
): Promise<ChallengeRecordRow[]> {
  const { results } = await db.prepare(
    `SELECT * FROM challenge_records
      WHERE run_id = ? AND deleted_at IS NULL
      ORDER BY created_at, id`,
  ).bind(runId).all<ChallengeRecordRow>();
  return results;
}

export async function findPendingChallengeRecord(
  db: D1Database,
  runId: string,
  name: string,
  value: string,
): Promise<ChallengeRecordRow | null> {
  return db.prepare(
    `SELECT * FROM challenge_records
      WHERE run_id = ? AND name = ? AND value = ? AND deleted_at IS NULL
      ORDER BY created_at LIMIT 1`,
  ).bind(runId, name, value).first<ChallengeRecordRow>();
}

export async function markChallengeRecordDeleted(db: D1Database, id: string): Promise<void> {
  await db.prepare(
    "UPDATE challenge_records SET deleted_at = COALESCE(deleted_at, ?) WHERE id = ?",
  ).bind(new Date().toISOString(), id).run();
}

export async function activateCertificate(db: D1Database, certificate: CertificateRow): Promise<void> {
  const existing = await getCertificate(db, certificate.id);
  if (existing) {
    if (
      existing.domain_id !== certificate.domain_id ||
      existing.fingerprint_sha256 !== certificate.fingerprint_sha256
    ) {
      throw new Error(`Certificate id ${certificate.id} is already in use`);
    }
    // A retry after the D1 commit must not re-activate an older certificate.
    return;
  }

  await db.batch([
    db.prepare(
      "UPDATE certificates SET status = 'superseded' WHERE domain_id = ? AND status = 'current'",
    ).bind(certificate.domain_id),
    db.prepare(
      `INSERT INTO certificates (
         id, domain_id, env, serial, fingerprint_sha256, sans_json, not_before, not_after,
         issued_at, r2_prefix, status, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'current', ?)`,
    ).bind(
      certificate.id,
      certificate.domain_id,
      certificate.env,
      certificate.serial,
      certificate.fingerprint_sha256,
      certificate.sans_json,
      certificate.not_before,
      certificate.not_after,
      certificate.issued_at,
      certificate.r2_prefix,
      certificate.created_at,
    ),
  ]);
}

export async function markCertificatePurged(db: D1Database, id: string): Promise<void> {
  const result = await db.prepare(
    `UPDATE certificates
        SET purged_at = COALESCE(purged_at, ?)
      WHERE id = ? AND status != 'current'`,
  ).bind(new Date().toISOString(), id).run();
  if (result.meta.changes !== 1) throw new Error(`Certificate ${id} was not eligible to mark purged`);
}

/** Flip a certificate to `revoked`; false when another caller already did it. */
export async function markCertificateRevoked(db: D1Database, id: string): Promise<boolean> {
  const result = await db.prepare(
    "UPDATE certificates SET status = 'revoked' WHERE id = ? AND status != 'revoked'",
  ).bind(id).run();
  return result.meta.changes === 1;
}

export interface DomainWithCertificateRow extends DomainRow {
  certificate_id: string | null;
  certificate_env: string | null;
  certificate_serial: string | null;
  certificate_sans_json: string | null;
  certificate_not_before: string | null;
  certificate_not_after: string | null;
  certificate_fingerprint_sha256: string | null;
}

export interface IssueRunWithDomainRow extends IssueRunRow {
  domain_name: string;
}

export interface CertificateWithDomainRow extends CertificateRow {
  domain_name: string;
}

export interface PullEventWithNamesRow extends PullEventRow {
  api_key_label: string;
  domain_name: string;
}

export interface OverviewStats {
  domains: { active: number; paused: number; deleted: number; total: number };
  certificates: { current: number; expiringSoon: number; nextExpiry: string | null };
  runs: {
    queued: number;
    running: number;
    failedLastDay: number;
    latestFailure: {
      id: string;
      domain_id: string;
      error: string | null;
      finished_at: string | null;
    } | null;
  };
  keys: { active: number; revoked: number; lastUsedAt: string | null };
}

export async function insertAuditLog(
  db: D1Database,
  entry: { actor: string; action: string; target?: string | null; meta?: unknown },
): Promise<void> {
  await db.prepare(
    `INSERT INTO audit_log (id, actor, action, target, meta_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).bind(
    crypto.randomUUID(),
    entry.actor,
    entry.action,
    entry.target ?? null,
    entry.meta === undefined ? null : JSON.stringify(entry.meta),
    new Date().toISOString(),
  ).run();
}

export async function listAuditLog(
  db: D1Database,
  options: { action?: string; limit: number; offset: number },
): Promise<AuditLogRow[]> {
  const actionFilter = options.action === undefined ? "" : " WHERE action = ?";
  const { results } = await db.prepare(
    `SELECT * FROM audit_log${actionFilter} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`,
  )
    .bind(...(options.action === undefined ? [] : [options.action]), options.limit, options.offset)
    .all<AuditLogRow>();
  return results;
}

export async function findDomainByName(db: D1Database, name: string): Promise<DomainRow | null> {
  return db.prepare("SELECT * FROM domains WHERE name = ?").bind(name).first<DomainRow>();
}

export async function createDomain(
  db: D1Database,
  domain: Pick<DomainRow, "id" | "name" | "zone_id" | "include_wildcard" | "renew_before_days">,
): Promise<void> {
  try {
    await db.prepare(
      `INSERT INTO domains (
         id, name, zone_id, include_wildcard, key_type, renew_before_days,
         preferred_chain, status, last_error, created_at, updated_at
       ) VALUES (?, ?, ?, ?, 'ecdsa_p256', ?, NULL, 'active', NULL, ?, ?)`,
    ).bind(
      domain.id,
      domain.name,
      domain.zone_id,
      domain.include_wildcard,
      domain.renew_before_days,
      new Date().toISOString(),
      new Date().toISOString(),
    ).run();
  } catch (error) {
    if (error instanceof Error && /UNIQUE constraint failed:\s*domains\.name/.test(error.message)) {
      throw new DomainNameConflictError(domain.name);
    }
    throw error;
  }
}

export async function updateDomainSettings(
  db: D1Database,
  id: string,
  settings: Pick<DomainRow, "include_wildcard" | "renew_before_days" | "status">,
): Promise<void> {
  await db.prepare(
    `UPDATE domains
        SET include_wildcard = ?, renew_before_days = ?, status = ?, updated_at = ?
      WHERE id = ? AND status != 'deleted'`,
  ).bind(
    settings.include_wildcard,
    settings.renew_before_days,
    settings.status,
    new Date().toISOString(),
    id,
  ).run();
}

export async function softDeleteDomain(db: D1Database, id: string): Promise<boolean> {
  const result = await db.prepare(
    "UPDATE domains SET status = 'deleted', updated_at = ? WHERE id = ? AND status != 'deleted'",
  ).bind(new Date().toISOString(), id).run();
  return result.meta.changes === 1;
}

export async function listDomains(
  db: D1Database,
  options: { status?: DomainStatus; limit: number; offset: number },
): Promise<DomainWithCertificateRow[]> {
  // Default listing hides soft-deleted rows; ask for one status explicitly to see them.
  const statusFilter = options.status === undefined ? " WHERE d.status != 'deleted'" : " WHERE d.status = ?";
  const { results } = await db.prepare(
    `SELECT d.id, d.name, d.zone_id, d.include_wildcard, d.key_type, d.renew_before_days,
            d.preferred_chain, d.status, d.last_error, d.created_at, d.updated_at,
            c.id AS certificate_id, c.env AS certificate_env, c.serial AS certificate_serial,
            c.sans_json AS certificate_sans_json, c.not_before AS certificate_not_before,
            c.not_after AS certificate_not_after, c.fingerprint_sha256 AS certificate_fingerprint_sha256
       FROM domains d
       LEFT JOIN certificates c ON c.domain_id = d.id AND c.status = 'current'${statusFilter}
      ORDER BY d.name LIMIT ? OFFSET ?`,
  )
    .bind(...(options.status === undefined ? [] : [options.status]), options.limit, options.offset)
    .all<DomainWithCertificateRow>();
  return results;
}

export async function findActiveIssueRun(db: D1Database, domainId: string): Promise<IssueRunRow | null> {
  return db.prepare(
    `SELECT * FROM issue_runs
      WHERE domain_id = ? AND status IN ('queued', 'running')
      ORDER BY rowid DESC LIMIT 1`,
  ).bind(domainId).first<IssueRunRow>();
}

export async function getIssueRunWithDomain(db: D1Database, id: string): Promise<IssueRunWithDomainRow | null> {
  return db.prepare(
    "SELECT r.*, d.name AS domain_name FROM issue_runs r JOIN domains d ON d.id = r.domain_id WHERE r.id = ?",
  ).bind(id).first<IssueRunWithDomainRow>();
}

export async function listIssueRuns(
  db: D1Database,
  options: { domainId?: string; status?: IssueRunStatus; limit: number; offset: number },
): Promise<IssueRunWithDomainRow[]> {
  const filters = [
    ...(options.domainId === undefined ? [] : ["r.domain_id = ?"]),
    ...(options.status === undefined ? [] : ["r.status = ?"]),
  ];
  const where = filters.length === 0 ? "" : ` WHERE ${filters.join(" AND ")}`;
  const { results } = await db.prepare(
    `SELECT r.*, d.name AS domain_name
       FROM issue_runs r JOIN domains d ON d.id = r.domain_id${where}
      ORDER BY r.rowid DESC LIMIT ? OFFSET ?`,
  )
    .bind(
      ...[options.domainId, options.status].filter((value): value is string => value !== undefined),
      options.limit,
      options.offset,
    )
    .all<IssueRunWithDomainRow>();
  return results;
}

export async function listCertificates(
  db: D1Database,
  options: { domainId?: string; status?: CertificateStatus; limit: number; offset: number },
): Promise<CertificateWithDomainRow[]> {
  const filters = [
    ...(options.domainId === undefined ? [] : ["c.domain_id = ?"]),
    ...(options.status === undefined ? [] : ["c.status = ?"]),
  ];
  const where = filters.length === 0 ? "" : ` WHERE ${filters.join(" AND ")}`;
  const { results } = await db.prepare(
    `SELECT c.*, d.name AS domain_name
       FROM certificates c JOIN domains d ON d.id = c.domain_id${where}
      ORDER BY c.created_at DESC, c.id DESC LIMIT ? OFFSET ?`,
  )
    .bind(
      ...[options.domainId, options.status].filter((value): value is string => value !== undefined),
      options.limit,
      options.offset,
    )
    .all<CertificateWithDomainRow>();
  return results;
}

export async function getApiKey(db: D1Database, id: string): Promise<ApiKeyRow | null> {
  return db.prepare("SELECT * FROM api_keys WHERE id = ?").bind(id).first<ApiKeyRow>();
}

export async function listApiKeys(
  db: D1Database,
  options: { limit: number; offset: number },
): Promise<ApiKeyRow[]> {
  const { results } = await db.prepare(
    "SELECT * FROM api_keys ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
  ).bind(options.limit, options.offset).all<ApiKeyRow>();
  return results;
}

export async function createApiKey(
  db: D1Database,
  key: Pick<ApiKeyRow, "id" | "label" | "key_hash" | "key_hint" | "allowed_domains_json">,
): Promise<void> {
  await db.prepare(
    `INSERT INTO api_keys (id, label, key_hash, key_hint, allowed_domains_json, status, created_at)
     VALUES (?, ?, ?, ?, ?, 'active', ?)`,
  ).bind(
    key.id,
    key.label,
    key.key_hash,
    key.key_hint,
    key.allowed_domains_json,
    new Date().toISOString(),
  ).run();
}

export async function revokeApiKey(db: D1Database, id: string): Promise<boolean> {
  const result = await db.prepare(
    `UPDATE api_keys
        SET status = 'revoked', revoked_at = ?
      WHERE id = ? AND status = 'active'`,
  ).bind(new Date().toISOString(), id).run();
  return result.meta.changes === 1;
}

/** All non-deleted domains with their current certificate (no pagination; one node scale). */
export async function listDomainsForPull(db: D1Database): Promise<DomainWithCertificateRow[]> {
  const { results } = await db.prepare(
    `SELECT d.id, d.name, d.zone_id, d.include_wildcard, d.key_type, d.renew_before_days,
            d.preferred_chain, d.status, d.last_error, d.created_at, d.updated_at,
            c.id AS certificate_id, c.env AS certificate_env, c.serial AS certificate_serial,
            c.sans_json AS certificate_sans_json, c.not_before AS certificate_not_before,
            c.not_after AS certificate_not_after, c.fingerprint_sha256 AS certificate_fingerprint_sha256
       FROM domains d
       LEFT JOIN certificates c ON c.domain_id = d.id AND c.status = 'current'
      WHERE d.status != 'deleted'
      ORDER BY d.name`,
  ).all<DomainWithCertificateRow>();
  return results;
}

/**
 * Active domains whose current certificate is missing or expires before
 * `renew_before_days` from `nowIso`. The per-row window is applied inside the
 * date modifier, so a single statement handles both triggers.
 */
export async function listDueDomains(db: D1Database, nowIso: string): Promise<DomainRow[]> {
  const { results } = await db.prepare(
    `SELECT d.*
       FROM domains d
       LEFT JOIN certificates c ON c.domain_id = d.id AND c.status = 'current'
      WHERE d.status = 'active'
        AND (c.id IS NULL OR datetime(c.not_after) <= datetime(?, '+' || d.renew_before_days || ' days'))
      ORDER BY COALESCE(c.not_after, '') ASC, d.name`,
  ).bind(nowIso).all<DomainRow>();
  return results;
}

/** Superseded/revoked certificates whose R2 artifacts may still exist. */
export async function listUnpurgedCertificates(db: D1Database): Promise<CertificateRow[]> {
  const { results } = await db.prepare(
    "SELECT * FROM certificates WHERE purged_at IS NULL AND status != 'current' ORDER BY created_at, id",
  ).all<CertificateRow>();
  return results;
}

/**
 * Published TXT records the sweeper must clean: untouched by their run for
 * longer than the cutoff (a live run's DNS timeout is minutes, the cutoff is 24 h).
 */
export async function listStaleChallengeRecords(db: D1Database, cutoffIso: string): Promise<ChallengeRecordRow[]> {
  const { results } = await db.prepare(
    `SELECT * FROM challenge_records
      WHERE deleted_at IS NULL AND created_at < ? AND name LIKE '\\_acme-challenge.%' ESCAPE '\\'
      ORDER BY created_at, id`,
  ).bind(cutoffIso).all<ChallengeRecordRow>();
  return results;
}

export async function listPullEvents(
  db: D1Database,
  options: { apiKeyId?: string; domainId?: string; limit: number; offset: number },
): Promise<PullEventWithNamesRow[]> {
  const filters = [
    ...(options.apiKeyId === undefined ? [] : ["p.api_key_id = ?"]),
    ...(options.domainId === undefined ? [] : ["p.domain_id = ?"]),
  ];
  const where = filters.length === 0 ? "" : ` WHERE ${filters.join(" AND ")}`;
  const { results } = await db.prepare(
    `SELECT p.*, k.label AS api_key_label, d.name AS domain_name
       FROM pull_events p
       JOIN api_keys k ON k.id = p.api_key_id
       JOIN domains d ON d.id = p.domain_id${where}
      ORDER BY p.created_at DESC, p.id DESC LIMIT ? OFFSET ?`,
  )
    .bind(
      ...[options.apiKeyId, options.domainId].filter((value): value is string => value !== undefined),
      options.limit,
      options.offset,
    )
    .all<PullEventWithNamesRow>();
  return results;
}

export async function getOverview(db: D1Database, now: Date): Promise<OverviewStats> {
  const nowIso = now.toISOString();
  const expiringThreshold = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
  const [domainCounts, certificateTotals, expiring, activeRuns, failedRuns, latestFailure, keyCounts, keyLastUse] =
    await db.batch([
      db.prepare("SELECT status, COUNT(*) AS count FROM domains GROUP BY status"),
      db.prepare(
        "SELECT COUNT(*) AS count, MIN(not_after) AS next_expiry FROM certificates WHERE status = 'current'",
      ),
      db.prepare("SELECT COUNT(*) AS count FROM certificates WHERE status = 'current' AND not_after <= ?")
        .bind(expiringThreshold),
      db.prepare("SELECT status, COUNT(*) AS count FROM issue_runs WHERE status IN ('queued', 'running') GROUP BY status"),
      db.prepare("SELECT COUNT(*) AS count FROM issue_runs WHERE status = 'failed' AND finished_at >= ?")
        .bind(dayAgo),
      db.prepare(
        `SELECT id, domain_id, error, finished_at FROM issue_runs
          WHERE status = 'failed'
          ORDER BY COALESCE(finished_at, '') DESC, rowid DESC LIMIT 1`,
      ),
      db.prepare("SELECT status, COUNT(*) AS count FROM api_keys GROUP BY status"),
      db.prepare("SELECT MAX(last_used_at) AS last_used_at FROM api_keys"),
    ]);

  const domainsByStatus = countByStatus(domainCounts.results);
  const runsByStatus = countByStatus(activeRuns.results);
  const keysByStatus = countByStatus(keyCounts.results);
  const latestFailureRow = latestFailure.results[0] as
    | { id: string; domain_id: string; error: string | null; finished_at: string | null }
    | undefined;

  return {
    domains: {
      active: domainsByStatus.active ?? 0,
      paused: domainsByStatus.paused ?? 0,
      deleted: domainsByStatus.deleted ?? 0,
      total: (domainsByStatus.active ?? 0) + (domainsByStatus.paused ?? 0) + (domainsByStatus.deleted ?? 0),
    },
    certificates: {
      current: scalarCount(certificateTotals.results),
      expiringSoon: scalarCount(expiring.results),
      nextExpiry: (certificateTotals.results[0] as { next_expiry?: string | null } | undefined)?.next_expiry ?? null,
    },
    runs: {
      queued: runsByStatus.queued ?? 0,
      running: runsByStatus.running ?? 0,
      failedLastDay: scalarCount(failedRuns.results),
      latestFailure: latestFailureRow ?? null,
    },
    keys: {
      active: keysByStatus.active ?? 0,
      revoked: keysByStatus.revoked ?? 0,
      lastUsedAt: (keyLastUse.results[0] as { last_used_at?: string | null } | undefined)?.last_used_at ?? null,
    },
  };
}

function countByStatus(results: unknown[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const row of results) {
    if (typeof row === "object" && row !== null) {
      const { status, count } = row as { status?: unknown; count?: unknown };
      if (typeof status === "string" && typeof count === "number") counts[status] = count;
    }
  }
  return counts;
}

function scalarCount(results: unknown[]): number {
  const row = results[0];
  if (typeof row === "object" && row !== null) {
    const { count } = row as { count?: unknown };
    if (typeof count === "number") return count;
  }
  return 0;
}

function parseSteps(value: string | null): Array<Record<string, string>> {
  if (value === null || value.length === 0) return [];
  const parsed: unknown = JSON.parse(value);
  if (!Array.isArray(parsed) || !parsed.every(isObject)) {
    throw new TypeError("Issue run steps_json must be a JSON array of objects");
  }
  return parsed;
}

function isObject(value: unknown): value is Record<string, string> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
