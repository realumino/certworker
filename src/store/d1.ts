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

export class ActiveIssueRunError extends Error {
  constructor(domainId: string) {
    super(`An issue run is already active for domain ${domainId}`);
    this.name = "ActiveIssueRunError";
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
