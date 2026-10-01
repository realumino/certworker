/**
 * Response shapes of the admin API (src/admin/*.ts `*Json` mappers). Keep these
 * in sync with the handlers; they are the SPA's only data contract.
 */

export type DomainStatus = "active" | "paused" | "deleted";
export type CertificateStatus = "current" | "superseded" | "revoked";
export type IssueRunStatus = "queued" | "running" | "succeeded" | "failed";
export type IssueTrigger = "cron" | "manual" | "retry";
export type ApiKeyStatus = "active" | "revoked";
export type AcmeEnvironment = "staging" | "production";

export interface CurrentCertificate {
  id: string;
  env: AcmeEnvironment;
  serial: string;
  sans: string[];
  not_after: string;
}

export interface Domain {
  id: string;
  name: string;
  zone_id: string;
  include_wildcard: boolean;
  key_type: string;
  renew_before_days: number;
  preferred_chain: string | null;
  status: DomainStatus;
  last_error: string | null;
  created_at: string;
  updated_at: string;
  current_certificate: CurrentCertificate | null;
}

export interface Certificate {
  id: string;
  domain_id: string;
  domain_name?: string;
  env: AcmeEnvironment;
  serial: string;
  fingerprint_sha256: string;
  sans: string[];
  not_before: string;
  not_after: string;
  issued_at: string;
  r2_prefix: string;
  status: CertificateStatus;
  purged_at: string | null;
  created_at: string;
}

export interface IssueRunStep {
  phase: string;
  at: string;
}

export interface IssueRun {
  id: string;
  domain_id: string;
  domain_name?: string;
  workflow_id: string;
  trigger: IssueTrigger;
  status: IssueRunStatus;
  phase: string | null;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
  steps: IssueRunStep[];
}

export interface ApiKey {
  id: string;
  label: string;
  key_hint: string;
  status: ApiKeyStatus;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

/** POST /api/keys and POST /api/keys/:id/rotate — `token` is returned exactly once. */
export interface CreatedApiKey {
  key: ApiKey;
  token: string;
}

export interface PullEvent {
  id: string;
  api_key_id: string;
  api_key_label: string;
  domain_id: string;
  domain_name: string;
  certificate_id: string | null;
  ip: string | null;
  user_agent: string | null;
  status: number;
  created_at: string;
}

export interface AuditEntry {
  id: string;
  actor: string;
  action: string;
  target: string | null;
  meta: unknown;
  created_at: string;
}

export interface Zone {
  id: string;
  name: string;
  status: string | null;
}

export interface Overview {
  domains: { active: number; paused: number; deleted: number; total: number };
  certificates: { current: number; expiring_within_30_days: number; next_expiry: string | null };
  runs: {
    queued: number;
    running: number;
    failed_last_24h: number;
    latest_failure: { id: string; domain_id: string; error: string | null; finished_at: string | null } | null;
  };
  keys: { active: number; revoked: number; last_used_at: string | null };
}

export interface IssuedRun {
  run_id: string;
  workflow_id: string;
  status: string;
}
