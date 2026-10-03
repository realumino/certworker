-- Initial schema (PLAN.md section 6).

CREATE TABLE domains (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,              -- lowercase punycode; may start with "*."
  zone_id TEXT NOT NULL,
  include_wildcard INTEGER NOT NULL DEFAULT 1,
  key_type TEXT NOT NULL DEFAULT 'ecdsa_p256',
  renew_before_days INTEGER NOT NULL DEFAULT 30,
  preferred_chain TEXT,
  status TEXT NOT NULL DEFAULT 'active',  -- active | paused | deleted
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE certificates (
  id TEXT PRIMARY KEY,
  domain_id TEXT NOT NULL REFERENCES domains(id),
  env TEXT NOT NULL,                      -- staging | production
  serial TEXT NOT NULL,
  fingerprint_sha256 TEXT NOT NULL,
  sans_json TEXT NOT NULL,
  not_before TEXT NOT NULL,
  not_after TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  r2_prefix TEXT NOT NULL,
  status TEXT NOT NULL,                   -- current | superseded | revoked
  purged_at TEXT,                         -- set when R2 objects deleted
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_cert_current ON certificates(domain_id) WHERE status = 'current';

CREATE TABLE issue_runs (
  id TEXT PRIMARY KEY,
  domain_id TEXT NOT NULL REFERENCES domains(id),
  workflow_id TEXT NOT NULL,
  trigger TEXT NOT NULL,                  -- cron | manual | retry
  status TEXT NOT NULL,                   -- queued | running | succeeded | failed
  phase TEXT,
  error TEXT,                             -- LE error payload verbatim
  started_at TEXT,
  finished_at TEXT,
  steps_json TEXT
);
CREATE UNIQUE INDEX idx_run_active
  ON issue_runs(domain_id) WHERE status IN ('queued', 'running');

CREATE TABLE acme_accounts (
  id TEXT PRIMARY KEY,
  env TEXT NOT NULL UNIQUE,
  directory_url TEXT NOT NULL,
  account_url TEXT NOT NULL,
  key_r2_key TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE challenge_records (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES issue_runs(id),
  zone_id TEXT NOT NULL,
  cf_record_id TEXT NOT NULL,
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at TEXT NOT NULL,
  deleted_at TEXT
);

CREATE TABLE api_keys (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,                    -- node name by convention
  key_hash TEXT NOT NULL,                 -- SHA-256 hex of the secret part
  key_hint TEXT NOT NULL,                 -- cw_<id>...<last4>
  allowed_domains_json TEXT,              -- NULL = all domains
  status TEXT NOT NULL DEFAULT 'active',  -- active | revoked
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);

CREATE TABLE pull_events (
  id TEXT PRIMARY KEY,
  api_key_id TEXT NOT NULL REFERENCES api_keys(id),
  domain_id TEXT NOT NULL REFERENCES domains(id),
  certificate_id TEXT,
  ip TEXT,
  user_agent TEXT,
  status INTEGER NOT NULL,                -- HTTP status
  created_at TEXT NOT NULL
);

CREATE TABLE audit_log (
  id TEXT PRIMARY KEY,
  actor TEXT NOT NULL,                    -- Access email
  action TEXT NOT NULL,
  target TEXT,
  meta_json TEXT,
  created_at TEXT NOT NULL
);
