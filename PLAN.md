# SSL Certificate Issuer & Distributor — Implementation Plan

A Cloudflare Worker that issues TLS certificates from Let's Encrypt (ACME v2, DNS-01
via the Cloudflare DNS API), stores them in R2, and distributes them to nodes that
pull periodically using per-node API keys. Admin surface is protected by Cloudflare
Access; there is no application-level user login.

Status: **M0–M6 complete. M2 live staging acceptance is still pending. M6 adds the node pull API (`/v1` bearer keys, ETag/304, per-key rate limit, pull events, `last_used_at` tracking). M7 adds certificate revocation, the DELETE-domain revoke step, and the daily renewal cron; M8 ships the node agent + runbook.**

---

## 1. Overview

**Goal.** One deployable Worker that:

1. Maintains a table of domains to issue (cert + private key generated server-side).
2. Issues/renews via Let's Encrypt with DNS-01 challenges recorded in Cloudflare DNS.
3. Stores certificate, chain, and encrypted private key in R2; metadata in D1.
4. Distributes the **exact same cert and key** to nodes over a pull API authenticated
   with one API key per node.
5. Renews automatically on a daily cron. Nodes poll; the server never notifies them.
6. Exposes an admin panel (SPA) for domains, runs, certificates, API keys, and pulls.

**Non-goals.** No push/notification to nodes. No per-node unique keys (identical
distribution is a requirement). No application user auth (Access only). No RSA keys
in v1 (ECDSA P-256 only). No non-Cloudflare DNS providers in v1 (a `DnsProvider`
abstraction may be introduced later). No expiry-notification emails (Let's Encrypt
removed them in 2025; the dashboard is the notification surface).

**Platform requirement.** Workers **Paid** plan: the free tier's 10 ms CPU limit
cannot perform issuance (EC/CSR/JWS crypto work), and Workflows/Queues features used
here require Paid.

---

## 2. Architecture

One Worker, one deployable, **one hostname**: `ssl.example.com`.

```
 admin browser ──▶ ssl.example.com                  Access app A: Allow (IdP/email)
                    ├─ /*      → Static Assets (SPA)      (protected)
                    └─ /api/*  → Admin API                JWT re-verified in Worker

 node agent ──────▶ ssl.example.com/v1/*             Access app B: Bypass (public)
 (systemd timer)        │                              Worker requires API key
                        ▼
                  CertificateWorkflow (durable steps, per run)
                   create order → publish TXT → wait → validate
                   → finalize → store → purge previous → cleanup
                        │
        ┌───────────────┼─────────────────┬────────────────────┐
        ▼               ▼                 ▼                    ▼
   Let's Encrypt   Cloudflare DNS   D1 (metadata)        R2 (PEMs + encrypted keys)
    ACME v2          TXT records    issue runs, keys      certs/<domain>/<cert-id>/
                                   audit, pull events
                   daily cron ──▶ creates workflow instances for due domains
```

### Routing

| Path | Handler | Access app | Worker-side check |
|---|---|---|---|
| `/`, SPA routes | Static Assets (`ASSETS`) | A (`ssl.example.com`) | — |
| `/api/*` | Admin API | A (`ssl.example.com`) | Access JWT (`iss` + `aud`) |
| `/v1/*` | Node pull API | B (`ssl.example.com/v1`) | API key (`Bearer scw_…`) |

Access evaluates the most specific path first, so `/v1/*` uses app B and never
redirects to login. The layering is deliberately asymmetric:

- If app B is deleted or mis-scoped, node pulls fail loudly (login redirect / 403 HTML)
  while admin is unaffected.
- If app A is ever misconfigured, the Worker's JWT verification still rejects `/api/*`.
- Access does not log bypassed traffic; `pull_events` in D1 is the pull log, and zone
  WAF/rate rules still apply to `/v1`.

Optional hardening (off by default, no code change): give app B a **Service Auth**
policy instead of Bypass, so nodes additionally present `CF-Access-Client-Id/Secret`.

---

## 3. Locked decisions

| Decision | Choice |
|---|---|
| Challenge type | DNS-01 only (mandatory for wildcards; no inbound HTTP) |
| DNS provider | Cloudflare DNS API, scoped token (`Zone:DNS:Edit` + `Zone:Zone:Read`) |
| Deployment shape | Single Worker — UI assets + admin API + node API in one script |
| Hostname | One: `ssl.example.com` (path-scoped Access apps) |
| Admin auth | Cloudflare Access + Worker-side JWT verification |
| Node auth | Bearer API key, **one key = one node**; no separate node entity |
| Leaf key type | ECDSA P-256 |
| Wildcard | Option per domain row, **default on**; explicit `*.` input = wildcard only |
| Old certificate | Purged immediately after the new cert is live |
| Revocation | Implemented now: endpoint + auto-revoke on domain deletion |
| Node agent | Shell script + systemd timer (reference implementation in repo) |
| Failure alerting | Deferred |
| Scale | One node today; multi-key/multi-domain design retained |

---

## 4. Domain & certificate rules

Input is a DNS name; lowercase punycode is the storage form.

| Input row | `include_wildcard` | SANs issued |
|---|---|---|
| `example.com` | on (default) | `example.com`, `*.example.com` |
| `example.com` | off | `example.com` |
| `*.example.com` | n/a (toggle hidden) | `*.example.com` only |

Validation rejects: `*.*.x`, `*x.com`, `x.*`, underscores, IPs, trailing dots,
uppercase (normalized), and names whose zone is not reachable with the scoped DNS
token. The apex+wildcard case is a single order with two authorizations on the same
`_acme-challenge.example.com` name; the workflow creates two TXT records by ID and
waits for both values.

---

## 5. ACME engine

All crypto uses Web Crypto; no Node built-ins.

- Leaf and account keys: ECDSA P-256 via `crypto.subtle.generateKey`.
- JWS: ES256. Web Crypto returns raw `r‖s`, exactly JOSE's format (no DER conversion).
  Protected header carries `jwk` for `newAccount`, `kid` afterwards.
- Thumbprint: SHA-256 of the canonical JWK. DNS-01 value:
  `base64url(SHA-256(token + "." + thumbprint))`.
- CSR: `@peculiar/x509` v2 `Pkcs10CertificateRequestGenerator` with a SAN extension
  for all identifiers. Fallback if it misbehaves in workerd: hand-built ASN.1 CSR —
  the signature call is the same.
- M1 validation: `@peculiar/x509@2.1.0` works in workerd when `@abraham/reflection` is
  imported first; the hand-built CSR fallback is not required.
- Certificate parsing (serial, `notAfter`, SANs): `new x509.X509Certificate(pem)`.

Protocol details:

- Directory: staging `https://acme-staging-v02.api.letsencrypt.org/directory`;
  production `https://acme-v02.api.letsencrypt.org/directory`. Per-environment var;
  local dev and tests always staging.
- `newAccount` once per environment; persist account URL + encrypted key in R2.
- All GETs are POST-as-GET (RFC 8555). Take `Replay-Nonce` from every response; on
  `urn:ietf:params:acme:error:badNonce`, refresh the nonce and retry once.
- Honor `Retry-After` on challenge/order polling. Classify
  `urn:ietf:params:acme:error:rateLimited` separately so the dashboard can say
  "CA rate limit — back off" instead of "bug".
- TXT record name: `_acme-challenge.<identifier>` with `*.` stripped. Create via the
  DNS API and keep record IDs; delete by ID during compensation.
- Propagation: poll DoH (`https://cloudflare-dns.com/dns-query?type=TXT&name=…` plus
  `8.8.8.8` as a second resolver) until every expected value is visible, then one
  settle interval; hard timeout (~5 min) → fail the run and clean up.
- Finalize with base64url(DER CSR); poll order to `valid`; download
  `application/pem-certificate-chain`; split leaf/chain; parse; store.
- Revoke: `revokeCert` JWS signed by the account key; treat
  `urn:ietf:params:acme:error:alreadyRevoked` as success.

Rate limits to design around (verify against current LE docs before launch):
~50 certs/registered-domain/week, ~5 duplicate certs/week, ~300 new orders/3 h/account,
~5 failed validations/hostname/h/account. Mitigations: staging by default, one order
per SAN set, never reissue an unchanged cert, jittered cron, no prod LE in tests.

Post-v1 options: ACME Renewal Information (ARI) instead of the fixed 30-day window;
`preferred_chain` via alternate chain links.

---

## 6. Data model (D1)

```sql
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
  key_hint TEXT NOT NULL,                 -- scw_<id>…<last4>
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
```

Invariants: at most one `current` certificate per domain (partial unique index); at
most one active run per domain (partial unique index), which serializes manual and
cron issuance without locks.

---

## 7. R2 layout

```
acme/<env>/account.json                    # account URL + metadata
acme/<env>/account-key.pem.enc             # AES-256-GCM, AAD = path
certs/<domain>/<cert-id>/cert.pem          # leaf only
certs/<domain>/<cert-id>/chain.pem
certs/<domain>/<cert-id>/fullchain.pem
certs/<domain>/<cert-id>/privkey.pem.enc   # AES-256-GCM, AAD = domain/cert-id
certs/<domain>/<cert-id>/meta.json         # SANs, dates, fingerprints, key type
```

Write order is always R2 first, then the D1 pointer flip, so a crash never leaves a
`current` certificate whose PEMs do not exist. Private keys are encrypted at rest
with `ENVELOPE_KEY` (Worker secret); the bucket stays private, and the key is only
ever decrypted in-process and streamed to an authenticated API key — never presigned,
never logged. Superseded material is **deleted immediately** (no rollback
generation); the D1 row remains for audit.

---

## 8. Issuance & renewal

`CertificateWorkflow` (Cloudflare Workflows) runs one instance per issuance:

1. `load` — domain row, SAN set, account, zone. Idempotent.
2. `ensure-account` — create/load the LE account.
3. `new-order` — identifiers = SANs; 429 and `rateLimited` are retryable/classified.
4. `publish-txt` — create TXT record(s); persist `challenge_records` IDs in run state.
5. `wait-propagation` — DoH poll loop for all values.
6. `accept-challenges` — POST each challenge.
7. `await-authz` — poll to valid/invalid; store LE error detail verbatim.
8. `key+csr` — generate ECDSA P-256; build CSR; encrypt + store the key to R2.
9. `finalize+store` — finalize; poll; download; parse; write R2; flip D1; audit.
10. `purge-previous` — delete the previous cert-id prefix from R2; set `purged_at`.
11. `cleanup-txt` — delete challenge records by ID (best effort, always runs).
12. `finish-run` — status, timings.

Compensation: steps 3–9 are wrapped in try/catch so `cleanup-txt` always runs;
`purge-previous` never fails the run (retries, then left to the sweeper).

**Triggers.**

- Daily cron `17 3 * * *` (jitter inside the handler): create instances for domains
  where `not_after − renew_before_days ≤ now` or that have no current certificate.
  Instance ID `renew-<domainId>-<yyyy-mm-dd>` makes cron idempotent by construction;
  manual runs use `manual-<runId>`.
- Sweeper (same cron): delete R2 objects for `certificates` rows with
  `purged_at IS NULL AND status != 'current'`; delete orphaned `_acme-challenge`
  records older than 24 h.
- Manual issue/reissue from the admin panel.

**Revocation.**

- `POST /api/certificates/:id/revoke` → ACME `revokeCert` (account key) → purge R2 →
  `status='revoked'`. Idempotent (`alreadyRevoked` treated as success).
- Deleting a domain row triggers the same flow (UI confirm), then soft-deletes the
  domain (`status='deleted'`) so history and audit survive.

---

## 9. API surface

### Admin API (`/api/*`, Access app A + JWT verified in Worker)

| Method + path | Purpose |
|---|---|
| `GET /overview` | counts, soonest expiry, failed runs, key last-use |
| `GET/POST /domains`, `PATCH/DELETE /domains/:id` | CRUD; zone picker (CF API); wildcard toggle |
| `POST /domains/:id/issue` | manual issue/reissue |
| `GET /certificates`, `GET /certificates/:id` | history + metadata |
| `POST /certificates/:id/revoke` | revoke + purge |
| `GET /certificates/:id/download?file=fullchain\|key\|bundle` | bootstrap download |
| `GET /runs`, `GET /runs/:id` | workflow status + LE error detail |
| `GET/POST /keys` | create key (plaintext shown once) |
| `POST /keys/:id/revoke` | immediate revocation |
| `POST /keys/:id/rotate` | create replacement (same label) + revoke old |
| `GET /pulls`, `GET /audit` | who pulled what; who changed what |

### Node pull API (`/v1/*`, Access app B bypass + API key)

| Method + path | Purpose |
|---|---|
| `GET /me` | key id, label, scoped domains |
| `GET /domains` | scoped list + current cert metadata (cheap poll) |
| `GET /domains/:name/cert` | JSON manifest: sans, serial, not_before/after, etag, `cert_pem`, `chain_pem`, `fullchain_pem`, `private_key_pem` |
| `GET /domains/:name/files/:file` | raw `cert` / `chain` / `fullchain` / `key` for curl-friendly agents |

Auth: `Authorization: Bearer scw_<id>.<secret>`. Only SHA-256(secret) is stored;
lookup by the embedded id, constant-time hash comparison, revocation immediate.
Responses carry `ETag` (serial + fingerprint) and `Cache-Control: no-store`;
`If-None-Match` → `304` with no decrypt work. Successful pulls write `pull_events`
and update `last_used_at` (throttled to once per 60 s per key) via `waitUntil`.
Rate limiting binding per key; `allowed_domains_json = NULL` means all domains
(per-key scoping is a dormant schema capability until a second node exists).

---

## 10. Security model

- **Access**: app A (`ssl.example.com`) allow-policy for humans; app B
  (`ssl.example.com/v1`) bypass for nodes. The Worker still verifies
  `Cf-Access-Jwt-Assertion` against `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`
  (JWKS cached per isolate), checking `iss` + `aud`. Network position is never the
  only control on `/api/*`.
- **CSRF**: mutations require same-origin (`Origin`/`Sec-Fetch-Site`) and
  `Content-Type: application/json`; no CORS headers are ever emitted.
- **Secrets**: `CF_DNS_API_TOKEN` (scoped to the relevant zones) and `ENVELOPE_KEY`
  as Worker secrets; nothing sensitive in D1.
- **At rest**: private keys and the ACME account key are AES-256-GCM encrypted;
  the R2 bucket is private; decryption happens only in the pull path.
- **Blast radius**: one leaked API key exposes the key material for exactly its
  scoped domains — inherent to identical distribution. Controls: narrow scopes,
  one-key-per-node revocation, `last_used_at`, pull audit trail.
- **Audit**: every admin mutation and successful pull is recorded (actor/key,
  target, IP, timestamp). LE error payloads stored verbatim on the run row.
- **Deliberately not built**: user login in the app (Access only), node
  notification/push, per-node unique keys.

---

## 11. Node agent (reference, shell)

`tools/node-agent/` ships a script + systemd units. Contract: `304` = skip; write
both files before reloading; never reload on a `304`; fail loudly on non-2xx; treat
an HTML `Content-Type` on a non-200 as "Access is in the way" in the log line.

```bash
#!/usr/bin/env bash
# /usr/local/bin/ssl-cert-pull
set -euo pipefail
API="https://ssl.example.com/v1"
TOKEN="$(cat /etc/ssl-cert-worker/token)"          # chmod 600
STATE="/var/lib/ssl-cert-worker"; CERTS="/etc/nginx/ssl"
mkdir -p "$STATE" "$CERTS"

for d in "$@"; do
  etag_file="$STATE/$d.etag"
  etag=$(cat "$etag_file" 2>/dev/null || true)
  out="$STATE/$d.json"
  code=$(curl -sS -o "$out" -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    ${etag:+-H "If-None-Match: $etag"} \
    "$API/domains/$d/cert")
  case "$code" in
    304) continue ;;
    200) ;;
    *)   echo "pull failed for $d: HTTP $code" >&2; exit 1 ;;
  esac
  jq -r .fullchain_pem "$out"  > "$CERTS/$d.pem.new"
  jq -r .private_key_pem "$out" > "$CERTS/$d.key.new"
  chmod 600 "$CERTS/$d.key.new"
  mv -f "$CERTS/$d.pem.new" "$CERTS/$d.pem"
  mv -f "$CERTS/$d.key.new" "$CERTS/$d.key"
  jq -r .etag "$out" > "$etag_file"
  nginx -t && nginx -s reload
done
```

```ini
# /etc/systemd/system/ssl-cert-pull.timer
[Timer]
OnCalendar=*:0/15
RandomizedDelaySec=300
Persistent=true
```

---

## 12. Repo layout and Wrangler config

```
ssl-cert-worker/
├─ src/                      # Worker script
│  ├─ index.ts               # fetch router (by path) + scheduled()
│  ├─ admin/                 # admin API handlers
│  ├─ nodes/                 # pull API handlers
│  ├─ acme/                  # jws.ts, client.ts, dns01.ts, errors.ts
│  ├─ dns/cloudflare.ts      # TXT create/delete, zone lookup
│  ├─ issue/workflow.ts      # CertificateWorkflow class
│  ├─ store/                 # d1.ts, r2.ts
│  ├─ crypto/                # base64url.ts, keys.ts, csr.ts, envelope.ts, pem.ts, certificate.ts
│  └─ auth/                  # access.ts (jose), api-key.ts
├─ scripts/issue.ts           # LE staging acceptance script (Node + tsx)
├─ scripts/tsconfig.json      # isolated Node script typecheck
├─ migrations/0001_init.sql
├─ web/                      # Vite + React SPA → web/dist
├─ tools/node-agent/         # script + systemd units
├─ test/                     # vitest + workerd pool and mocked ACME/DNS tests
└─ wrangler.jsonc
```

```jsonc
{
  "name": "ssl-cert-worker",
  "main": "src/index.ts",
  "compatibility_date": "2026-09-01",
  "assets": {
    "directory": "web/dist",
    "binding": "ASSETS",
    "not_found_handling": "single-page-application",
    "run_worker_first": ["/api/*", "/v1/*"]
  },
  "d1_databases": [{ "binding": "DB", "database_name": "ssl-cert-worker", "database_id": "<id>" }],
  "r2_buckets": [{ "binding": "CERTS", "bucket_name": "ssl-cert-artifacts" }],
  "workflows": [{ "name": "certificate-issuance", "binding": "ISSUANCE", "class_name": "CertificateWorkflow" }],
  "ratelimits": [{ "name": "PULL_LIMITER", "namespace_id": "1001", "simple": { "limit": 60, "period": 60 } }],
  "triggers": { "crons": ["17 3 * * *"] },
  "routes": [{ "pattern": "ssl.example.com", "custom_domain": true }],
  "vars": {
    "ACCESS_TEAM_DOMAIN": "https://<team>.cloudflareaccess.com",
    "ACCESS_AUD": "<aud>",
    "ACME_DIRECTORY": "https://acme-staging-v02.api.letsencrypt.org/directory"
  },
  "env": {
    "production": {
      "vars": { "ACME_DIRECTORY": "https://acme-v02.api.letsencrypt.org/directory" },
      "d1_databases": [{ "binding": "DB", "database_name": "ssl-cert-worker-prod", "database_id": "<id>" }],
      "r2_buckets": [{ "binding": "CERTS", "bucket_name": "ssl-cert-artifacts-prod" }]
    }
  }
}
```

Secrets (`wrangler secret put`): `CF_DNS_API_TOKEN`, `ENVELOPE_KEY`.

---

## 13. Environments and testing

- `ACME_DIRECTORY` is per-environment; local dev and CI always staging. Production is
  an explicit opt-in.
- Unit tests (`@cloudflare/vitest-pool-workers`): JWS vectors, DNS-01 value
  derivation, CSR round-trip + SAN parsing, name normalization/validation, envelope
  encrypt→decrypt, routing/auth (Access JWT via local JWKS fixture; API keys), and
  mocked ACME/Cloudflare DNS protocol behavior.
- M2 live acceptance is a manual run against LE **staging** on a dedicated test zone:
  issue a certificate, assert SANs and leaf-key match, inspect the chain and expiry,
  and verify TXT cleanup. It requires a real DNS token and has not yet been run in
  this workspace. Production LE is never used by automated tests.
- Production LE is never used by automated tests. The M2 script blocks non-staging
  directories unless the operator explicitly passes `--allow-production`.

---

## 14. Milestones

| # | Deliverable | Acceptance |
|---|---|---|
| M0 | Scaffold: wrangler config, one-hostname routing, D1 migration, bindings, local dev | `wrangler dev` boots; migration applies; `/api/*` 401s without JWT |
| M1 | Crypto core: keygen, JWK/thumbprint, ES256 JWS, CSR build/parse, envelope encryption | Unit tests green in workerd |
| M2 | ACME client: account, order, DNS-01, nonce/retry, finalize, download | Staging cert issued end-to-end by a script |
| M3 | Persistence + Workflow pipeline + manual issue + purge-previous + TXT cleanup | Manual run yields R2 artifacts and D1 rows, previous prefix purged, no TXT leftovers |
| M4 | Admin API + Access JWT + audit | Unauthenticated `/api/*` rejected; mutations audited |
| M5 | SPA: domains (wildcard default on), runs, certificates, API keys, pulls, overview | Issued cert visible/downloadable; key shown once |
| M6 | Node pull API + keys + ETag + rate limit | Shell agent pulls; 304 on repeat; revoked key rejected |
| M7 | Daily cron renewals + sweeper + revocation + staging/prod split | Renewal fires inside window; superseded R2 gone; revoke idempotent |
| M8 | Shell agent + runbook | New node onboarded with key + three files |

---

## 15. Risks and mitigations

| Risk | Mitigation |
|---|---|
| LE rate limits (duplicates, per-domain) | staging first, dedupe by SAN set, jittered cron, no reissue without change, distinct `rateLimited` handling |
| DNS propagation vs LE multi-perspective validation | wait for full visibility at two resolvers + settle interval; retryable run |
| Same TXT name needed by two orders | one row with wildcard toggle preferred; per-order record IDs; per-zone lock only if it ever bites |
| CPU limits during keygen/CSR | ECDSA P-256 only; RSA out of v1 |
| Access bypass misconfiguration | node path fails loudly; Worker JWT check is the backstop on `/api`; bypassed traffic logged by `pull_events` |
| Private key exposure | envelope encryption, private bucket, narrow key scopes, pull audit, instant revocation |
| Partial writes (R2 ok, D1 not) | R2-then-D1 order; compensation step; D1 pointer is the only "current" truth |
| Immediate purge race | a pull in flight during flip/purge may 404; agent retries next cycle (single node) |
| Envelope key rotation | versioned key ids in `meta.json`; rewrap migration deferred |

---

## 16. Open items

1. **Failure alerting** — deferred (webhook/email later; nodes are never notified).
2. **Access Service Auth for `/v1`** — optional hardening; default is Bypass.
3. **Envelope key rotation** — deferred; needs versioned keys + rewrap command.
4. **Per-key domain scoping UI** — column exists (`allowed_domains_json`); expose when
   a second node exists.
