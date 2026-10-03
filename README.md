# certworker

A single Cloudflare Worker that issues TLS certificates from Let's Encrypt (ACME v2,
DNS-01 via the Cloudflare DNS API), stores them in R2, and serves them to nodes that
pull periodically with per-node API keys.

It replaces the usual per-node certbot setup: certificates and private keys are
generated **once, server-side**, and every authorized node pulls the **exact same
certificate + key**. One Worker deployment covers issuance, renewal, storage,
distribution, and an admin panel.

- **Runtime:** one Worker, one hostname (e.g. `certworker.example.org`).
- **Admin surface:** React SPA + `/api/*`, protected by Cloudflare Access (no app login).
- **Node surface:** `GET /v1/*`, public path with bearer API keys, ETag/`304` support.
- **Renewal:** daily cron creates Cloudflare Workflow instances for due domains.
- **Plans:** runs on the Workers **Free** plan (Workflows is included; free allows
  10 ms CPU per step, which the ECDSA P-256 keygen/CSR fits). Paid removes the free
  daily limits and raises per-step CPU to 30 s.

Design details and the data model live in [PLAN.md](./PLAN.md). The node agent and its
onboarding runbook live in [agent/](./agent/README.md).

---

## What it does

```
 admin browser ──▶ certworker.example.org          Access app A: Allow (IdP/email)
                    ├─ /*      → Static Assets (SPA)     (protected)
                    └─ /api/*  → Admin API               JWT re-verified in Worker

 node agent ──────▶ certworker.example.org/v1/*     Access app B: Bypass (public)
 (systemd timer)        │                             Worker requires API key
                        ▼
                  CertificateWorkflow (durable steps, per run)
                   create order → publish TXT → wait → validate
                   → finalize → store → purge previous → cleanup
```

1. You add a domain row (apex, wildcard, or apex+wildcard) in the admin panel.
2. The Workflow obtains an ECDSA P-256 certificate from Let's Encrypt using DNS-01
   TXT records created through the Cloudflare DNS API, then stores the PEMs in R2 and
   metadata in D1. The previous certificate is purged.
3. You create an API key per node (shown once) and install the reference agent.
4. The agent polls `GET /v1/domains/<name>/cert` on a systemd timer, skips unchanged
   certificates with `If-None-Match`/`304`, validates with `openssl`, installs the
   files, and reloads nginx only when the pair changed.
5. The daily cron (`17 3 * * *`, UTC) reissues certificates whose `not_after` falls
   within their `renew_before_days` window (default 30). Nodes pick the new pair up on
   their next poll.

## What you can expect

**Admin panel** (behind Cloudflare Access) — routes under `/`:

| View | What it gives you |
|---|---|
| Overview | counts, soonest expiry, failed runs, key last-use |
| Domains | add/edit/pause domains, wildcard toggle, manual issue/reissue, delete (revokes first) |
| Runs | per-domain workflow status and Let's Encrypt error payloads |
| Certificates | history, metadata, download `fullchain` / `key` / `bundle`, revoke |
| API Keys | create (plaintext shown **once**), rotate, revoke |
| Pulls | which key pulled which domain, when, with what HTTP status |
| Audit | every admin mutation with the Access email as actor |

**Node pull API** (`/v1/*`) — GET only, `Authorization: Bearer cw_<id>.<secret>`:

| Endpoint | Purpose |
|---|---|
| `GET /v1/me` | key identity and allowed domains |
| `GET /v1/domains` | visible domain list + current-cert metadata (cheap poll) |
| `GET /v1/domains/:name/cert` | JSON manifest with all four PEMs (including the decrypted key) |
| `GET /v1/domains/:name/files/:file` | raw `cert` / `chain` / `fullchain` / `key` |

Responses carry `ETag: "<serial>-<fingerprint>"` and `Cache-Control: no-store`;
sending the ETag back as `If-None-Match` returns `304` with no body and no decryption.
Keys are rate limited to 60 requests / 60 s and stop working immediately on revoke.

**Scope and limitations**

- TLS certificate distribution copies the private key to every authorized node
  (required so nodes serve an identical cert). A leaked key exposes exactly its
  scoped domains; keys are per-node, scoped, rate limited, revocable, and audited.
- ECDSA P-256 leaf keys only; no RSA in this version.
- DNS-01 only, and only the Cloudflare DNS API.
- Identical cert + key on every node — no per-node unique keys.
- No push/notification to nodes; nodes pull. No expiry emails (Let's Encrypt removed
  them); the dashboard is the notification surface.
- No application-level user login; Cloudflare Access is the only admin auth.
- Only Let's Encrypt **staging** has been exercised end-to-end in this repo; production
  ACME is an explicit opt-in and is never used by tests.

---

## Configuration

The Worker binding/variable contract is defined in `wrangler.example.jsonc` (tracked
template). Local development uses a gitignored copy at `wrangler.jsonc`.

### Bindings (wrangler config)

| Binding | Type | Purpose |
|---|---|---|
| `ASSETS` | Static Assets | admin SPA from `web/dist` |
| `DB` | D1 | domains, certificates, runs, keys, pull events, audit |
| `CERTS` | R2 | PEMs and the encrypted private keys |
| `ISSUANCE` | Workflow | `CertificateWorkflow` (class in `src/issue/workflow.ts`) |
| `PULL_LIMITER` | Rate limit | per-key pulls, `simple: { limit: 60, period: 60 }` |

Cron trigger: `17 3 * * *` (daily renewal + sweeper).

### Variables

| Variable | Meaning |
|---|---|
| `ACCESS_TEAM_DOMAIN` | e.g. `https://<team>.cloudflareaccess.com`; JWKS is fetched from `<domain>/cdn-cgi/access/certs` |
| `ACCESS_AUD` | Access application AUD tag for the admin app; verified together with `iss` |
| `ACME_DIRECTORY` | `https://acme-staging-v02.api.letsencrypt.org/directory` (staging) or `https://acme-v02.api.letsencrypt.org/directory` (production) |
| `DEV_ACCESS_EMAIL` | Local only. Empty in every deployed environment. When set, `/api/*` from loopback hosts skips JWT verification and uses this email as the audit actor |

### Secrets

| Secret | Meaning |
|---|---|
| `CF_DNS_API_TOKEN` | Cloudflare API token with `Zone:Zone:Read` + `Zone:DNS:Edit` on the zones you issue for |
| `ENVELOPE_KEY` | base64 of 32 random bytes, `openssl rand -base64 32`; AES-256-GCM key that encrypts private keys at rest. **Use a distinct value per environment and keep it** |

Copy `.dev.vars.example` to `.dev.vars` for local runs. `.dev.vars` and `wrangler.jsonc`
are gitignored.

### Cloudflare Access

Two Access applications on the same hostname:

- **App A** — pattern `certworker.example.org`, policy Allow (IdP/email). Protects the SPA and `/api/*`.
- **App B** — pattern `certworker.example.org/v1`, policy **Bypass** (or Service Auth for extra hardening). The Worker enforces the API key either way.

Set `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` from app A. The Worker verifies the injected
`Cf-Access-Jwt-Assertion` (RS256, `iss`, `aud`) on every admin request, so `/api/*` is
never protected by network position alone.

### Environments

`wrangler.example.jsonc` defines a staging top-level config and an `env.production`
block:

| | staging (default) | production (`--env production`) |
|---|---|---|
| Worker name | `certworker-staging` | `certworker` |
| ACME directory | LE staging | LE production |
| D1 | `certworker-staging` | `certworker` |
| R2 | `certworker-artifacts-staging` | `certworker-artifacts` |
| Secrets | set separately | set separately (distinct `ENVELOPE_KEY`) |

The top-level staging Worker has no custom-domain route, so it deploys to
`certworker-staging.<subdomain>.workers.dev`. The `env.production` block carries the
`routes` entry (`certworker.example.org` in the template) — replace it with your host.
Because both environments share one hostname, moving it between them is a cutover:
release the route from the previous Worker first.

---

## Local development

Prerequisites: Node.js >= 22 (Wrangler 4 requires it), npm.

```sh
npm install
cp wrangler.example.jsonc wrangler.jsonc   # working config; gitignored
cp .dev.vars.example .dev.vars             # add a dev DNS token + ENVELOPE_KEY
npm run build:web                          # builds the admin SPA -> web/dist (needed first)
npm run types                              # regenerate worker-configuration.d.ts after config changes
npm run db:migrate:local                   # apply migrations to local D1 (.wrangler/state)
npm test                                   # workerd tests + SPA DOM suite
npm run dev                                # wrangler dev on http://localhost:8787
```

`web/dist`, `wrangler.jsonc`, and `.dev.vars` must exist before `npm test`,
`npm run types`, and `npm run dev`; `vitest.config.ts` and Wrangler both read
`./wrangler.jsonc`. The placeholder D1/R2 IDs in the template are fine locally.

**Admin dev loop.** With `DEV_ACCESS_EMAIL` set in `.dev.vars` (the example sets
`dev@example.com`), requests from `localhost`/`127.0.0.1`/`[::1]` skip Access JWT
verification and audit as that address. For SPA hot reload, run `npm run dev` in one
terminal and `npm run dev -w web` in another — Vite serves `http://localhost:5173` and
proxies `/api` to `wrangler dev` on 8787.

**Trigger the cron locally.** With `npx wrangler dev --test-scheduled`:

```sh
curl 'http://localhost:8787/__scheduled?cron=17+3+*+*+*'
```

**Issue a real staging certificate from the CLI** (bypasses the Worker; uses the ACME
client directly and needs `CF_DNS_API_TOKEN`):

```sh
npm run issue -- example.com                  # apex + wildcard by default
npm run issue -- '*.example.com'              # wildcard only
npm run issue -- example.com --no-wildcard    # apex only
```

It defaults to LE staging, waits for DNS-01 propagation, deletes its TXT records, and
writes artifacts to `.wrangler/acme/`. Any non-staging directory requires
`--allow-production`.

Tests run in two suites: `vitest run` (worker, `@cloudflare/vitest-pool-workers`,
mocked ACME/DNS, migrations applied in setup) and `npm run test -w web` (SPA, happy-dom
+ Testing Library). `npm test` runs both after building the SPA. `npm run check` runs
all four TypeScript projects (worker, tests, scripts, web).

---

## Deploy to Cloudflare

### 1. Create resources and fill in the config

```sh
npx wrangler d1 create certworker-staging
npx wrangler r2 bucket create certworker-artifacts-staging
# for production:
npx wrangler d1 create certworker
npx wrangler r2 bucket create certworker-artifacts
```

Copy the printed D1 IDs into `wrangler.jsonc` (top level and under `env.production`),
set the R2 bucket names, `ACME_DIRECTORY`, `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`, and the
production `routes` pattern. Then `npm run types`.

### 2. Apply migrations and set secrets

```sh
npx wrangler d1 migrations apply DB --remote
npx wrangler secret put CF_DNS_API_TOKEN
npx wrangler secret put ENVELOPE_KEY          # openssl rand -base64 32

# production:
npx wrangler d1 migrations apply DB --env production --remote
npx wrangler secret put CF_DNS_API_TOKEN --env production
npx wrangler secret put ENVELOPE_KEY --env production   # distinct from staging
```

### 3. Create Access applications

Create app A on your host (Allow policy) and app B on `/<your host>/v1` (Bypass).
Put app A's team domain and AUD in the `vars` block, then redeploy if you changed them.

### 4. Deploy

```sh
npm run deploy                    # staging: build SPA + wrangler deploy
npx wrangler deploy --env production   # production
```

After the first production deploy, open the admin panel, add a domain, run **Issue**,
then create an API key and onboard the node with [agent/README.md](./agent/README.md).

### 5. Onboard a node

See [agent/README.md](./agent/README.md) for the full runbook. Short version: install
`agent/certworker-pull` and the systemd units, put the `cw_<id>.<secret>` token in
`/etc/certworker/token` (mode `600`), set `CERTWORKER_API`/`ExecStart` in the service
unit, run the service once to install the PEMs under `/etc/nginx/ssl`, then
`systemctl enable --now certworker-pull.timer` (polls every 15 min ±5 min).

---

## Operations

- **Renewals** are automatic and server-side; nodes only pull. Reissue manually from
  the admin panel (**Domains → Issue**) at any time.
- **Revocation:** revoking a certificate or deleting a domain revokes it via ACME and
  purges the stored PEMs. Revocation is idempotent; an already-purged certificate can no
  longer be revoked (409).
- **Sweeper:** the daily invocation also purges R2 prefixes of non-current certificates
  and deletes stale `_acme-challenge` TXT records (>24 h). All steps are best-effort and
  logged (`cron.complete`, `sweeper.*`).
- **Logs:** `npx wrangler tail` for worker logs. Admin failures log structured
  `admin.request_failed`; cron logs `cron.complete` / `cron.failed`.
- **Key rotation:** rotate a key in the admin **Keys** view and install the new token
  on the node; the old key stops working immediately.
