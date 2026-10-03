# CertWorker

> **Warning — this project is still under heavy development.**
> APIs, storage layout, and configuration may change without notice between
> revisions. Pin a revision before deploying, read the diff on every update, and
> do not treat the admin panel or the pull API as stable interfaces yet.

## About this project

CertWorker is a centralized TLS certificate issuer and distributor that runs as a
single Cloudflare Worker.

The problem it solves: Let's Encrypt rate limits (certificates per registered
domain per week, duplicate certificates, failed validations) are applied per
registered domain and per ACME account. When every machine provisions its own
certificate, they all draw down the *same* budget, each machine needs DNS API
credentials, private keys are generated and stored everywhere, and a broken
provisioner burns the shared quota with failed validations. Adding a node makes
the fleet more fragile, not less.

CertWorker flips the model: certificates are issued **once**, server-side, and
every node simply pulls the identical material:

1. A table of domains drives issuance (leaf key + CSR generated on the server).
2. Certificates are issued and renewed via Let's Encrypt (ACME v2, DNS-01
   challenges published through the Cloudflare DNS API — works for wildcards,
   no inbound HTTP required).
3. Certificate, chain, and the private key (AES-256-GCM encrypted at rest) are
   stored in R2; metadata lives in D1.
4. Nodes fetch the **same** certificate and key through a pull API authenticated
   with one API key per node (Bearer token, ETags, per-key rate limit).
5. A daily cron renews certificates before expiry; nodes poll on their own
   schedule. The server never notifies or pushes to nodes.
6. An admin SPA (static assets in the same Worker) manages domains, issuance
   runs, certificates, API keys, and pull history — protected by Cloudflare
   Access, there is no application-level user login.

Non-goals: node push/notification, per-node unique keys, non-Cloudflare DNS
providers, RSA keys (ECDSA P-256 only), and expiry notification emails.

## Usage

### Deploy to Cloudflare Workers

**Prerequisites**

On your local machine:

- Node.js ≥ 22 and npm (the repo uses npm workspaces for `web/`).
- This repository checked out; `npm install` once.
- Wrangler (installed as a dev dependency — use `npx wrangler`), authenticated
  against your account (`npx wrangler login`, or `CLOUDFLARE_API_TOKEN` in the
  environment).

In the Cloudflare account:

- Permission to create Workers, D1 databases, R2 buckets, and Workflows (an
  "Edit Cloudflare Workers" token plus D1/R2 storage edit covers the CLI
  commands below; otherwise create the resources in the dashboard).
- One hostname on a zone in the account for the Worker's custom domain
  (e.g. `certworker.example.org`).
- A Cloudflare Access (Zero Trust) team to protect the admin surface.

API tokens:

- `CF_DNS_API_TOKEN` — a **separate, least-privilege** token used by the Worker
  to complete DNS-01 challenges. Scope: `Zone:DNS:Edit` + `Zone:Zone:Read` on
  exactly the zones whose certificates you will issue.
- `ENVELOPE_KEY` — 32 random bytes, base64 (`openssl rand -base64 32`). This is
  the AES-256-GCM key that encrypts private keys at rest. Generate it per
  environment, keep it out of version control, and never lose it (the stored
  keys are unreadable without it).

**The config has two environments — know which one you are editing**

Configuration lives in `wrangler.jsonc` (a gitignored working copy); the tracked
template is `wrangler.example.jsonc`:

```sh
cp wrangler.example.jsonc wrangler.jsonc
```

One file defines **two environments**:

- **Top level = staging.** Worker `certworker-staging`, Let's Encrypt *staging*
  directory (`acme-staging-v02`), separate staging D1/R2/workflow names. This is
  what `npm run dev` and `npm run deploy` use.
- **`env.production` = production.** Worker `certworker`, the *production* Let's
  Encrypt directory, its own D1/R2 and workflow, and (in the template) the
  custom-domain route. Deploy it explicitly with `wrangler deploy --env production`.

Bindings and vars are **not inherited** across environments: whatever you change
in the top level must be repeated under `env.production` (only `assets` and
`triggers` carry over). Every command below states which environment it targets;
double-check before running anything that writes to D1 or deploys.

**0. Fill in `wrangler.jsonc`**

Replace the placeholders in both blocks: the Worker/resource names if you
deviate from the template, the D1 `database_id` (after step 1), R2 bucket names,
workflow names, the rate-limit `namespace_id` (unique per environment), and the
vars:

- `ACCESS_TEAM_DOMAIN` — `https://<team>.cloudflareaccess.com` (see the Access
  step).
- `ACCESS_AUD` — the AUD tag of the admin Access application.
- `ACME_DIRECTORY` — keep the staging directory until the whole flow is
  verified; only switch to `https://acme-v02.api.letsencrypt.org/directory` in
  the production environment.
- `DEV_ACCESS_EMAIL` — must stay `""` in every deployed environment.

**1. Create the D1 database and R2 bucket**

```sh
# staging (top-level environment)
npx wrangler d1 create certworker-staging
npx wrangler r2 bucket create certworker-artifacts-staging

# production (env.production)
npx wrangler d1 create certworker
npx wrangler r2 bucket create certworker-artifacts
```

Paste the printed `database_id` into the matching `d1_databases` entry. R2
buckets are referenced by name only.

**2. Set the Worker secrets**

Secrets are per deployed Worker, so production needs its own:

```sh
npx wrangler secret put CF_DNS_API_TOKEN
npx wrangler secret put ENVELOPE_KEY

npx wrangler secret put CF_DNS_API_TOKEN --env production
npx wrangler secret put ENVELOPE_KEY --env production
```

**3. Apply the D1 migration**

```sh
npx wrangler d1 migrations apply DB --remote
npx wrangler d1 migrations apply DB --remote --env production
```

(Local development uses `npm run db:migrate:local` instead.)

**4. Deploy**

```sh
npm run deploy                              # staging (top level)
npm run build:web && npx wrangler deploy --env production
```

`npm run deploy` builds the SPA into `web/dist` first; `web/dist` must exist
before `wrangler dev` or `vitest run` as well. After the first deploy, open
`https://<your-hostname>/` and confirm the admin SPA loads (it will prompt for
Access login in the next step).

#### Protect with Access

The Worker serves one hostname with **two path-scoped Access applications**:

| Access app | Path | Policy | Serves |
|---|---|---|---|
| A | `certworker.example.org` (most specific match on `/api/*` too) | **Allow** — your IdP group or specific emails | Admin SPA + `/api/*` |
| B | `certworker.example.org/v1` | **Bypass** (or Service Auth) | Node pull API |

Access evaluates the most specific path first, so `/v1/*` hits app B and never
redirects a node to a login page, while everything else is gated by app A.

Setup:

1. Create app A on your hostname with an Allow policy for your team/IdP (or
   individual emails). Copy its **AUD tag**.
2. Create app B with the path `certworker.example.org/v1` and a **Bypass**
   policy. (Do not reuse app A's allow policy here; nodes have no browser.)
3. Put the team domain and app A's AUD tag into the `vars` of **both**
   environments: `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD`, then redeploy.

The layering is deliberately defense-in-depth: the Worker **re-verifies** the
`Cf-Access-Jwt-Assertion` header on every `/api/*` request against the team JWKS
(`iss` + `aud`), so even if app A is misconfigured, the admin API rejects
unauthenticated requests. Conversely, if app B is deleted or mis-scoped, node
pulls fail loudly (an HTML login page or 403 — see the troubleshooting table in
[`agent/README.md`](agent/README.md)) while the admin surface keeps working.
Access does not log bypassed traffic; the `pull_events` table is the pull log.

Optional hardening (no code change): give app B a **Service Auth** policy
instead of Bypass, so nodes additionally send `CF-Access-Client-Id` /
`CF-Access-Client-Secret` headers.

### Run on local wrangler

Local dev runs the same Worker under `wrangler dev`, with placeholders in
`wrangler.jsonc` and a local D1/R2 (Miniflare):

```sh
npm install
cp wrangler.example.jsonc wrangler.jsonc   # placeholder IDs are fine locally
npm run db:migrate:local
cp .dev.vars.example .dev.vars             # then edit it
npm run dev                                # serves http://localhost:8787
```

- `.dev.vars` holds the two secrets for local runs (`CF_DNS_API_TOKEN`,
  `ENVELOPE_KEY`). **Real issuance touches Let's Encrypt staging and your real
  Cloudflare DNS zone** — use a throwaway zone/subdomain.
- `DEV_ACCESS_EMAIL` in `.dev.vars` is the local-only Access bypass: when set,
  `/api/*` requests from loopback hosts skip Access JWT verification and that
  email is recorded as the audit actor. It must be empty in deployed
  environments (the deployed Worker refuses the bypass for non-loopback hosts).
- The `ACME_DIRECTORY` var applies as configured — locally that is always the
  staging directory.

Useful commands (same as CI):

```sh
npm run check        # typecheck worker, tests, scripts, and web
npm test             # worker tests (workerd pool) + web tests
npm run issue -- example.com   # LE-staging acceptance script (scripts/issue.ts)
```

The `issue` script issues a certificate end-to-end outside the Worker and writes
PEMs to `.wrangler/acme/out`; it refuses any non-staging ACME directory unless
you pass `--allow-production`.

## API Endpoints

Both APIs live on the same hostname and are dispatched by path in
`src/index.ts`. Errors are JSON: `{"error": "<code>", "message": "<text>"}`.

### Admin API — `/api/*`

Auth: Cloudflare Access JWT (`Cf-Access-Jwt-Assertion`), re-verified in the
Worker. Mutations additionally require same-origin (`Origin` /
`Sec-Fetch-Site`) and `Content-Type: application/json`; no CORS headers are
ever emitted. List endpoints accept `?limit=` (1–200, default 50) and
`?offset=`.

| Method + path | Purpose |
|---|---|
| `GET /api/overview` | counts, soonest expiry, failed runs, key last-use |
| `GET /api/zones` | Cloudflare zones reachable with the DNS token (for the picker) |
| `GET /api/domains` · `POST /api/domains` | list / create domain rows (zone, wildcard toggle, key type, renewal window) |
| `GET /api/domains/:id` · `PATCH /api/domains/:id` · `DELETE /api/domains/:id` | detail / update / delete (delete revokes + purges, then soft-deletes) |
| `POST /api/domains/:id/issue` | manual issue / reissue |
| `GET /api/certificates` · `GET /api/certificates/:id` | certificate history and metadata |
| `GET /api/certificates/:id/download?file=cert\|chain\|fullchain\|key\|bundle` | bootstrap download (`bundle` = fullchain + key) |
| `POST /api/certificates/:id/revoke` | ACME revoke + purge artifacts (idempotent) |
| `GET /api/runs` · `GET /api/runs/:id` | issuance runs: status, phase, timings, Let's Encrypt error detail |
| `GET /api/keys` · `POST /api/keys` | list / create node API keys (plaintext shown **once**; optional `allowed_domains` scope) |
| `PATCH /api/keys/:id` | replace a key's domain scope (`allowed_domains`; `null` = all domains, `[]` = no domains) |
| `POST /api/keys/:id/revoke` | immediate revocation |
| `POST /api/keys/:id/rotate` | replacement key (same label) + revoke the old one |
| `GET /api/pulls` | pull log (key, domain, status, IP) |
| `GET /api/audit` | admin mutations (actor, action, target) |

### Node pull API — `/v1/*`

Auth: `Authorization: Bearer cw_<id>.<secret>`. GET only. Per-key rate limit
(60 requests/minute). Every response carries `ETag` (`"<serial>-<fingerprint>"`)
and `Cache-Control: no-store`; sending `If-None-Match` returns `304` without
touching R2 or decrypting anything. Successful pulls are recorded in
`pull_events` and bump the key's `last_used_at`.

| Method + path | Purpose |
|---|---|
| `GET /v1/me` | key id, label, scoped domains |
| `GET /v1/domains` | domains this key may pull + current certificate metadata (cheap poll) |
| `GET /v1/domains/:name/cert` | JSON manifest: SANs, serial, validity, ETag, and all PEMs (`cert_pem`, `chain_pem`, `fullchain_pem`, `private_key_pem`) |
| `GET /v1/domains/:name/files/:file` | raw file: `cert`, `chain`, `fullchain`, or `key` — for curl-based agents, no JSON parsing |

`:name` is the exact domain row name (`example.com`, or `*.example.com` for a
wildcard-only row). Common errors: `401` bad/revoked key, `403 forbidden_domain`
(key not scoped to that name), `404 not_found` (unknown domain) or
`404 certificate_missing` (nothing issued yet), `429 rate_limited`.

## Concepts

**Domain row.** The unit of issuance. Stores the lowercase punycode name, the
Cloudflare zone, `include_wildcard` (default on), `key_type`
(`ecdsa_p256`), `renew_before_days` (default 30), and status
(`active | paused | deleted`). The SAN set is derived from the row:

| Row | Wildcard toggle | SANs issued |
|---|---|---|
| `example.com` | on | `example.com`, `*.example.com` (one order, two DNS-01 authorizations) |
| `example.com` | off | `example.com` |
| `*.example.com` | n/a | `*.example.com` only |

**Certificate.** At most one `current` certificate per domain (D1 unique
index). Artifacts live in R2 under `certs/<domain>/<cert-id>/`: `cert.pem`,
`chain.pem`, `fullchain.pem`, `privkey.pem.enc`, `meta.json`. The private key is
AES-256-GCM encrypted with `ENVELOPE_KEY` (AAD = path) and is decrypted only
inside the pull path — never presigned, never logged. R2 is written before the
D1 `current` pointer flips, so a crash can never leave a current certificate
whose PEMs do not exist. Superseded artifacts are deleted immediately (the D1
row survives for audit); a daily sweeper finishes anything a crash left behind.

**Issuance run.** One Cloudflare Workflows instance
(`CertificateWorkflow`) per issuance: create order → publish `_acme-challenge`
TXT record(s) → wait for DNS propagation (DoH, two resolvers + settle) → accept
challenges → await authorizations → generate key + CSR → finalize, download,
store, flip `current` → purge the previous certificate → clean up TXT records.
One run at a time per domain. Triggered by the daily cron (renewal window:
`not_after − renew_before_days`; instance IDs like `renew-<domainId>-<date>`
make cron idempotent) or manually from the admin panel. Let's Encrypt error
payloads are stored verbatim on the run row.

**ACME account.** One Let's Encrypt account per environment, stored in R2 under
`acme/<env>/` (account key encrypted the same way as leaf keys). Leaf keys are
generated per certificate; the account key is long-lived.

**API key (one key = one node).** Token format `cw_<id>.<secret>`; only
SHA-256 of the secret is stored, the plaintext is shown once. Lookup by embedded
id with constant-time hash comparison; revocation takes effect immediately.
Each key carries a domain scope (`allowed_domains`): `null` (the default) lets
it pull every registered domain, `[]` denies all pulls, while an explicit list
restricts it to those exact domain row names (`example.com` and `*.example.com`
are separate entries; only registered, non-deleted rows are accepted). Set the
scope at creation or via `PATCH /api/keys/:id`; rotating a key carries its
scope over. A leaked key
exposes exactly its scoped domains' material — inherent to identical
distribution — so scope narrowly, rotate per node, and watch `last_used_at` /
the pull log.

**Pull model.** Nodes poll; the server never notifies. The ETag changes exactly
when the certificate changes (serial + fingerprint), so a poll that returns
`304` costs nothing and never triggers a reload. A renewal that flips while a
pull is in flight may 404 briefly; the next poll heals it.

**Audit.** Every admin mutation (actor = Access email) and every pull (key, IP,
status) is recorded in D1. Access is the only login; there is no application
user table.

**Environments.** Staging and production differ by ACME directory and by their
D1/R2/workflow resources; certificates carry an `env` column. Local dev and all
automated tests use the staging directory — production Let's Encrypt is an
explicit opt-in.

## Implement on nodes.

Nodes run a small pull agent: fetch the raw files from `/v1/domains/<name>/files/...`
(no JSON), validate with `openssl`, install into an app-owned directory, and
optionally reload the web server — under a systemd timer.

The reference implementation (a shell script plus a systemd service and timer)
and the complete onboarding runbook — key creation, install paths, unit
configuration, first pull, web-server wiring, operations, and troubleshooting —
are in [`agent/README.md`](agent/README.md).
