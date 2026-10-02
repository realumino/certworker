# ssl-cert-worker

Issues TLS certificates from Let's Encrypt (ACME v2, DNS-01 via the Cloudflare DNS
API) on Cloudflare Workers, stores them in R2, and distributes them to nodes that
pull periodically using per-node API keys (one key = one node).

- Single Worker deployment, single hostname (`ssl.example.com`).
- Admin panel: static SPA behind Cloudflare Access; admin API re-verifies the Access JWT.
- Node pull API: `ssl.example.com/v1/*`, Access bypass, bearer API keys, ETag/304.
- Renewal: daily cron creates Cloudflare Workflow instances for due domains.
- Runs on the Workers **Free** plan (Workflows is included on both plans; free allows
  10 ms CPU per step). Paid removes the free daily limits and raises per-step CPU to 30 s.

Status: M0–M8 complete. M2 ACME client and issuance script are implemented; live staging acceptance is pending. M3 persistence, Workflow pipeline, and internal manual trigger are implemented; offline workerd acceptance passes. M4 admin API, Access JWT verification, and the audit trail are implemented. M5 admin SPA is implemented (overview, domains, runs, certificates, API keys, pulls, audit; DOM tests run in happy-dom). M6 node pull API is implemented (bearer keys, ETag/304, per-key rate limit, pull events, last-use tracking). M7 adds certificate revocation (endpoint + revoke-on-domain-delete), the daily renewal cron, the sweeper, and the production environment config. M8 adds the reference node agent and its onboarding runbook (`agent/`); live onboarding acceptance is pending.

## Local development

Prerequisites: Node.js >= 22 (Wrangler 4 requires it) and npm.

```sh
npm install
cp .dev.vars.example .dev.vars
npm run build:web          # builds the admin SPA -> web/dist (required before wrangler dev / vitest)
npm run types              # regenerate worker-configuration.d.ts after changing wrangler.jsonc
npm run db:migrate:local   # apply migrations to the local D1 database (.wrangler/state)
npm test                   # workerd-pool tests + the SPA DOM suite (happy-dom)
npm run dev                # wrangler dev on http://localhost:8787
```

Iterating on the SPA: run `npm run dev` in one terminal and `npm run dev -w web` in a
second. The Vite dev server on http://localhost:5173 hot-reloads and proxies `/api` to
`wrangler dev` on port 8787.

The admin API (`/api/*`) requires the `Cf-Access-Jwt-Assertion` header injected by
Cloudflare Access; the Worker verifies its RS256 signature against the team JWKS
(`${ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`) plus `iss` and `aud`, rejecting
everything else with 401. Mutations are additionally same-origin and JSON-only.
Every admin mutation is recorded in the `audit_log` D1 table with the Access
email as the actor.

For local development behind `wrangler dev` (where no Access sits in front), set
`DEV_ACCESS_EMAIL` in `.dev.vars`: requests from loopback hosts then skip JWT
verification and use that email as the audit actor. The variable is empty in
`wrangler.jsonc`, so deployed Workers never run the bypass — it is also
unreachable on any non-loopback hostname.

Deployment placeholders: `wrangler.jsonc` currently carries placeholder D1/R2 IDs.
Replace them (`wrangler d1 create ssl-cert-worker`, `wrangler r2 bucket create
ssl-cert-artifacts`) before the first deploy.

## M2 staging issuance

Set `CF_DNS_API_TOKEN` in `.dev.vars` (or the process environment) with `Zone:Zone:Read`
and `Zone:DNS:Edit` on a dedicated test zone, then run:

```sh
npm run issue -- example.com                  # apex + wildcard by default
npm run issue -- '*.example.com'              # wildcard only
npm run issue -- example.com --no-wildcard    # apex only
```

The script defaults to Let's Encrypt staging, waits for DNS-01 propagation through
Cloudflare and Google DoH, and deletes its TXT records during cleanup. It stores the
staging account and downloaded artifacts under `.wrangler/acme/` (gitignored). The
local account and leaf private keys are plaintext development artifacts; do not copy
them into production storage. Any non-staging directory requires `--allow-production`.

The offline suite covers the ACME/Cloudflare DNS flows. The live staging run requires
a real test zone and DNS token and has not yet been performed in this workspace.

## Renewals, sweeper, and revocation (M7)

**Daily renewals.** The cron trigger `17 3 * * *` fires `scheduled()` (`src/index.ts`), which jitters 0–60 s and then creates one `CertificateWorkflow` instance per active domain that has no current certificate or whose `not_after` falls within its `renew_before_days`. Instance IDs are `renew-<domainId>-<yyyy-mm-dd>` (UTC), so an accidental same-day repeat skips instead of reissuing; the `idx_run_active` partial unique index serializes renewals against manual runs. Failures are per-domain and recorded on the run row. Locally: `npx wrangler dev --test-scheduled`, then

```sh
curl 'http://localhost:8787/__scheduled?cron=17+3+*+*+*'
```

**Sweeper.** The same invocation cleans up state a crashed pipeline could not finish: R2 prefixes of certificates with `status != 'current' AND purged_at IS NULL` are deleted and marked purged, and `_acme-challenge` TXT records recorded in `challenge_records` older than 24 h are deleted via the DNS API. Every step is best-effort and logged (`cron.complete`, `sweeper.*`).

**Revocation.** `POST /api/certificates/:id/revoke` (admin API, Access-protected) revokes via ACME `revokeCert` signed with the issuing account key, then deletes the stored PEMs and flips the D1 row to `revoked`. It is idempotent: a repeat call or an `alreadyRevoked` answer from the CA still ends `revoked`+purged and issues no second CA request. A certificate whose artifacts were already purged can no longer be revoked (409). `DELETE /api/domains/:id` revokes the current certificate first, then soft-deletes the row; while the CA rejects the revocation the deletion is refused with 502, and the audit entry records the revoke outcome.

## Staging and production (M7)

`wrangler.jsonc` carries an `env.production` block: production ACME directory (`https://acme-v02.api.letsencrypt.org/directory`), separate D1 (`ssl-cert-worker-prod`) and R2 bucket (`ssl-cert-artifacts-prod`). Cron triggers and assets are inherited from the top level; deploy and configure it with:

```sh
npx wrangler d1 create ssl-cert-worker-prod
npx wrangler r2 bucket create ssl-cert-artifacts-prod   # paste both IDs into env.production
npx wrangler d1 migrations apply DB --env production --remote
npx wrangler secret put CF_DNS_API_TOKEN --env production
npx wrangler secret put ENVELOPE_KEY --env production   # distinct from staging
npx wrangler deploy --env production
```

Both environments share the single hostname: moving `ssl.example.com` from one Worker to the other is a cutover, so release the route from the previous Worker first.

## Node pull API (M6)

Nodes authenticate with a one-time `scw_<id>.<secret>` token created in the admin
panel (POST /api/keys); only the SHA-256 of the secret is stored. All endpoints are
GET-only under `ssl.example.com/v1/*`:

```sh
TOKEN=$(cat /etc/ssl-cert-worker/token)   # scw_<id>.<secret>

# Manifest with metadata and all four PEMs (including the decrypted private key)
curl -sS -H "Authorization: Bearer $TOKEN" \
  https://ssl.example.com/v1/domains/example.com/cert

# Raw files: cert | chain | fullchain | key
curl -sS -H "Authorization: Bearer $TOKEN" \
  https://ssl.example.com/v1/domains/example.com/files/fullchain

# Cheap poll (scoped domains + current-cert metadata, no PEMs)
curl -sS -H "Authorization: Bearer $TOKEN" https://ssl.example.com/v1/domains

# Key identity and scope
curl -sS -H "Authorization: Bearer $TOKEN" https://ssl.example.com/v1/me
```

Responses carry `ETag: "<serial>-<fingerprint>"` and `Cache-Control: no-store`.
Sending the stored ETag back as `If-None-Match` returns `304` with no body and no
decryption work; never reload on a `304`. Successful and failed per-domain pulls
(`200`/`304`/`403`/`404`) are logged to `pull_events`, and `last_used_at` is
throttled to one update per 60 s per key. Keys are rate limited (60 requests/60 s
per key via the `PULL_LIMITER` binding) and rejected immediately once revoked.
Domains are pulled by row name (`example.com` or `*.example.com`); a key whose
`allowed_domains` is null may pull every non-deleted domain.

## Node agent (M8)

`agent/` ships the reference node agent: a `ssl-cert-pull` shell script plus
`ssl-cert-pull.service`/`.timer`, and the onboarding runbook in
[agent/README.md](./agent/README.md). On a fresh node:

```sh
install -d -m 700 /etc/ssl-cert-worker
umask 077
printf '%s\n' 'scw_<id>.<secret>' > /etc/ssl-cert-worker/token   # from the admin Keys view
chmod 600 /etc/ssl-cert-worker/token
install -m 755 ssl-cert-pull /usr/local/bin/ssl-cert-pull
install -m 644 ssl-cert-pull.service ssl-cert-pull.timer /etc/systemd/system/
# edit SSL_CERT_API and ExecStart= in the service unit, then:
systemctl daemon-reload
systemctl start ssl-cert-pull.service     # first pull, installs .pem/.key under /etc/nginx/ssl
systemctl enable --now ssl-cert-pull.timer
```

The agent polls every 15 minutes (±5 min jitter), skips unchanged certificates
with `If-None-Match`/`304`, validates each pair with `openssl`, and reloads nginx
only after a change. The node needs `curl`, `jq`, `openssl`, and nginx.

Full design: [PLAN.md](./PLAN.md).
